//! Reorgs, failed broadcasts, and concurrent payouts.

use std::{collections::HashSet, time::Duration};

use anyhow::{bail, ensure};
use connectrpc::error::ErrorCode;
use fastwithdraw_proto::{
    v1::WithdrawalStatus,
    wallet::{GetPayoutRequest, PayRequest, TickRequest as WalletTickRequest},
};
use serde_json::{Value, json};

use crate::{
    fakes::Proxy,
    helpers::{SETTLE_BLOCKS, Service, Stack, expect_code, expect_status},
    setup::Thunder,
    util::{BinPaths, TestContext, wait_for},
};

/// A payment whose L2 block is reorged out by a longer competing chain is
/// paid by neither the api nor the wallet, and the withdrawal goes back to
/// awaiting payment.
pub async fn l2_reorg(context: TestContext, bins: BinPaths) -> anyhow::Result<()> {
    // The api considers one confirmation enough, the wallet two: the api
    // moves to pay before the reorg, and the wallet alone holds it back.
    let stack = Stack::start(context, bins, |options| {
        options
            .api_env
            .push(("THUNDER_CONFIRMATIONS", "1".to_owned()));
    })
    .await?;
    // A second, unconnected miner that will build the competing chain.
    let rival = Thunder::start_named(
        &stack.context,
        &stack.bins,
        &stack.dir,
        &stack.mainchain,
        None,
        "thunder-rival",
    )
    .await?;
    stack.fund().await?;
    let quote = stack.quote(100_000).await?;
    let outpoint = stack.pay_quote(&quote).await?;
    stack.customer.bmm(&stack.mainchain).await?;
    stack.tick().await?;
    expect_status(
        &stack.get(&quote.withdrawal_id).await?,
        WithdrawalStatus::WITHDRAWAL_STATUS_PAYMENT_CONFIRMED,
    )?;

    // The rival merge-mines a longer chain without the payment, and the
    // customer's node (the one the services watch) adopts it.
    let ours = stack.customer.block_count().await?;
    for _ in 0..=ours {
        rival.bmm(&stack.mainchain).await?;
    }
    stack
        .customer
        .rpc
        .call::<Value>("connect_peer", json!([rival.net_addr]))
        .await?;
    let rival_tip = rival.tip().await?;
    wait_for(
        "the customer's node to reorg",
        Duration::from_secs(60),
        || async {
            let tip = stack.customer.tip().await?;
            ensure!(tip == rival_tip, "customer at {tip}, rival at {rival_tip}");
            Ok(())
        },
    )
    .await?;

    // Neither service pays for the reorged-out payment.
    stack.tick().await?;
    let reorged = stack.get(&quote.withdrawal_id).await?;
    if reorged.status == WithdrawalStatus::WITHDRAWAL_STATUS_PAID {
        bail!("paid out for a reorged-out payment");
    }
    expect_code(
        stack
            .services
            .wallet
            .pay(stack.pay_request(&quote, &outpoint)?)
            .await,
        ErrorCode::FailedPrecondition,
    )?;

    // The rival chain lacks the deposit the payment spent, so the payment is
    // gone for good and the withdrawal waits for a new one.
    let tx: Value = stack
        .customer
        .rpc
        .call("get_transaction", json!([outpoint.0]))
        .await?;
    ensure!(tx.is_null(), "payment survived the reorg: {tx}");
    expect_status(
        &reorged,
        WithdrawalStatus::WITHDRAWAL_STATUS_AWAITING_PAYMENT,
    )?;
    rival.check_running()?;
    stack.check_running()
}

/// A payout whose broadcast fails is still signed and stored, and the
/// wallet's tick broadcasts it once Esplora accepts it.
pub async fn broadcast_retry(context: TestContext, bins: BinPaths) -> anyhow::Result<()> {
    let esplora = Proxy::start("http://127.0.0.1:1").await?;
    let proxy = esplora.clone();
    let stack = Stack::start(context, bins, move |options| {
        proxy.set_upstream(options.esplora_url.clone());
        options.esplora_url = proxy.url();
    })
    .await?;
    stack.fund().await?;

    esplora.fail_posts_to(Some("/tx"));
    esplora.mimic_mempool(true);
    let quote = stack.quote(100_000).await?;
    stack.pay_quote(&quote).await?;
    stack.confirm_l2().await?;
    stack.tick().await?;
    let paid = stack.get(&quote.withdrawal_id).await?;
    expect_status(&paid, WithdrawalStatus::WITHDRAWAL_STATUS_PAID)?;
    ensure!(
        !stack.in_mempool(&paid.l1_payout_txid).await,
        "broadcast should have failed"
    );

    let wallet = &stack.services.wallet;
    let pending = wallet
        .tick(WalletTickRequest::default())
        .await?
        .into_owned();
    ensure!(
        pending.pending_payouts == 1,
        "pending {}",
        pending.pending_payouts
    );
    ensure!(
        !stack.in_mempool(&paid.l1_payout_txid).await,
        "rebroadcast should fail too"
    );

    esplora.fail_posts_to(None);
    wallet.tick(WalletTickRequest::default()).await?;
    ensure!(
        stack.in_mempool(&paid.l1_payout_txid).await,
        "tick did not rebroadcast"
    );
    stack.mainchain.mine(SETTLE_BLOCKS).await?;
    wait_for("payout to confirm", Duration::from_secs(60), || async {
        let pending = wallet
            .tick(WalletTickRequest::default())
            .await?
            .into_owned();
        ensure!(
            pending.pending_payouts == 0,
            "pending {}",
            pending.pending_payouts
        );
        Ok(())
    })
    .await?;
    stack.check_running()
}

/// Two wallet instances on one database pay out concurrently without
/// double-spending, and a raced duplicate request pays once.
pub async fn concurrent_payouts(context: TestContext, bins: BinPaths) -> anyhow::Result<()> {
    let mut stack = Stack::start(context, bins, |_| {}).await?;
    let second = stack
        .services
        .spawn_wallet(&stack.context, &stack.bins, &stack.dir, "wallet-2")
        .await?;
    stack.fund().await?;

    // Thunder's wallet won't spend unconfirmed change, so one payment a block.
    let mut requests = Vec::new();
    for _ in 0..4 {
        let quote = stack.quote(100_000).await?;
        let outpoint = stack.pay_quote(&quote).await?;
        stack.customer.bmm(&stack.mainchain).await?;
        requests.push(stack.pay_request(&quote, &outpoint)?);
    }
    stack.confirm_l2().await?;

    let wallets = [&stack.services.wallet, &second];
    let pay = |index: usize, request: PayRequest| {
        let wallet = wallets[index % 2];
        async move {
            wallet
                .pay(request)
                .await
                .map(|r| r.into_owned().l1_payout_txid)
        }
    };
    let mut calls: Vec<_> = requests
        .iter()
        .cloned()
        .enumerate()
        .map(|(index, request)| pay(index, request))
        .collect();
    // The same withdrawal, raced on the other instance.
    calls.push(pay(1, requests[0].clone()));
    let results = futures::future::join_all(calls).await;
    let mut txids = Vec::new();
    for result in results {
        txids.push(result?);
    }
    ensure!(txids[0] == txids[4], "a raced duplicate paid twice");
    let unique: HashSet<_> = txids.iter().collect();
    ensure!(
        unique.len() == 4,
        "expected 4 distinct payouts, got {}",
        unique.len()
    );
    for txid in &unique {
        ensure!(
            stack.in_mempool(txid).await,
            "payout {txid} not in the mempool"
        );
    }
    stack.mainchain.mine(SETTLE_BLOCKS).await?;
    wait_for("payouts to confirm", Duration::from_secs(60), || async {
        let pending = stack
            .services
            .wallet
            .tick(WalletTickRequest::default())
            .await?
            .into_owned();
        ensure!(
            pending.pending_payouts == 0,
            "pending {}",
            pending.pending_payouts
        );
        Ok(())
    })
    .await?;
    stack.check_running()
}

/// A payout the wallet refuses for good parks the withdrawal as FAILED
/// instead of retrying. Here the api's record of the destination is
/// tampered with after the quote, so it no longer matches what the wallet
/// registered.
pub async fn refused_payout_needs_review(
    context: TestContext,
    bins: BinPaths,
) -> anyhow::Result<()> {
    let stack = Stack::start(context, bins, |_| {}).await?;
    stack.fund().await?;
    let quote = stack.quote(100_000).await?;
    let thief: String = stack
        .mainchain
        .bitcoind
        .call("getnewaddress", json!([]))
        .await?;
    let api_db = sqlx::PgPool::connect(&stack.services.postgres.api_url).await?;
    sqlx::query("UPDATE withdrawals SET l1_destination = $1 WHERE id = $2")
        .bind(&thief)
        .bind(&quote.withdrawal_id)
        .execute(&api_db)
        .await?;
    stack.pay_quote(&quote).await?;
    stack.confirm_l2().await?;
    stack.tick().await?;
    let failed = stack.get(&quote.withdrawal_id).await?;
    expect_status(&failed, WithdrawalStatus::WITHDRAWAL_STATUS_FAILED)?;
    let alert = format!("withdrawal_failed:{}", quote.withdrawal_id);
    ensure!(
        stack.open_alerts(Service::Api).await?.contains(&alert),
        "no {alert} alert"
    );
    // Later ticks leave it alone.
    stack.tick().await?;
    expect_status(
        &stack.get(&quote.withdrawal_id).await?,
        WithdrawalStatus::WITHDRAWAL_STATUS_FAILED,
    )?;
    stack.check_running()
}

/// A payout miners won't take is replaced at a higher fee rate to the same
/// destination, and the api follows it to the replacement's txid.
pub async fn fee_bump(context: TestContext, bins: BinPaths) -> anyhow::Result<()> {
    let stack = Stack::start(context, bins, |options| {
        options
            .wallet_env
            .push(("FEE_BUMP_AFTER_BLOCKS", "1".to_owned()));
    })
    .await?;
    stack.fund().await?;
    let quote = stack.quote(100_000).await?;
    stack.pay_quote(&quote).await?;
    stack.confirm_l2().await?;
    stack.tick().await?;
    let paid = stack.get(&quote.withdrawal_id).await?;
    expect_status(&paid, WithdrawalStatus::WITHDRAWAL_STATUS_PAID)?;
    let original = paid.l1_payout_txid.clone();

    // A block passes it over, as if its fee rate were far too low.
    let bitcoind = &stack.mainchain.bitcoind;
    stack.mainchain.mine_empty().await?;
    ensure!(stack.in_mempool(&original).await, "original was mined");
    stack
        .services
        .wallet
        .tick(WalletTickRequest::default())
        .await?;
    stack.tick().await?;
    let bumped = stack.get(&quote.withdrawal_id).await?.l1_payout_txid;
    ensure!(bumped != original, "payout was not replaced");
    ensure!(
        stack.in_mempool(&bumped).await,
        "replacement not in mempool"
    );
    ensure!(
        !stack.in_mempool(&original).await,
        "original still in mempool"
    );

    // The replacement pays the same destination and amount.
    let tx: Value = bitcoind
        .call("getrawtransaction", json!([bumped, true]))
        .await?;
    let pays = tx["vout"].as_array().into_iter().flatten().any(|output| {
        output["scriptPubKey"]["address"] == quote.l1_address.as_str()
            && output["value"].as_f64() == Some(0.001)
    });
    ensure!(pays, "replacement doesn't pay the quote: {tx}");

    stack.mainchain.mine(SETTLE_BLOCKS).await?;
    wait_for(
        "the replacement to settle",
        Duration::from_secs(60),
        || async {
            let tick = stack
                .services
                .wallet
                .tick(WalletTickRequest::default())
                .await?;
            ensure!(tick.into_owned().pending_payouts == 0, "payouts pending");
            Ok(())
        },
    )
    .await?;
    stack.tick().await?;
    ensure!(
        stack.get(&quote.withdrawal_id).await?.l1_payout_txid == bumped,
        "api lost track of the replacement"
    );
    stack.check_running()
}

/// While Thunder's L2 tip is BMM'd too far back on L1 (Thunder lost the
/// enforcer, or nobody mines L2 blocks), the wallet refuses payouts and the
/// api refuses quotes; both resume once Thunder is current again.
pub async fn thunder_stale(context: TestContext, bins: BinPaths) -> anyhow::Result<()> {
    let stack = Stack::start(context, bins, |options| {
        options
            .wallet_env
            .push(("THUNDER_MAX_L1_LAG", "2".to_owned()));
    })
    .await?;
    stack.fund().await?;
    let quote = stack.quote(100_000).await?;
    let outpoint = stack.pay_quote(&quote).await?;
    stack.confirm_l2().await?;

    stack.mainchain.mine(3).await?;
    expect_code(
        stack
            .services
            .wallet
            .pay(stack.pay_request(&quote, &outpoint)?)
            .await,
        ErrorCode::Unavailable,
    )?;
    stack.tick().await?;
    expect_status(
        &stack.get(&quote.withdrawal_id).await?,
        WithdrawalStatus::WITHDRAWAL_STATUS_PAYMENT_CONFIRMED,
    )?;
    stack.wallet_tick().await?;
    ensure!(
        stack
            .open_alerts(Service::Wallet)
            .await?
            .contains(&"thunder_unsynced".to_owned()),
        "no thunder_unsynced alert"
    );
    // The api caches the wallet's status briefly.
    wait_for("quotes to be refused", Duration::from_secs(30), || async {
        expect_code(stack.quote(100_000).await, ErrorCode::Unavailable)
    })
    .await?;
    let status = stack.status().await?;
    let behind = status.sidechains[0]
        .tip_bmm_height
        .map(|height| status.l1_tip_height - height);
    ensure!(
        !status.accepting_withdrawals
            && status.paused_reason.contains("stopped following L1")
            && behind.is_some_and(|behind| behind > 2),
        "status while Thunder is stale: {status:?}"
    );

    // A new L2 block brings Thunder's tip up to date.
    stack.customer.bmm(&stack.mainchain).await?;
    stack.tick().await?;
    expect_status(
        &stack.get(&quote.withdrawal_id).await?,
        WithdrawalStatus::WITHDRAWAL_STATUS_PAID,
    )?;
    wait_for("quotes to resume", Duration::from_secs(30), || async {
        Ok(stack.quote(100_000).await?)
    })
    .await?;
    ensure!(
        stack.status().await?.accepting_withdrawals,
        "status not accepting after Thunder caught up"
    );
    stack.wallet_tick().await?;
    ensure!(
        !stack
            .open_alerts(Service::Wallet)
            .await?
            .contains(&"thunder_unsynced".to_owned()),
        "thunder_unsynced alert not resolved"
    );
    stack.check_running()
}

/// A payout that stays unmined because its fee bump would exceed the fee cap
/// raises an alert, resolved once the payout is mined.
pub async fn stuck_payout_alert(context: TestContext, bins: BinPaths) -> anyhow::Result<()> {
    let stack = Stack::start(context, bins, |options| {
        // Room for the payout's own fee (~280 sats), not for a bump.
        options.wallet_env.extend([
            ("FEE_BUMP_AFTER_BLOCKS", "1".to_owned()),
            ("MAX_FEE_SATS", "350".to_owned()),
        ]);
    })
    .await?;
    stack.fund().await?;
    let quote = stack.quote(100_000).await?;
    stack.pay_quote(&quote).await?;
    stack.confirm_l2().await?;
    stack.tick().await?;
    expect_status(
        &stack.get(&quote.withdrawal_id).await?,
        WithdrawalStatus::WITHDRAWAL_STATUS_PAID,
    )?;

    let stuck = "payouts_stuck".to_owned();
    stack.mainchain.mine_empty().await?;
    stack.wallet_tick().await?;
    ensure!(
        !stack.open_alerts(Service::Wallet).await?.contains(&stuck),
        "payouts_stuck alert before a bump was due"
    );
    stack.mainchain.mine_empty().await?;
    stack.wallet_tick().await?;
    ensure!(
        stack.open_alerts(Service::Wallet).await?.contains(&stuck),
        "no payouts_stuck alert"
    );

    stack.mainchain.mine(1).await?;
    stack.wallet_tick().await?;
    ensure!(
        !stack.open_alerts(Service::Wallet).await?.contains(&stuck),
        "payouts_stuck alert not resolved once mined"
    );
    stack.check_running()
}

/// A payout that is fee-bumped but never mined, as when no broadcast reaches
/// the network, still raises payouts_stuck: each bump replaces the payout,
/// but the wait counts from its first version.
pub async fn stuck_payout_bumped(context: TestContext, bins: BinPaths) -> anyhow::Result<()> {
    let esplora = Proxy::start("http://127.0.0.1:1").await?;
    let proxy = esplora.clone();
    let stack = Stack::start(context, bins, move |options| {
        proxy.set_upstream(options.esplora_url.clone());
        options.esplora_url = proxy.url();
        options
            .wallet_env
            .push(("FEE_BUMP_AFTER_BLOCKS", "1".to_owned()));
    })
    .await?;
    stack.fund().await?;

    esplora.fail_posts_to(Some("/tx"));
    let quote = stack.quote(100_000).await?;
    stack.pay_quote(&quote).await?;
    stack.confirm_l2().await?;
    stack.tick().await?;
    let payout_txid = || async {
        let request = GetPayoutRequest {
            withdrawal_id: quote.withdrawal_id.clone(),
        };
        anyhow::Ok(
            stack
                .services
                .wallet
                .get_payout(request)
                .await?
                .into_owned()
                .l1_payout_txid,
        )
    };
    let first = payout_txid().await?;

    let stuck = "payouts_stuck".to_owned();
    stack.mainchain.mine(1).await?;
    stack.wallet_tick().await?;
    ensure!(
        !stack.open_alerts(Service::Wallet).await?.contains(&stuck),
        "payouts_stuck alert before a bump was due"
    );
    stack.mainchain.mine(1).await?;
    stack.wallet_tick().await?;
    ensure!(payout_txid().await? != first, "payout was not fee-bumped");
    ensure!(
        stack.open_alerts(Service::Wallet).await?.contains(&stuck),
        "no payouts_stuck alert for a payout bumped but never mined"
    );

    esplora.fail_posts_to(None);
    stack.wallet_tick().await?;
    stack.mainchain.mine(1).await?;
    stack.wallet_tick().await?;
    ensure!(
        !stack.open_alerts(Service::Wallet).await?.contains(&stuck),
        "payouts_stuck alert not resolved once mined"
    );
    stack.check_running()
}

/// A payment first seen deeper than the block scan reaches (eg. after an
/// outage) still counts as confirmed, at the api and the wallet, and is
/// paid out.
pub async fn deep_payment(context: TestContext, bins: BinPaths) -> anyhow::Result<()> {
    let stack = Stack::start(context, bins, |options| {
        options.api_env.push(("THUNDER_SCAN_DEPTH", "2".to_owned()));
        options
            .wallet_env
            .push(("THUNDER_SCAN_DEPTH", "2".to_owned()));
    })
    .await?;
    stack.fund().await?;
    let quote = stack.quote(100_000).await?;
    stack.pay_quote(&quote).await?;
    // Mined, then buried below the two-block scan before anyone looks.
    stack.confirm_l2().await?;
    stack.customer.bmm(&stack.mainchain).await?;
    stack.customer.bmm(&stack.mainchain).await?;
    stack.tick().await?;
    expect_status(
        &stack.get(&quote.withdrawal_id).await?,
        WithdrawalStatus::WITHDRAWAL_STATUS_PAID,
    )?;
    stack.check_running()
}
