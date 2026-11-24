//! Limits: the wallet's caps, the api's liquidity reservations and quote
//! caps, and quote expiry.

use std::time::Duration;

use anyhow::ensure;
use connectrpc::{client::CallOptions, error::ErrorCode};
use fastwithdraw_proto::{
    v1::{CreateWithdrawalRequest, WithdrawalStatus},
    wallet::PayRequest,
};

use crate::{
    helpers::{Service, Stack, expect_code, expect_status},
    util::{BinPaths, TestContext, wait_for},
};

/// The wallet enforces its per-payout and daily caps whatever the api asks.
pub async fn wallet_caps(context: TestContext, bins: BinPaths) -> anyhow::Result<()> {
    let stack = Stack::start(context, bins, |options| {
        options.wallet_env.extend([
            ("MAX_PAYOUT_SATS", "120000".to_owned()),
            ("DAILY_CAP_SATS", "150000".to_owned()),
        ]);
    })
    .await?;
    stack.fund().await?;
    let wallet = &stack.services.wallet;
    stack.wallet_tick().await?;
    ensure!(
        !stack
            .open_alerts(Service::Wallet)
            .await?
            .contains(&"daily_cap_reached".to_owned()),
        "daily_cap_reached alert before any payout"
    );

    // Over the per-payout cap: refused before the L2 payment is even checked.
    expect_code(
        wallet
            .pay(PayRequest {
                withdrawal_id: "too-big".to_owned(),
                l2_index: 1,
                l2_payment_txid: "ab".repeat(32),
                l2_payment_vout: 0,
                l1_address: stack.destination.clone(),
                l1_payout_sats: 120_001,
                ..Default::default()
            })
            .await,
        ErrorCode::ResourceExhausted,
    )?;

    // The first payout fits under the daily cap.
    let first = stack.quote(100_000).await?;
    stack.pay_quote(&first).await?;
    stack.confirm_l2().await?;
    stack.tick().await?;
    expect_status(
        &stack.get(&first.withdrawal_id).await?,
        WithdrawalStatus::WITHDRAWAL_STATUS_PAID,
    )?;
    // Less than one maximum payout is left of the cap.
    stack.wallet_tick().await?;
    ensure!(
        stack
            .open_alerts(Service::Wallet)
            .await?
            .contains(&"daily_cap_reached".to_owned()),
        "no daily_cap_reached alert"
    );

    // The second would exceed it: the withdrawal stays confirmed, unpaid.
    let second = stack.quote(100_000).await?;
    let outpoint = stack.pay_quote(&second).await?;
    stack.confirm_l2().await?;
    stack.tick().await?;
    expect_status(
        &stack.get(&second.withdrawal_id).await?,
        WithdrawalStatus::WITHDRAWAL_STATUS_PAYMENT_CONFIRMED,
    )?;
    expect_code(
        wallet.pay(stack.pay_request(&second, &outpoint)?).await,
        ErrorCode::ResourceExhausted,
    )?;
    stack.check_running()
}

/// A payout whose miner fee exceeds the wallet's cap is never signed.
pub async fn wallet_fee_cap(context: TestContext, bins: BinPaths) -> anyhow::Result<()> {
    let stack = Stack::start(context, bins, |options| {
        options.wallet_env.push(("MAX_FEE_SATS", "50".to_owned()));
    })
    .await?;
    stack.fund().await?;
    let quote = stack.quote(100_000).await?;
    let outpoint = stack.pay_quote(&quote).await?;
    stack.confirm_l2().await?;
    stack.tick().await?;
    expect_status(
        &stack.get(&quote.withdrawal_id).await?,
        WithdrawalStatus::WITHDRAWAL_STATUS_PAYMENT_CONFIRMED,
    )?;
    expect_code(
        stack
            .services
            .wallet
            .pay(stack.pay_request(&quote, &outpoint)?)
            .await,
        ErrorCode::ResourceExhausted,
    )?;
    stack.check_running()
}

/// Quotes reserve no liquidity: none are issued against an unfunded wallet,
/// but any number against a funded one, so free quotes can't lock others out.
pub async fn liquidity_limits(context: TestContext, bins: BinPaths) -> anyhow::Result<()> {
    let stack = Stack::start(context, bins, |_| {}).await?;
    let status = stack.status().await?;
    ensure!(
        !status.accepting_withdrawals
            && status.paused_reason.contains("no L2 blocks")
            && status.sidechains[0].tip_height.is_none(),
        "status before any L2 block: {status:?}"
    );
    // Quotes need a current Thunder: one L2 block. The api caches the
    // wallet's status briefly.
    stack.customer.bmm(&stack.mainchain).await?;
    wait_for(
        "the empty wallet's refusal",
        Duration::from_secs(30),
        || async {
            expect_code(stack.quote(100_000).await, ErrorCode::ResourceExhausted)?;
            let status = stack.status().await?;
            ensure!(
                !status.accepting_withdrawals
                    && status.paused_reason.contains("minimum payout")
                    && status.max_payout_now_sats == 0
                    && status.sidechains[0].tip_height.is_some(),
                "{status:?}"
            );
            Ok(())
        },
    )
    .await?;
    // A new wallet raises no alert until it has been funded once.
    let low_funds = "low_funds".to_owned();
    stack.wallet_tick().await?;
    ensure!(
        !stack
            .open_alerts(Service::Wallet)
            .await?
            .contains(&low_funds),
        "low_funds alert for the never-funded wallet"
    );

    // Nor while its first funding is unconfirmed.
    stack
        .mainchain
        .bitcoind
        .call::<serde_json::Value>(
            "sendtoaddress",
            serde_json::json!([stack.services.wallet_address.to_string(), 0.01]),
        )
        .await?;
    let url = format!(
        "{}/address/{}",
        stack.mainchain.esplora_url, stack.services.wallet_address
    );
    wait_for(
        "the funding in Esplora's mempool",
        Duration::from_secs(30),
        || async {
            let stats: serde_json::Value = reqwest::get(&url).await?.json().await?;
            ensure!(stats["mempool_stats"]["tx_count"] == 1, "{stats}");
            Ok(())
        },
    )
    .await?;
    stack.wallet_tick().await?;
    ensure!(
        !stack
            .open_alerts(Service::Wallet)
            .await?
            .contains(&low_funds),
        "low_funds alert while the first funding is unconfirmed"
    );

    // Less than one maximum payout (0.1 BTC) once confirmed: the alert says
    // where to top up.
    stack.fund_wallet(0.01).await?;
    stack.wallet_tick().await?;
    ensure!(
        stack
            .open_alerts(Service::Wallet)
            .await?
            .contains(&low_funds),
        "no low_funds alert for the underfunded wallet"
    );
    let message = stack.alert_message(Service::Wallet, &low_funds).await?;
    let address = stack.services.wallet_address.to_string();
    ensure!(
        message.contains(&address),
        "low_funds alert doesn't name {address}: {message}"
    );

    stack.fund_wallet(1.0).await?;
    stack.wallet_tick().await?;
    ensure!(
        !stack
            .open_alerts(Service::Wallet)
            .await?
            .contains(&low_funds),
        "low_funds alert not resolved"
    );
    // The api caches the wallet balance briefly.
    wait_for(
        "quotes against the funded wallet",
        Duration::from_secs(30),
        || async { Ok(stack.quote(100_000).await?) },
    )
    .await?;
    let status = stack.status().await?;
    let chain = &status.sidechains[0];
    ensure!(
        status.accepting_withdrawals
            && status.paused_reason.is_empty()
            && status.hot_wallet_balance_sats > 100_000_000
            // The maximum payout (0.1 BTC) fits.
            && status.max_payout_now_sats == 10_000_000
            && status.daily_cap_left_sats > 0
            && status.l1_tip_height > 0
            && chain.tip_bmm_height.is_some_and(|height| height <= status.l1_tip_height)
            && chain.connected_peers.is_some(),
        "status of the funded wallet: {status:?}"
    );
    let attempts = futures::future::join_all((0..10).map(|_| stack.quote(100_000))).await;
    for attempt in attempts {
        attempt?;
    }
    stack.check_running()
}

/// An expired quote's address still counts: a payment that arrives late is
/// honored.
pub async fn quote_expiry(context: TestContext, bins: BinPaths) -> anyhow::Result<()> {
    let stack = Stack::start(context, bins, |options| {
        options.api_env.push(("QUOTE_TTL_SECS", "10".to_owned()));
    })
    .await?;
    stack.fund().await?;
    let quote = stack.quote(100_000).await?;

    tokio::time::sleep(Duration::from_secs(11)).await;
    stack.tick().await?;
    expect_status(
        &stack.get(&quote.withdrawal_id).await?,
        WithdrawalStatus::WITHDRAWAL_STATUS_EXPIRED,
    )?;

    stack.pay_quote(&quote).await?;
    stack.confirm_l2().await?;
    stack.tick().await?;
    expect_status(
        &stack.get(&quote.withdrawal_id).await?,
        WithdrawalStatus::WITHDRAWAL_STATUS_PAID,
    )?;
    stack.check_running()
}

/// Quotes are free, so the api caps open quotes per client (by the load
/// balancer's `X-Client-IP`) and the number it watches in all.
pub async fn quote_limits(context: TestContext, bins: BinPaths) -> anyhow::Result<()> {
    let stack = Stack::start(context, bins, |options| {
        options.api_env.extend([
            ("MAX_OPEN_QUOTES_PER_CLIENT", "2".to_owned()),
            ("MAX_WATCHED_QUOTES", "5".to_owned()),
        ]);
    })
    .await?;
    stack.fund().await?;
    let quote = |ip: &'static str| {
        let request = CreateWithdrawalRequest {
            request_id: uuid::Uuid::new_v4().to_string(),
            sidechain: "thunder".to_owned(),
            l1_address: stack.destination.clone(),
            l1_payout_sats: 100_000,
        };
        let options = CallOptions::default().with_header(
            http::HeaderName::from_static("x-client-ip"),
            http::HeaderValue::from_static(ip),
        );
        stack
            .services
            .api
            .create_withdrawal_with_options(request, options)
    };
    quote("203.0.113.1").await?;
    quote("203.0.113.1").await?;
    expect_code(quote("203.0.113.1").await, ErrorCode::ResourceExhausted)?;
    // IPv6 clients count per /64.
    quote("2001:db8::1").await?;
    quote("2001:db8::2").await?;
    expect_code(quote("2001:db8::3").await, ErrorCode::ResourceExhausted)?;
    // The fifth watched quote is the last anyone gets.
    quote("203.0.113.2").await?;
    expect_code(quote("203.0.113.3").await, ErrorCode::ResourceExhausted)?;
    stack.check_running()
}
