//! The withdrawal flow end to end.

use std::time::Duration;

use anyhow::{Context as _, ensure};
use connectrpc::error::ErrorCode;
use ed25519_dalek::Verifier as _;
use fastwithdraw_proto::{
    v1::{CreateWithdrawalRequest, GetServiceInfoRequest, SubmitPaymentRequest, WithdrawalStatus},
    wallet::{PayRequest, RegisterQuoteRequest, TickRequest as WalletTickRequest},
};
use fastwithdraw_thunder::Xpriv;
use serde_json::{Value, json};

use crate::{
    helpers::{SETTLE_BLOCKS, Stack, expect_code, expect_status, withdrawal},
    setup::{CONFIRMATIONS, Mainchain, PayoutKey, SERVICE_MNEMONIC, Thunder, test_dir},
    util::{BinPaths, TestContext, wait_for},
};

/// Our xpub derivation matches the addresses Thunder's own wallet hands out.
pub async fn thunder_derivation(context: TestContext, bins: BinPaths) -> anyhow::Result<()> {
    let dir = test_dir(context.name)?;
    let mainchain = Mainchain::start(&context, &bins, &dir).await?;
    let thunder = Thunder::start(&context, &bins, &dir, &mainchain, Some(SERVICE_MNEMONIC)).await?;
    let xpub = Xpriv::from_mnemonic(SERVICE_MNEMONIC)?.account().xpub();
    for index in 1..=5 {
        let address: String = thunder.rpc.call("get_new_address", json!([])).await?;
        ensure!(
            address == xpub.address(index)?.to_string(),
            "index {index}: Thunder gave {address}, we derived {}",
            xpub.address(index)?
        );
    }
    Ok(())
}

/// A customer pays L2 coins to a quoted address and receives L1 coins, both
/// by reporting the payment and by the service finding it on its own. The
/// wallet refuses payouts it can't tie to a confirmed payment to us.
pub async fn fast_withdrawal(context: TestContext, bins: BinPaths) -> anyhow::Result<()> {
    let stack = Stack::start(context, bins, |_| {}).await?;
    stack.fund().await?;
    let services = &stack.services;

    // A quote, signed with the key GetServiceInfo publishes.
    let info = services
        .api
        .get_service_info(GetServiceInfoRequest::default())
        .await?
        .into_owned();
    ensure!(info.quote_signing_public_key == services.quote_key.to_bytes());
    ensure!(
        info.hot_wallet_address == services.wallet_address.to_string(),
        "GetServiceInfo hot wallet address {}",
        info.hot_wallet_address
    );
    let request = CreateWithdrawalRequest {
        request_id: uuid::Uuid::new_v4().to_string(),
        sidechain: "thunder".to_owned(),
        l1_address: stack.destination.clone(),
        l1_payout_sats: 100_000,
    };
    let quote = withdrawal(
        services
            .api
            .create_withdrawal(request.clone())
            .await?
            .into_owned()
            .withdrawal,
    )?;
    let expires_at = quote.expires_at.as_option().context("no expiry")?.seconds;
    let signed = fastwithdraw_api::quote_bytes(
        &quote.withdrawal_id,
        &quote.l2_payment_address,
        quote.l2_payment_sats,
        &quote.l1_address,
        quote.l1_payout_sats,
        quote.service_fee_sats,
        quote.required_confirmations,
        expires_at,
    );
    let signature = ed25519_dalek::Signature::from_slice(&quote.quote_signature)?;
    services.quote_key.verify(&signed, &signature)?;
    ensure!(quote.l2_payment_address == services.xpub.address(1)?.to_string());
    ensure!(quote.l2_payment_sats == 101_000, "1% fee");
    let again = withdrawal(
        services
            .api
            .create_withdrawal(request)
            .await?
            .into_owned()
            .withdrawal,
    )?;
    ensure!(
        again.withdrawal_id == quote.withdrawal_id,
        "CreateWithdrawal is idempotent"
    );

    // Reported payment: confirming while in the mempool, paid once confirmed.
    let outpoint = stack.pay_quote(&quote).await?;
    let submitted = services
        .api
        .submit_payment(SubmitPaymentRequest {
            withdrawal_id: quote.withdrawal_id.clone(),
            l2_payment_txid: outpoint.0.clone(),
            l2_payment_vout: outpoint.1,
        })
        .await?;
    expect_status(
        &withdrawal(submitted.into_owned().withdrawal)?,
        WithdrawalStatus::WITHDRAWAL_STATUS_CONFIRMING_PAYMENT,
    )?;
    // The wallet refuses below the required confirmations on its own,
    // whatever the api asks: in the mempool, then one block short.
    let pay = stack.pay_request(&quote, &outpoint)?;
    for _ in 1..CONFIRMATIONS {
        expect_code(
            services.wallet.pay(pay.clone()).await,
            ErrorCode::FailedPrecondition,
        )?;
        stack.customer.bmm(&stack.mainchain).await?;
    }
    expect_code(
        services.wallet.pay(pay.clone()).await,
        ErrorCode::FailedPrecondition,
    )?;
    stack.customer.bmm(&stack.mainchain).await?;
    stack.tick().await?;
    let paid = stack.get(&quote.withdrawal_id).await?;
    expect_status(&paid, WithdrawalStatus::WITHDRAWAL_STATUS_PAID)?;
    stack.mainchain.mine(1).await?;
    let received: Value = stack
        .mainchain
        .bitcoind
        .call("gettransaction", json!([paid.l1_payout_txid]))
        .await?;
    ensure!(
        received["amount"] == json!(0.001),
        "payout amount {}",
        received["amount"]
    );

    // The wallet only pays what was registered with a quote, once, for a
    // payment it can verify. Here the test plays a compromised api.
    let wallet = &services.wallet;
    let repeat = wallet.pay(pay.clone()).await?;
    ensure!(
        repeat.into_owned().l1_payout_txid == paid.l1_payout_txid,
        "Pay is idempotent"
    );
    // Quotes charge the 1% default service fee on top.
    let register = |id: &str, l2_index: u32, sats: u64| {
        wallet.register_quote(RegisterQuoteRequest {
            withdrawal_id: id.to_owned(),
            l2_index,
            l1_address: stack.destination.clone(),
            l1_payout_sats: sats,
            l2_payment_sats: sats + sats / 100,
        })
    };
    // The wallet enforces the service fee, whatever the api asks for.
    expect_code(
        wallet
            .register_quote(RegisterQuoteRequest {
                withdrawal_id: "no-fee".to_owned(),
                l2_index: 80,
                l1_address: stack.destination.clone(),
                l1_payout_sats: 100_000,
                l2_payment_sats: 100_999,
            })
            .await,
        ErrorCode::InvalidArgument,
    )?;
    // Each index belongs to one quote.
    expect_code(
        register("replay", 1, 100_000).await,
        ErrorCode::AlreadyExists,
    )?;
    // No registration, no payout.
    expect_code(
        wallet
            .pay(PayRequest {
                withdrawal_id: "unregistered".to_owned(),
                ..pay.clone()
            })
            .await,
        ErrorCode::NotFound,
    )?;
    // A real, confirmed payment can't be paid anywhere but the registered
    // destination.
    let thief: String = stack
        .mainchain
        .bitcoind
        .call("getnewaddress", json!([]))
        .await?;
    let second = stack.quote(100_000).await?;
    let second_outpoint = stack.pay_quote(&second).await?;
    stack.confirm_l2().await?;
    expect_code(
        wallet
            .pay(PayRequest {
                l1_address: thief,
                ..stack.pay_request(&second, &second_outpoint)?
            })
            .await,
        ErrorCode::InvalidArgument,
    )?;
    // Registered, but no such payment.
    register("unknown", 90, 100_000).await?;
    expect_code(
        wallet
            .pay(PayRequest {
                withdrawal_id: "unknown".to_owned(),
                l2_index: 90,
                l2_payment_txid: "ab".repeat(32),
                ..pay.clone()
            })
            .await,
        ErrorCode::FailedPrecondition,
    )?;
    // A payment to index 50, claimed for index 51, or for more than it paid.
    let stray = services.xpub.address(50)?.to_string();
    let (stray_txid, stray_vout) = stack.pay_l2(&stray, 20_000).await?;
    stack.confirm_l2().await?;
    let stray_pay = PayRequest {
        l2_payment_txid: stray_txid,
        l2_payment_vout: stray_vout,
        ..pay
    };
    register("wrong-index", 51, 15_000).await?;
    expect_code(
        wallet
            .pay(PayRequest {
                withdrawal_id: "wrong-index".to_owned(),
                l2_index: 51,
                l1_payout_sats: 15_000,
                ..stray_pay.clone()
            })
            .await,
        ErrorCode::FailedPrecondition,
    )?;
    register("overpaid", 50, 20_000).await?;
    expect_code(
        wallet
            .pay(PayRequest {
                withdrawal_id: "overpaid".to_owned(),
                l2_index: 50,
                l1_payout_sats: 20_000,
                ..stray_pay
            })
            .await,
        // 20k on L2 is less than the 20.2k the quote asks for.
        ErrorCode::FailedPrecondition,
    )?;

    // Unreported payment: the tick finds it once it is in a block.
    let quote = stack.quote(50_000).await?;
    stack.pay_quote(&quote).await?;
    stack.confirm_l2().await?;
    stack.tick().await?;
    expect_status(
        &stack.get(&quote.withdrawal_id).await?,
        WithdrawalStatus::WITHDRAWAL_STATUS_PAID,
    )?;

    // Payouts settle.
    stack.mainchain.mine(SETTLE_BLOCKS).await?;
    wait_for("payouts to confirm", Duration::from_secs(60), || async {
        let tick = services.wallet.tick(WalletTickRequest::default()).await?;
        ensure!(tick.into_owned().pending_payouts == 0, "payouts pending");
        Ok(())
    })
    .await?;
    stack.check_running()
}

/// The same payout with the key on a PKCS#11 token (SoftHSM), set up with the
/// operator tool.
pub async fn pkcs11_payout(context: TestContext, bins: BinPaths) -> anyhow::Result<()> {
    let stack = Stack::start(context, bins, |options| {
        options.payout_key = PayoutKey::SoftHsm;
    })
    .await?;
    stack.fund().await?;
    let quote = stack.quote(100_000).await?;
    stack.pay_quote(&quote).await?;
    stack.confirm_l2().await?;
    stack.tick().await?;
    let paid = stack.get(&quote.withdrawal_id).await?;
    expect_status(&paid, WithdrawalStatus::WITHDRAWAL_STATUS_PAID)?;
    stack.mainchain.mine(1).await?;
    let received: Value = stack
        .mainchain
        .bitcoind
        .call("gettransaction", json!([paid.l1_payout_txid]))
        .await?;
    ensure!(
        received["confirmations"].as_u64() == Some(1),
        "payout not mined: {received}"
    );
    stack.check_running()
}
