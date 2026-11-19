//! The offline L2 sweep tool against a live Thunder node and the api.

use anyhow::{Context as _, ensure};
use connectrpc::error::ErrorCode;
use fastwithdraw_proto::v1::{RequestRefundRequest, WithdrawalStatus};
use fastwithdraw_thunder::{Address, rpc};
use serde_json::{Value, json};

use crate::{
    fakes::Proxy,
    helpers::{Service, Stack, expect_code, expect_status, withdrawal},
    setup::{INTERNAL_TOKEN, SERVICE_MNEMONIC},
    util::{BinPaths, TestContext, run, run_with_stdin},
};

const FEE_SATS: u64 = 1_000;

/// Sats unspent at `address`.
async fn balance(thunder: &rpc::Client, address: &str) -> anyhow::Result<u64> {
    let address: Address = address.parse()?;
    Ok(thunder
        .unspent_payments(&[address], 0, &Default::default())
        .await?
        .iter()
        .map(|payment| payment.sats)
        .sum())
}

/// Sweeps only payments the wallet has paid out, plus indexes named
/// explicitly, and `sign` refuses plans that don't match the mnemonic, the
/// destination or the fee limit.
pub async fn l2_sweep(context: TestContext, bins: BinPaths) -> anyhow::Result<()> {
    let stack = Stack::start(context, bins, |_| {}).await?;
    stack.fund().await?;
    // A paid-out withdrawal, one paid but not yet paid out, and a
    // payment that matches no quote.
    let paid = stack.quote(100_000).await?;
    stack.pay_quote(&paid).await?;
    stack.confirm_l2().await?;
    stack.tick().await?;
    expect_status(
        &stack.get(&paid.withdrawal_id).await?,
        WithdrawalStatus::WITHDRAWAL_STATUS_PAID,
    )?;
    let pending = stack.quote(50_000).await?;
    stack.pay_quote(&pending).await?;
    // The customer's wallet would spend the same coin twice within a block.
    stack.customer.bmm(&stack.mainchain).await?;
    let stray = stack.services.xpub.address(500)?.to_string();
    stack.pay_l2(&stray, 7_000).await?;
    stack.customer.bmm(&stack.mainchain).await?;

    let thunder = rpc::Client::new(&stack.customer.rpc_url, 10);
    let treasury: String = stack
        .customer
        .rpc
        .call("get_new_address", json!([]))
        .await?;
    let sweep = &stack.bins.sweep;
    let file = |name: &str| stack.dir.join(name).display().to_string();
    // `plan` asks the api for paid indexes through its load balancer, as an
    // operator would.
    let load_balancer =
        Proxy::start(format!("http://127.0.0.1:{}", stack.services.api_port)).await?;
    load_balancer.stamp_client_ip(true);
    let online_env = [
        ("THUNDER_URL", stack.customer.rpc_url.clone()),
        ("THUNDER_XPUB", stack.services.xpub.to_string()),
        ("API_INTERNAL_TOKEN", INTERNAL_TOKEN.to_owned()),
    ];
    let fee = FEE_SATS.to_string();
    run(
        sweep,
        &online_env,
        &[
            "plan",
            "--api-url",
            &load_balancer.url(),
            "--destination",
            &treasury,
            "--fee-sats",
            &fee,
            "--out",
            &file("plan.json"),
        ],
    )
    .await?;
    ensure!(
        load_balancer.authorizations() == [format!("Bearer {INTERNAL_TOKEN}")],
        "plan didn't send the token: {:?}",
        load_balancer.authorizations()
    );
    let plan: Value = serde_json::from_str(&std::fs::read_to_string(file("plan.json"))?)?;
    let inputs = plan["inputs"].as_array().context("plan has no inputs")?;
    let paid_index = stack.l2_index(&paid.l2_payment_address)?;
    ensure!(
        inputs.len() == 1 && inputs[0]["l2_index"] == paid_index,
        "plan should spend only the paid-out payment: {inputs:?}"
    );

    // `sign` checks the plan rather than trusting it.
    let sign = |plan: String, destination: String, max_fee: u64, mnemonic: &'static str| {
        let out = file(&format!("signed-{}.json", uuid::Uuid::new_v4()));
        async move {
            let args = [
                "sign",
                "--plan",
                &plan,
                "--destination",
                &destination,
                "--max-fee-sats",
                &max_fee.to_string(),
                "--out",
                &out,
            ];
            run_with_stdin(sweep, &[], &args, mnemonic)
                .await
                .map(|_| out)
        }
    };
    let refused = |result: anyhow::Result<String>, why: &str| {
        ensure!(result.is_err(), "sign accepted {why}");
        Ok(())
    };
    refused(
        sign(file("plan.json"), stray.clone(), FEE_SATS, SERVICE_MNEMONIC).await,
        "another destination",
    )?;
    refused(
        sign(
            file("plan.json"),
            treasury.clone(),
            FEE_SATS - 1,
            SERVICE_MNEMONIC,
        )
        .await,
        "a fee over the limit",
    )?;
    refused(
        sign(
            file("plan.json"),
            treasury.clone(),
            FEE_SATS,
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .await,
        "the wrong mnemonic",
    )?;
    let mut tampered = plan.clone();
    tampered["inputs"][0]["l2_index"] = json!(500);
    std::fs::write(file("tampered.json"), tampered.to_string())?;
    refused(
        sign(
            file("tampered.json"),
            treasury.clone(),
            FEE_SATS,
            SERVICE_MNEMONIC,
        )
        .await,
        "an input listed under another index",
    )?;

    let signed = sign(
        file("plan.json"),
        treasury.clone(),
        FEE_SATS,
        SERVICE_MNEMONIC,
    )
    .await?;
    run(sweep, &online_env[..1], &["submit", "--signed", &signed]).await?;
    stack.customer.bmm(&stack.mainchain).await?;
    ensure!(balance(&thunder, &treasury).await? == paid.l2_payment_sats - FEE_SATS);
    ensure!(balance(&thunder, &paid.l2_payment_address).await? == 0);
    ensure!(
        balance(&thunder, &pending.l2_payment_address).await? == pending.l2_payment_sats,
        "the unpaid withdrawal's payment was swept"
    );
    ensure!(balance(&thunder, &stray).await? == 7_000);

    // Named explicitly, the stray payment is swept too.
    run(
        sweep,
        &online_env[..2],
        &[
            "plan",
            "--index",
            "500",
            "--destination",
            &treasury,
            "--fee-sats",
            &fee,
            "--out",
            &file("stray.json"),
        ],
    )
    .await?;
    let signed = sign(
        file("stray.json"),
        treasury.clone(),
        FEE_SATS,
        SERVICE_MNEMONIC,
    )
    .await?;
    run(sweep, &online_env[..1], &["submit", "--signed", &signed]).await?;
    stack.customer.bmm(&stack.mainchain).await?;
    ensure!(balance(&thunder, &stray).await? == 0);
    ensure!(balance(&thunder, &treasury).await? == paid.l2_payment_sats + 7_000 - 2 * FEE_SATS);
    stack.check_running()
}

/// A payment smaller than its quote isn't paid out: the withdrawal becomes
/// UNDERPAID and alerts the operator. The customer names a refund address,
/// once; the operator refunds with the sweep tool, and the withdrawal becomes
/// REFUNDED.
pub async fn underpayment_refund(context: TestContext, bins: BinPaths) -> anyhow::Result<()> {
    let stack = Stack::start(context, bins, |_| {}).await?;
    stack.fund().await?;
    let quote = stack.quote(100_000).await?;
    let received = quote.l2_payment_sats - 1;
    stack.pay_l2(&quote.l2_payment_address, received).await?;
    stack.confirm_l2().await?;
    stack.tick().await?;
    let underpaid = stack.get(&quote.withdrawal_id).await?;
    expect_status(&underpaid, WithdrawalStatus::WITHDRAWAL_STATUS_UNDERPAID)?;
    ensure!(underpaid.l2_received_sats == received, "{underpaid:?}");
    ensure!(underpaid.l1_payout_txid.is_empty(), "underpayment paid out");
    let alert = format!("underpaid:{}", quote.withdrawal_id);
    ensure!(
        stack.open_alerts(Service::Api).await?.contains(&alert),
        "no underpaid alert"
    );

    let refund = |id: &str, address: &str| {
        stack.services.api.request_refund(RequestRefundRequest {
            withdrawal_id: id.to_owned(),
            l2_refund_address: address.to_owned(),
        })
    };
    let refund_address: String = stack
        .customer
        .rpc
        .call("get_new_address", json!([]))
        .await?;
    let other_address: String = stack
        .customer
        .rpc
        .call("get_new_address", json!([]))
        .await?;
    for bad in [
        String::new(),
        "not an address".to_owned(),
        format!(" {refund_address}"),
        format!("{refund_address}\n"),
        // A refund to one of our own payment addresses goes nowhere useful.
        quote.l2_payment_address.clone(),
    ] {
        expect_code(
            refund(&quote.withdrawal_id, &bad).await,
            ErrorCode::InvalidArgument,
        )
        .with_context(|| format!("refund address {bad:?}"))?;
    }
    let open = stack.quote(100_000).await?;
    expect_code(
        refund(&open.withdrawal_id, &refund_address).await,
        ErrorCode::FailedPrecondition,
    )?;
    let requested = withdrawal(
        refund(&quote.withdrawal_id, &refund_address)
            .await?
            .into_owned()
            .withdrawal,
    )?;
    ensure!(requested.l2_refund_address == refund_address);
    // Asking again is idempotent; another address is refused.
    refund(&quote.withdrawal_id, &refund_address).await?;
    expect_code(
        refund(&quote.withdrawal_id, &other_address).await,
        ErrorCode::AlreadyExists,
    )?;
    let index = stack.l2_index(&quote.l2_payment_address)?;
    let requested_alert = format!("refund_requested:{}", quote.withdrawal_id);
    let alerts = stack.open_alerts(Service::Api).await?;
    ensure!(
        !alerts.contains(&alert) && alerts.contains(&requested_alert),
        "alerts after the refund request: {alerts:?}"
    );
    let message = stack.alert_message(Service::Api, &requested_alert).await?;
    ensure!(
        message.contains(&refund_address) && message.contains(&format!("--index {index}")),
        "refund alert lacks the address or index: {message}"
    );

    // The operator refunds with the sweep tool, as the alert says.
    let sweep = &stack.bins.sweep;
    let file = |name: &str| stack.dir.join(name).display().to_string();
    let online_env = [
        ("THUNDER_URL", stack.customer.rpc_url.clone()),
        ("THUNDER_XPUB", stack.services.xpub.to_string()),
    ];
    let fee = FEE_SATS.to_string();
    run(
        sweep,
        &online_env,
        &[
            "plan",
            "--index",
            &index.to_string(),
            "--destination",
            &refund_address,
            "--fee-sats",
            &fee,
            "--out",
            &file("refund.json"),
        ],
    )
    .await?;
    let signed = file("refund-signed.json");
    run_with_stdin(
        sweep,
        &[],
        &[
            "sign",
            "--plan",
            &file("refund.json"),
            "--destination",
            &refund_address,
            "--max-fee-sats",
            &fee,
            "--out",
            &signed,
        ],
        SERVICE_MNEMONIC,
    )
    .await?;
    run(sweep, &online_env[..1], &["submit", "--signed", &signed]).await?;
    stack.customer.bmm(&stack.mainchain).await?;
    stack.tick().await?;

    let refunded = stack.get(&quote.withdrawal_id).await?;
    expect_status(&refunded, WithdrawalStatus::WITHDRAWAL_STATUS_REFUNDED)?;
    ensure!(
        !stack
            .open_alerts(Service::Api)
            .await?
            .contains(&requested_alert),
        "refund alert not resolved"
    );
    let thunder = rpc::Client::new(&stack.customer.rpc_url, 10);
    ensure!(balance(&thunder, &refund_address).await? == received - FEE_SATS);
    stack.check_running()
}

/// Dust to a quote address is ignored. A real underpayment makes the
/// withdrawal UNDERPAID, but until a refund is requested a full payment still
/// replaces it and is paid out, and the operator is told about the
/// underpayment that is now swept with the index.
pub async fn underpayment_superseded(context: TestContext, bins: BinPaths) -> anyhow::Result<()> {
    let stack = Stack::start(context, bins, |_| {}).await?;
    stack.fund().await?;
    let quote = stack.quote(100_000).await?;
    let id = &quote.withdrawal_id;
    // Below the minimum payout: not an underpayment, just dust.
    stack.pay_l2(&quote.l2_payment_address, 1_000).await?;
    stack.confirm_l2().await?;
    stack.tick().await?;
    expect_status(
        &stack.get(id).await?,
        WithdrawalStatus::WITHDRAWAL_STATUS_AWAITING_PAYMENT,
    )?;

    stack.pay_l2(&quote.l2_payment_address, 50_000).await?;
    stack.confirm_l2().await?;
    stack.tick().await?;
    expect_status(
        &stack.get(id).await?,
        WithdrawalStatus::WITHDRAWAL_STATUS_UNDERPAID,
    )?;
    let underpaid = format!("underpaid:{id}");
    ensure!(stack.open_alerts(Service::Api).await?.contains(&underpaid));

    stack.pay_quote(&quote).await?;
    stack.confirm_l2().await?;
    stack.tick().await?;
    let paid = stack.get(id).await?;
    expect_status(&paid, WithdrawalStatus::WITHDRAWAL_STATUS_PAID)?;
    ensure!(paid.l2_received_sats == 0, "{paid:?}");
    let alerts = stack.open_alerts(Service::Api).await?;
    ensure!(
        !alerts.contains(&underpaid) && alerts.contains(&format!("underpayment_replaced:{id}")),
        "alerts after the replacement: {alerts:?}"
    );
    stack.check_running()
}
