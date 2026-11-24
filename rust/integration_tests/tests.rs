//! The list of integration tests.

use std::{future::Future, pin::Pin};

use crate::{
    test_edges, test_flow, test_limits, test_resilience, test_sweep,
    util::{BinPaths, Failures, LogRegistry, TestContext, trial},
};

type TestFn = fn(TestContext, BinPaths) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send>>;

macro_rules! tests {
    ($($module:ident::$name:ident),* $(,)?) => {
        [$((
            stringify!($name),
            (|context, bins| Box::pin($module::$name(context, bins))) as TestFn,
        )),*]
    };
}

pub fn all(
    bins: &BinPaths,
    rt: &tokio::runtime::Handle,
    logs: &LogRegistry,
    failures: &Failures,
) -> Vec<libtest_mimic::Trial> {
    tests![
        test_flow::thunder_derivation,
        test_flow::fast_withdrawal,
        test_flow::pkcs11_payout,
        test_limits::wallet_caps,
        test_limits::wallet_fee_cap,
        test_limits::liquidity_limits,
        test_limits::quote_expiry,
        test_limits::quote_limits,
        test_resilience::l2_reorg,
        test_resilience::broadcast_retry,
        test_resilience::concurrent_payouts,
        test_resilience::refused_payout_needs_review,
        test_resilience::fee_bump,
        test_resilience::thunder_stale,
        test_resilience::stuck_payout_alert,
        test_resilience::stuck_payout_bumped,
        test_resilience::deep_payment,
        test_sweep::l2_sweep,
        test_sweep::underpayment_refund,
        test_sweep::underpayment_superseded,
        test_edges::rate_limit,
        test_edges::internal_token,
        test_edges::scheduler_id_token,
        test_edges::wallet_callers,
        test_edges::reflection,
        test_edges::wallet_id_token_auth,
    ]
    .into_iter()
    .map(|(name, test)| {
        let bins = bins.clone();
        trial(
            name,
            rt.clone(),
            logs.clone(),
            failures.clone(),
            move |context| test(context, bins),
        )
    })
    .collect()
}
