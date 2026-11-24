//! Shared steps for the tests: a full stack and the customer's actions.

use std::time::Duration;

use anyhow::{Context as _, bail, ensure};
use connectrpc::{ConnectError, error::ErrorCode};
use fastwithdraw_proto::{
    internal::TickRequest,
    v1::{
        CreateWithdrawalRequest, GetStatusRequest, GetStatusResponse, GetWithdrawalRequest,
        Withdrawal, WithdrawalStatus,
    },
    wallet::{GetBalanceRequest, PayRequest},
};
use serde_json::{Value, json};

use crate::{
    setup::{
        CONFIRMATIONS, INTERNAL_TOKEN, Mainchain, ServiceOptions, Services, Thunder, bearer,
        test_dir,
    },
    util::{BinPaths, TestContext, wait_for},
};

#[derive(Clone, Copy, Debug)]
pub enum Service {
    Api,
    Wallet,
}

/// Blocks after which the wallet stops watching a payout.
pub const SETTLE_BLOCKS: u32 = 6;

pub fn withdrawal(
    field: buffa::MessageField<Withdrawal, buffa::Inline<Withdrawal>>,
) -> anyhow::Result<Withdrawal> {
    field.into_option().context("response has no withdrawal")
}

pub fn expect_code<T>(result: Result<T, ConnectError>, code: ErrorCode) -> anyhow::Result<()> {
    match result {
        Ok(_) => bail!("expected {code:?}, got success"),
        Err(err) if err.code == code => Ok(()),
        Err(err) => bail!("expected {code:?}, got {err:?}"),
    }
}

pub fn expect_status(withdrawal: &Withdrawal, status: WithdrawalStatus) -> anyhow::Result<()> {
    ensure!(
        withdrawal.status == status,
        "withdrawal {}: expected {status:?}, got {:?}",
        withdrawal.withdrawal_id,
        withdrawal.status
    );
    Ok(())
}

/// A regtest chain, a customer with a Thunder wallet, and the services.
pub struct Stack {
    pub context: TestContext,
    pub bins: BinPaths,
    pub dir: std::path::PathBuf,
    pub mainchain: Mainchain,
    pub customer: Thunder,
    pub services: Services,
    /// An address in bitcoind's wallet, the default payout destination.
    pub destination: String,
}

impl Stack {
    pub async fn start(
        context: TestContext,
        bins: BinPaths,
        configure: impl FnOnce(&mut ServiceOptions),
    ) -> anyhow::Result<Self> {
        let dir = test_dir(context.name)?;
        let mainchain = Mainchain::start(&context, &bins, &dir).await?;
        let customer = Thunder::start(&context, &bins, &dir, &mainchain, None).await?;
        let mut options = ServiceOptions::new(&mainchain, &customer);
        configure(&mut options);
        let services = Services::start(&context, &bins, &dir, options).await?;
        let destination = mainchain.bitcoind.call("getnewaddress", json!([])).await?;
        Ok(Self {
            context,
            bins,
            dir,
            mainchain,
            customer,
            services,
            destination,
        })
    }

    /// Funds the payout wallet with `btc` on L1.
    pub async fn fund_wallet(&self, btc: f64) -> anyhow::Result<()> {
        self.mainchain
            .bitcoind
            .call::<Value>(
                "sendtoaddress",
                json!([self.services.wallet_address.to_string(), btc]),
            )
            .await?;
        self.mainchain.mine(1).await?;
        let expected = bitcoin::Amount::from_btc(btc)?.to_sat();
        wait_for("wallet balance", Duration::from_secs(60), || async {
            let balance = self
                .services
                .wallet
                .get_balance(GetBalanceRequest::default())
                .await?
                .into_owned()
                .spendable_sats;
            ensure!(balance >= expected, "wallet balance {balance}");
            Ok(())
        })
        .await
    }

    /// Funds the payout wallet with 1 BTC and the customer with 0.5 BTC on L2.
    pub async fn fund(&self) -> anyhow::Result<()> {
        self.fund_wallet(1.0).await?;
        self.customer.fund(&self.mainchain, 50_000_000).await
    }

    /// GetStatus. The api caches the wallet's part briefly.
    pub async fn status(&self) -> anyhow::Result<GetStatusResponse> {
        Ok(self
            .services
            .api
            .get_status(GetStatusRequest::default())
            .await?
            .into_owned())
    }

    pub async fn quote(&self, sats: u64) -> Result<Withdrawal, ConnectError> {
        let response = self
            .services
            .api
            .create_withdrawal(CreateWithdrawalRequest {
                request_id: uuid::Uuid::new_v4().to_string(),
                sidechain: "thunder".to_owned(),
                l1_address: self.destination.clone(),
                l1_payout_sats: sats,
            })
            .await?;
        response
            .into_owned()
            .withdrawal
            .into_option()
            .ok_or_else(|| ConnectError::internal("no withdrawal"))
    }

    /// Pays `sats` to `address` from the customer's Thunder wallet. Returns
    /// the payment outpoint.
    pub async fn pay_l2(&self, address: &str, sats: u64) -> anyhow::Result<(String, u32)> {
        let txid: String = self
            .customer
            .rpc
            .call("create_transfer", json!([address, sats, 1_000, null]))
            .await?;
        let tx: Value = self
            .customer
            .rpc
            .call("get_transaction", json!([txid]))
            .await?;
        let vout = tx["tx"]["outputs"]
            .as_array()
            .context("transaction has no outputs")?
            .iter()
            .position(|output| output["address"] == address)
            .context("no output pays the address")?;
        Ok((txid, u32::try_from(vout)?))
    }

    /// Pays a quote in full.
    pub async fn pay_quote(&self, quote: &Withdrawal) -> anyhow::Result<(String, u32)> {
        self.pay_l2(&quote.l2_payment_address, quote.l2_payment_sats)
            .await
    }

    /// Merge-mines enough Thunder blocks to confirm pending payments.
    pub async fn confirm_l2(&self) -> anyhow::Result<()> {
        for _ in 0..CONFIRMATIONS {
            self.customer.bmm(&self.mainchain).await?;
        }
        Ok(())
    }

    pub async fn tick(&self) -> anyhow::Result<()> {
        self.services
            .internal
            .tick_with_options(TickRequest {}, bearer(INTERNAL_TOKEN))
            .await?;
        Ok(())
    }

    pub async fn get(&self, id: &str) -> anyhow::Result<Withdrawal> {
        let response = self
            .services
            .api
            .get_withdrawal(GetWithdrawalRequest {
                withdrawal_id: id.to_owned(),
            })
            .await?;
        withdrawal(response.into_owned().withdrawal)
    }

    /// The derivation index of a quote address.
    pub fn l2_index(&self, address: &str) -> anyhow::Result<u32> {
        (1..1_000)
            .find(|index| {
                self.services
                    .xpub
                    .address(*index)
                    .is_ok_and(|derived| derived.to_string() == address)
            })
            .context("address is not ours")
    }

    /// A wallet `Pay` request for a paid quote.
    pub fn pay_request(
        &self,
        quote: &Withdrawal,
        outpoint: &(String, u32),
    ) -> anyhow::Result<PayRequest> {
        Ok(PayRequest {
            withdrawal_id: quote.withdrawal_id.clone(),
            l2_index: self.l2_index(&quote.l2_payment_address)?,
            l2_payment_txid: outpoint.0.clone(),
            l2_payment_vout: outpoint.1,
            l1_address: quote.l1_address.clone(),
            l1_payout_sats: quote.l1_payout_sats,
            // No l2_block hint: the wallet locates the payment itself.
            ..Default::default()
        })
    }

    /// Whether bitcoind's mempool holds `txid`.
    pub async fn in_mempool(&self, txid: &str) -> bool {
        self.mainchain
            .bitcoind
            .call::<Value>("getmempoolentry", json!([txid]))
            .await
            .is_ok()
    }

    /// Keys of the open alerts in the api's or the wallet's database.
    pub async fn open_alerts(&self, service: Service) -> anyhow::Result<Vec<String>> {
        let url = match service {
            Service::Api => &self.services.postgres.api_url,
            Service::Wallet => &self.services.postgres.wallet_url,
        };
        let db = sqlx::PgPool::connect(url).await?;
        let keys = sqlx::query_scalar("SELECT key FROM alerts ORDER BY key")
            .fetch_all(&db)
            .await?;
        db.close().await;
        Ok(keys)
    }

    pub async fn alert_message(&self, service: Service, key: &str) -> anyhow::Result<String> {
        let url = match service {
            Service::Api => &self.services.postgres.api_url,
            Service::Wallet => &self.services.postgres.wallet_url,
        };
        let db = sqlx::PgPool::connect(url).await?;
        let message = sqlx::query_scalar("SELECT message FROM alerts WHERE key = $1")
            .bind(key)
            .fetch_one(&db)
            .await?;
        db.close().await;
        Ok(message)
    }

    /// Runs the wallet's tick, which also updates its alerts.
    pub async fn wallet_tick(&self) -> anyhow::Result<()> {
        self.services
            .wallet
            .tick(fastwithdraw_proto::wallet::TickRequest::default())
            .await?;
        Ok(())
    }

    pub fn check_running(&self) -> anyhow::Result<()> {
        self.mainchain.check_running()?;
        self.customer.check_running()?;
        self.services.check_running()
    }
}
