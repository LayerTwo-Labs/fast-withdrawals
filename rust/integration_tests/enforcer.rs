//! Connect clients for the BIP300/301 enforcer, generated from its protos at
//! the commit pinned in buf.gen.yaml.

use buffa::{Inline, MessageField};
use buffa_types::google::protobuf::{StringValue, UInt32Value, UInt64Value};
use connectrpc::client::{ClientConfig, HttpClient};

#[allow(
    non_camel_case_types,
    dead_code,
    unused_imports,
    unused_qualifications,
    clippy::all
)]
pub mod generated {
    pub mod buffa {
        pub mod cusf {
            pub mod common {
                pub mod v1 {
                    include!("generated/buffa/cusf.common.v1.rs");
                }
            }
            pub mod mainchain {
                pub mod v1 {
                    include!("generated/buffa/cusf.mainchain.v1.rs");
                }
            }
        }
    }
    pub mod connect {
        pub mod cusf {
            pub mod mainchain {
                pub mod v1 {
                    include!("generated/connect/cusf.mainchain.v1.rs");
                }
            }
        }
    }
}

use generated::{
    buffa::cusf::{
        common::v1::{ConsensusHex, Hex},
        mainchain::v1::{
            self as mainchain, AckAllProposalsPolicy, CreateDepositTransactionRequest,
            CreateNewAddressRequest, GenerateToAddressRequest, GetBalanceRequest,
            GetBlockProducerStateRequest, GetChainTipRequest, GetSidechainsRequest,
            SetAckAllProposalsRequest, SidechainDeclaration, SubmitSidechainProposalRequest,
        },
    },
    connect::cusf::mainchain::v1::{
        BlockProducerServiceClient, MiningServiceClient, ValidatorServiceClient,
        WalletServiceClient,
    },
};

pub const THUNDER_SLOT: u32 = 9;

fn string(value: impl Into<String>) -> MessageField<StringValue, Inline<StringValue>> {
    MessageField::some(StringValue {
        value: value.into(),
        ..Default::default()
    })
}

fn u32_value(value: u32) -> MessageField<UInt32Value, Inline<UInt32Value>> {
    MessageField::some(UInt32Value {
        value,
        ..Default::default()
    })
}

fn u64_value(value: u64) -> MessageField<UInt64Value, Inline<UInt64Value>> {
    MessageField::some(UInt64Value {
        value,
        ..Default::default()
    })
}

pub struct Enforcer {
    validator: ValidatorServiceClient<HttpClient>,
    wallet: WalletServiceClient<HttpClient>,
    mining: MiningServiceClient<HttpClient>,
    block_producer: BlockProducerServiceClient<HttpClient>,
}

impl Enforcer {
    pub fn new(port: u16) -> anyhow::Result<Self> {
        let http = HttpClient::plaintext_http2_only();
        let config = ClientConfig::new(format!("http://127.0.0.1:{port}").parse()?);
        Ok(Self {
            validator: ValidatorServiceClient::new(http.clone(), config.clone()),
            wallet: WalletServiceClient::new(http.clone(), config.clone()),
            mining: MiningServiceClient::new(http.clone(), config.clone()),
            block_producer: BlockProducerServiceClient::new(http, config),
        })
    }

    /// Hash of the tip the validator has processed, as displayed hex.
    pub async fn tip(&self) -> anyhow::Result<String> {
        let tip = self
            .validator
            .get_chain_tip(GetChainTipRequest::default())
            .await?;
        let tip = tip.into_owned();
        Ok(tip
            .block_header_info
            .as_option()
            .and_then(|info| info.block_hash.as_option())
            .and_then(|hash| hash.hex.as_option())
            .map(|hex| hex.value.clone())
            .unwrap_or_default())
    }

    pub async fn new_address(&self) -> anyhow::Result<String> {
        let response = self
            .wallet
            .create_new_address(CreateNewAddressRequest::default())
            .await?;
        Ok(response.into_owned().address)
    }

    pub async fn confirmed_balance(&self) -> anyhow::Result<u64> {
        let response = self
            .wallet
            .get_balance(GetBalanceRequest::default())
            .await?;
        Ok(response.into_owned().confirmed_sats)
    }

    pub async fn generate_to_address(&self, address: &str) -> anyhow::Result<()> {
        self.mining
            .generate_to_address(GenerateToAddressRequest {
                blocks: u32_value(1),
                address: address.to_owned(),
            })
            .await?;
        Ok(())
    }

    /// Proposes Thunder's slot and ACKs every proposal for an empty slot.
    pub async fn propose_thunder(&self) -> anyhow::Result<()> {
        self.block_producer
            .set_ack_all_proposals(SetAckAllProposalsRequest {
                policy: AckAllProposalsPolicy::ACK_ALL_PROPOSALS_POLICY_NEW_SLOTS.into(),
            })
            .await?;
        let declaration = mainchain::sidechain_declaration::V0 {
            title: string("thunder"),
            description: string("thunder"),
            hash_id_1: MessageField::some(ConsensusHex {
                hex: string("0".repeat(64)),
            }),
            hash_id_2: MessageField::some(Hex {
                hex: string("0".repeat(40)),
            }),
        };
        self.block_producer
            .submit_sidechain_proposal(SubmitSidechainProposalRequest {
                sidechain_id: u32_value(THUNDER_SLOT),
                declaration: MessageField::some(SidechainDeclaration {
                    sidechain_declaration: Some(
                        mainchain::__buffa::oneof::sidechain_declaration::SidechainDeclaration::V0(
                            Box::new(declaration),
                        ),
                    ),
                }),
            })
            .await?;
        Ok(())
    }

    pub async fn pending_proposals(&self) -> anyhow::Result<usize> {
        let state = self
            .block_producer
            .get_block_producer_state(GetBlockProducerStateRequest::default())
            .await?;
        Ok(state.into_owned().pending_proposals.len())
    }

    pub async fn active_sidechains(&self) -> anyhow::Result<usize> {
        let response = self
            .validator
            .get_sidechains(GetSidechainsRequest::default())
            .await?;
        Ok(response.into_owned().sidechains.len())
    }

    /// Deposits `sats` from the enforcer wallet to a Thunder address. Returns
    /// the L1 txid.
    pub async fn deposit(&self, address: &str, sats: u64) -> anyhow::Result<String> {
        let response = self
            .wallet
            .create_deposit_transaction(CreateDepositTransactionRequest {
                sidechain_id: u32_value(THUNDER_SLOT),
                address: string(address),
                value_sats: u64_value(sats),
                fee_sats: u64_value(1_000_000),
            })
            .await?;
        response
            .into_owned()
            .txid
            .as_option()
            .and_then(|txid| txid.hex.as_option())
            .map(|hex| hex.value.clone())
            .ok_or_else(|| anyhow::anyhow!("deposit response has no txid"))
    }
}
