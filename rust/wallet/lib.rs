//! The L1 payout wallet: a watch-only BDK wallet over one `wpkh` key whose
//! signatures come from a [`TxSigner`](fastwithdraw_signer::TxSigner).

pub mod config;
mod server;
mod service;
mod store;

pub use config::Config;
pub use server::run;
pub use service::{Error, Limits, Service};
