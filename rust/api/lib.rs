//! The public fast-withdrawal API: signed quotes, L2 payment detection, and
//! payouts through the wallet service.

mod auth;
pub mod config;
mod server;
mod service;
mod store;
mod wallet_client;

pub use config::Config;
pub use server::{RateLimiter, run, service};
pub use service::{Error, Service, quote_bytes};
