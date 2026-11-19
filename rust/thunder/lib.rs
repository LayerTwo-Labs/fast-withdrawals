//! Thunder sidechain support: a JSON-RPC client for the node's public RPC,
//! and the watch-only address derivation from `fastwithdraw-thunder-keys`.

pub mod rpc;

pub use fastwithdraw_thunder_keys::{self as keys, Address, Xpriv, Xpub};
pub use rpc::{BlockRef, Client, OutPoint, Payment};
