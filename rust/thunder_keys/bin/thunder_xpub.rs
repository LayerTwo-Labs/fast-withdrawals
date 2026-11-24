//! Offline tool for the cold Thunder key.
//!
//!     thunder-xpub new                       new mnemonic and its xpub
//!     thunder-xpub [ADDRESSES] < mnemonic.txt  xpub of an existing mnemonic,
//!                                              and its first ADDRESSES addresses

use std::io::{Read as _, Write as _};

use fastwithdraw_thunder_keys::Xpriv;
use rand::TryRng as _;
use zeroize::Zeroizing;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arg = std::env::args().nth(1);
    let mut out = std::io::stdout().lock();
    if arg.as_deref() == Some("new") {
        let mut entropy = Zeroizing::new([0u8; 16]);
        rand::rngs::SysRng.try_fill_bytes(entropy.as_mut())?;
        let mnemonic = bip39::Mnemonic::from_entropy(entropy.as_ref())?;
        let words = Zeroizing::new(mnemonic.to_string());
        let xpub = Xpriv::from_mnemonic(&words)?.account().xpub();
        writeln!(
            out,
            "Mnemonic: write it down and keep it offline. It controls every customer payment.\n\n  {}\n\nAccount xpub, for THUNDER_XPUB:\n\n  {xpub}\n\nIts first receive address, to check against Thunder's wallet:\n\n  {}",
            words.as_str(),
            xpub.address(1)?
        )?;
        return Ok(());
    }
    let addresses: u32 = arg.map(|n| n.parse()).transpose()?.unwrap_or(0);
    let mut mnemonic = Zeroizing::new(String::new());
    std::io::stdin().read_to_string(&mut mnemonic)?;
    let xpub = Xpriv::from_mnemonic(mnemonic.trim())?.account().xpub();
    writeln!(out, "{xpub}")?;
    for index in 1..=addresses {
        writeln!(out, "{index} {}", xpub.address(index)?)?;
    }
    Ok(())
}
