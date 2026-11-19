# PKCS#11 payout signer

For running the wallet without Google Cloud KMS: the payout key lives on any
HSM that speaks PKCS#11 and supports secp256k1 ECDSA, such as a YubiHSM 2, a
network HSM, or AWS CloudHSM. The key is generated on the device and can't be
exported; the wallet only ever asks the device to sign.

You need:
- **The vendor's PKCS#11 module:** a `.so` or `.dylib`.
- **A token:** an initialized slot with a label and a user PIN.
- **`fastwithdraw-pkcs11`:** built with `cargo build --release -p fastwithdraw-signer`.

## 1. Generate the key and config

```sh
export PKCS11_PIN='<user PIN>'
fastwithdraw-pkcs11 init \
  --module /path/to/vendor-pkcs11.so \
  --token-label <token label> \
  --out signer.toml \
  --network bitcoin
```

This:
- generates a secp256k1 key pair labelled `fastwithdraw-payout` (override with
  `--key-label`), marked sensitive and non-extractable;
- signs a test digest with it;
- writes `signer.toml`;
- prints the public key and the payout address, which is the address to fund.

It refuses to overwrite an existing file, or to reuse a label the token
already has.

`signer.toml` contains no secrets:

```toml
module = "/path/to/vendor-pkcs11.so"
token_label = "<token label>"
key_label = "fastwithdraw-payout"
public_key = "03…"
```

`public_key` pins the key. The wallet refuses to start if the token's key
doesn't match it, so a swapped token or a mislabelled key fails loudly instead
of producing a different address.

## 2. Check it

```sh
PKCS11_PIN='<user PIN>' fastwithdraw-pkcs11 check --config signer.toml --network bitcoin
```

This loads the config exactly as the wallet does, signs, verifies the
signature, and prints the payout address. Run it after any change to the
host, the module or the token.

## 3. Run the wallet

```sh
WALLET_PKCS11_CONFIG=signer.toml PKCS11_PIN='<user PIN>' fastwithdraw-wallet …
```

Keep the PIN out of shell history and process listings. Use your secret store
or a systemd `LoadCredential`, and export it into the wallet's environment.

## Devices

### SoftHSM (testing only)

SoftHSM stores keys in files on disk. Use it for development and CI, never for
real funds.

```sh
brew install softhsm            # or: apt install softhsm2
export SOFTHSM2_CONF=$PWD/softhsm2.conf
mkdir -p tokens
printf 'directories.tokendir = %s/tokens\nobjectstore.backend = file\n' "$PWD" > softhsm2.conf
softhsm2-util --init-token --free --label fastwithdraw --pin 1234 --so-pin 5678
PKCS11_PIN=1234 fastwithdraw-pkcs11 init \
  --module "$(brew --prefix)/lib/softhsm/libsofthsm2.so" \
  --token-label fastwithdraw --out signer.toml --network regtest
```

The module is at `/usr/lib/softhsm/libsofthsm2.so` on Debian/Ubuntu.

### YubiHSM 2

- **Install** the YubiHSM SDK. It includes `yubihsm-connector`,
  `yubihsm-shell` and the PKCS#11 module `yubihsm_pkcs11.so`.
- **Connector:** run `yubihsm-connector` on the wallet host.
- **Module config:** point the module at the connector with
  `YUBIHSM_PKCS11_CONF`, a file containing `connector = http://127.0.0.1:12345`.
- **PIN:** an authentication key ID in 4 hex digits followed by its password,
  eg. `0001password`. Create a dedicated authentication key for the wallet with
  only the capabilities it needs to generate and sign with EC keys. Don't use
  the factory default key.
- **Token label:** list the slots with OpenSC's `pkcs11-tool`:
  `pkcs11-tool --module yubihsm_pkcs11.so --list-slots`.

### Other HSMs

Any module that supports `CKM_EC_KEY_PAIR_GEN` and `CKM_ECDSA` on secp256k1
(OID 1.3.132.0.10) works. Check with
`pkcs11-tool --module <module> --list-mechanisms`, then run `init` and `check`.

## Operating notes

- **The key has no backup by design.** Losing the device loses the funds at
  its address. Keep the hot balance small, top it up from cold storage, and
  sweep the excess back.
- **Rotating to a new device or key:** run `init` on the new token, fund its
  address, point the wallet at the new config, and sweep the old address.
- **Treat the token PIN as a signing credential.** Anyone with the PIN and
  access to the device can sign. The wallet's per-payout, daily and fee caps
  still apply to every payout it makes.
