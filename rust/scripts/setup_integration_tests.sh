#!/usr/bin/env bash
# Download integration-test dependencies and write integrationtests.env.
# Idempotent: cached artifacts are reused. Postgres is fetched at runtime by
# postgresql_embedded (cached under ~/.theseus).
set -euo pipefail

RUST_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Shared by all worktrees of this clone.
GIT_COMMON_DIR="$(cd "$RUST_ROOT" && git rev-parse --git-common-dir)"
case "$GIT_COMMON_DIR" in
    /*) ;;
    *) GIT_COMMON_DIR="$RUST_ROOT/$GIT_COMMON_DIR" ;;
esac
DEPS_DIR="$(cd "$GIT_COMMON_DIR/.." && pwd)/.integration-deps"

# The thunder_types tag the sweep tool builds against, so the tests run the
# Thunder release whose types it uses. Bumping it there means updating the
# THUNDER_SHA256 sums below.
THUNDER_VERSION="$(sed -nE 's/^thunder_types = .*tag = "v([^"]+)".*/\1/p' "$RUST_ROOT/Cargo.toml")"
if [ -z "$THUNDER_VERSION" ]; then
    echo "no thunder_types tag in $RUST_ROOT/Cargo.toml" >&2
    exit 1
fi
ELECTRS_VERSION="v3.2.0"
# The commit v3.2.0 points to, so a moved tag isn't built.
ELECTRS_COMMIT="e6eb9b5f8376e1c8de34fc01d93e5ba830c51f69"
BITCOIN_PATCHED_VERSION="v30.2"

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
# Every download is checked against these SHA-256 sums. The enforcer is only
# published as "latest", so a new enforcer release fails the check until the
# sum here is updated.
case "$OS-$ARCH" in
    linux-x86_64)
        TARGET="x86_64-unknown-linux-gnu"
        BITCOIN_PATCHED_SHA256="22191481bb9b7fb3fc6ea86b51bd842d6d3ebcca70f1331c9d534c61c6b99085"
        ENFORCER_SHA256="f8462ec68a1df6f9ef166402aae847a961ebad3bf0081f93c9181094d2b1436b"
        THUNDER_SHA256="68717682e3bb0af604c48e0d55ad60d60b24089338b60c7e22100087521a9e9a"
        ;;
    darwin-x86_64)
        TARGET="x86_64-apple-darwin"
        BITCOIN_PATCHED_SHA256="ca107eb36121969ff220eeb896ca991fee9eb72d0ae28a47884eacd3898fcced"
        ENFORCER_SHA256="66eaf4ab37d70e72362f2e87282c6ad378a71eabaa7a0dd9b2cd492db74e6b63"
        THUNDER_SHA256="1e8d7d54a87c5067edb1a13cf1bbae974119f4dbf7c8827d67a520d85f7dca05"
        ;;
    darwin-arm64)
        TARGET="aarch64-apple-darwin"
        BITCOIN_PATCHED_SHA256="d3e335b82eb9578dd3f473e2b5bf52d03baf9f947da1ffe21084d1d68637c1e2"
        ENFORCER_SHA256="f3185b86b0283568ffa1ed1da0945cb3b2d5b3d5532e1955c504888d03a994a1"
        THUNDER_SHA256="c565f424c3aae1ecff372685e84e1f1960545c1f9b6d359b8eb0f6300e2bcf7a"
        ;;
    *) echo "unsupported platform: $OS-$ARCH" >&2; exit 1 ;;
esac

mkdir -p "$DEPS_DIR"

# Fails unless file $1 has SHA-256 $2.
verify_sha256() {
    local file="$1" expected="$2" actual
    actual=$(shasum -a 256 "$file" | cut -d" " -f1)
    if [ "$actual" != "$expected" ]; then
        echo "SHA-256 mismatch for $file: expected $expected, got $actual." >&2
        echo "If the upstream release changed on purpose, update the sum in $0." >&2
        exit 1
    fi
}

# Downloads releases.drivechain.info/$1.zip, which unpacks to a directory
# named $1, into $3, after checking it has SHA-256 $2.
fetch_drivechain_zip() {
    local name="$1" sha256="$2" dest="$3" tmp
    tmp=$(mktemp -d)
    curl -# -fL "https://releases.drivechain.info/$name.zip" -o "$tmp/bins.zip"
    verify_sha256 "$tmp/bins.zip" "$sha256"
    unzip -q "$tmp/bins.zip" -d "$tmp"
    rm -rf "$dest"
    mv "$tmp/$name" "$dest"
    rm -rf "$tmp"
}

PATCHED_DIR="$DEPS_DIR/bitcoin-patched-$BITCOIN_PATCHED_VERSION"
if [ ! -x "$PATCHED_DIR/bitcoind" ]; then
    echo "Downloading patched bitcoin $BITCOIN_PATCHED_VERSION ($TARGET)..."
    fetch_drivechain_zip "L1-bitcoin-patched-$BITCOIN_PATCHED_VERSION-$TARGET" "$BITCOIN_PATCHED_SHA256" "$PATCHED_DIR"
    rm -rf "$PATCHED_DIR/qt" "$PATCHED_DIR/bitcoin-qt"
    chmod +x "$PATCHED_DIR/bitcoind" "$PATCHED_DIR/bitcoin-cli"
else
    echo "Patched bitcoin: cached"
fi

# Keyed by the pinned sum: "latest" names no version.
ENFORCER_DIR="$DEPS_DIR/bip300301-enforcer-${ENFORCER_SHA256:0:12}"
ENFORCER_BIN="$ENFORCER_DIR/bip300301-enforcer-latest-$TARGET"
if [ ! -x "$ENFORCER_BIN" ]; then
    echo "Downloading enforcer ($TARGET)..."
    fetch_drivechain_zip "bip300301-enforcer-latest-$TARGET" "$ENFORCER_SHA256" "$ENFORCER_DIR"
    chmod +x "$ENFORCER_BIN"
else
    echo "Enforcer: cached"
fi

THUNDER_BIN="$DEPS_DIR/thunder-$THUNDER_VERSION/thunder"
if [ ! -x "$THUNDER_BIN" ]; then
    echo "Downloading thunder $THUNDER_VERSION ($TARGET)..."
    mkdir -p "$(dirname "$THUNDER_BIN")"
    curl -# -fL "https://github.com/LayerTwo-Labs/thunder-rust/releases/download/v$THUNDER_VERSION/thunder-$THUNDER_VERSION-$TARGET" \
        -o "$THUNDER_BIN.download"
    verify_sha256 "$THUNDER_BIN.download" "$THUNDER_SHA256"
    chmod +x "$THUNDER_BIN.download"
    mv "$THUNDER_BIN.download" "$THUNDER_BIN"
else
    echo "Thunder: cached"
fi

ELECTRS_DIR="$DEPS_DIR/electrs-$ELECTRS_VERSION"
ELECTRS_BIN="$ELECTRS_DIR/electrs"
if [ ! -x "$ELECTRS_BIN" ]; then
    echo "Building electrs $ELECTRS_VERSION (a few minutes on a cold build)..."
    src=$(mktemp -d)
    trap 'rm -rf "$src"' EXIT
    git clone --branch "$ELECTRS_VERSION" --depth 1 https://github.com/mempool/electrs.git "$src/electrs"
    commit=$(git -C "$src/electrs" rev-parse HEAD)
    if [ "$commit" != "$ELECTRS_COMMIT" ]; then
        echo "electrs $ELECTRS_VERSION is at $commit, expected $ELECTRS_COMMIT." >&2
        exit 1
    fi
    printf '\n[workspace]\n' >> "$src/electrs/Cargo.toml"
    # electrs' RocksDB (8.1) omits <cstdint>, which GCC 13+ no longer pulls in
    # through other headers (eg. on Ubuntu 24.04).
    (cd "$src/electrs" && CXXFLAGS="${CXXFLAGS:-} -include cstdint" cargo build --locked --release)
    mkdir -p "$ELECTRS_DIR"
    cp "$src/electrs/target/release/electrs" "$ELECTRS_BIN"
    rm -rf "$src"
    trap - EXIT
else
    echo "electrs: cached"
fi

# SoftHSM backs the PKCS#11 signer tests. Installed from the system package
# manager rather than built here.
SOFTHSM2_UTIL="$(command -v softhsm2-util || true)"
SOFTHSM2_MODULE=""
for candidate in /opt/homebrew/lib/softhsm/libsofthsm2.so /usr/local/lib/softhsm/libsofthsm2.so \
    /usr/lib/softhsm/libsofthsm2.so /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so; do
    if [ -f "$candidate" ]; then SOFTHSM2_MODULE="$candidate"; break; fi
done
if [ -z "$SOFTHSM2_UTIL" ] || [ -z "$SOFTHSM2_MODULE" ]; then
    echo "SoftHSM not found; install it (brew install softhsm / apt install softhsm2)" >&2
    exit 1
fi

cat > "$RUST_ROOT/integrationtests.env" <<EOF
BITCOIND='$PATCHED_DIR/bitcoind'
BIP300301_ENFORCER='$ENFORCER_BIN'
ELECTRS='$ELECTRS_BIN'
THUNDER='$THUNDER_BIN'
FASTWITHDRAW_API='${CARGO_TARGET_DIR:-$RUST_ROOT/target}/debug/fastwithdraw-api'
FASTWITHDRAW_WALLET='${CARGO_TARGET_DIR:-$RUST_ROOT/target}/debug/fastwithdraw-wallet'
FASTWITHDRAW_PKCS11='${CARGO_TARGET_DIR:-$RUST_ROOT/target}/debug/fastwithdraw-pkcs11'
SOFTHSM2_UTIL='$SOFTHSM2_UTIL'
SOFTHSM2_MODULE='$SOFTHSM2_MODULE'
EOF
echo "Wrote $RUST_ROOT/integrationtests.env (deps cache: $DEPS_DIR)"
