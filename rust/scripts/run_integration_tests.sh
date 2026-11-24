#!/usr/bin/env bash
# Run the integration tests. Args go to the test runner, eg. a test name
# filter. Dependencies are downloaded on first use.
set -euo pipefail

RUST_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$RUST_ROOT"
if [ ! -f integrationtests.env ]; then
    ./scripts/setup_integration_tests.sh
fi
# All features: the scheduler ID token test needs `gcp-auth`.
cargo build --locked --bins --all-features
FASTWITHDRAW_INTEGRATION_TEST_ENV="$RUST_ROOT/integrationtests.env" \
    cargo run --locked --example integration_tests -- "$@"
