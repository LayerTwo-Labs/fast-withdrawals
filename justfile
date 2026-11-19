proto:
    buf format -w
    buf lint
    cd rust && buf generate --template buf.gen.yaml
    cd rust/integration_tests && buf generate --template buf.gen.yaml

# Lints every released feature set (the image variants in rust-docker.yml)
# and all features.
test:
    cd rust && cargo clippy --quiet --workspace --all-targets
    cd rust && cargo clippy --quiet --workspace --all-targets --features "fastwithdraw-api/gcp-kms fastwithdraw-api/gcp-auth fastwithdraw-wallet/gcp-kms"
    cd rust && cargo clippy --quiet --workspace --all-targets --all-features
    cd rust && cargo test --quiet --workspace --all-features

# Integration tests against a regtest stack; args filter tests.
test-it *args='':
    rust/scripts/run_integration_tests.sh {{ args }}

docker:
    docker build --target api -t fastwithdraw-api rust
    docker build --target wallet -t fastwithdraw-wallet rust
