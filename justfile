# Once just v1.39.0 is widely deployed, simplify with the `read` function.
NIGHTLY_VERSION := trim(read(justfile_directory() / "nightly-version"))

_default:
  @just --list

# Install rbmt (Rust Bitcoin Maintainer Tools).
@_install-rbmt:
  cargo install --quiet --git https://github.com/rust-bitcoin/rust-bitcoin-maintainer-tools.git --rev $(cat {{justfile_directory()}}/rbmt-version) cargo-rbmt

# Check spdk-core.
[group('spdk-core')]
check: 
  cargo check -p spdk-core

# Build spdk-core.
[group('spdk-core')]
build: 
  cargo build -p spdk-core

# Test spdk-core.
[group('spdk-core')]
test: 
  cargo test -p spdk-core

# Lint spdk-core.
[group('spdk-core')]
lint:
  cargo +{{NIGHTLY_VERSION}} clippy -p spdk-core

# Run cargo fmt
fmt:
  cargo +{{NIGHTLY_VERSION}} fmt --all

# Run dleq example (default)
run-dleq:
  cargo run --example dleq_example

# Run dleq example (standalone)
run-dleq-standalone:
  cargo run -p spdk-core --example dleq_example --no-default-features --features dleq-standalone

# Update the recent and minimal lock files using rbmt.
[group('tools')]
@update-lock-files: _install-rbmt
  rustup run {{NIGHTLY_VERSION}} cargo rbmt lock

# Run CI tasks with rbmt.
[group('ci')]
@ci task toolchain="stable" lock="recent": _install-rbmt
  RBMT_LOG_LEVEL=quiet rustup run {{toolchain}} cargo rbmt --lock-file {{lock}} {{task}}

# Test crate.
[group('ci')]
ci-test: (ci "test stable")

# Lint crate.
[group('ci')]
ci-lint: (ci "lint" NIGHTLY_VERSION)

# Bitcoin core integration tests.
[group('ci')]
ci-integration: (ci "integration")
