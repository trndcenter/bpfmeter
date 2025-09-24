export RUSTFLAGS := "-D warnings"
export RUSTDOCFLAGS := "-D warnings"

# List of available commands
help:
    @just --list

# Format source code
fmt:
    @echo "-> Formatting code"
    @cargo fmt --all

# Performs quick checks of source code for compliance with formatting standards
check:
    @echo "-> Checking code format"
    @cargo fmt --all -- --check

# Performs more detailed code quality checks
lint:
    @echo "-> Checking code style"
    @cargo clippy --workspace

# Builds crate
build:
    @echo "-> Building all crates"
    @cargo build --workspace

# Builds crate without default features
build-minimized:
    @echo "-> Building all crates"
    @cargo build --workspace --no-default-features

# Builds release crate
build-release:
    @echo "-> Building all crates"
    @cargo build --release --workspace

# Builds release crate without default features
build-release-minimized:
    @echo "-> Building all crates"
    @cargo build --release --workspace --no-default-features

# Runs all tests
test:
    @echo "-> Running tests"
    @cargo test --workspace

# Update version
update-version old new:
    @echo "-> Updating version to {{new}}"
    @sed -i "s/version = \"{{old}}\"/version = \"{{new}}\"/g" bpfmeter/Cargo.toml
    @sed -i "s/bpfmeter:v{{old}}/bpfmeter:v{{new}}/g" README.md
    @sed -i "s/bpfmeter:v{{old}}/bpfmeter:v{{new}}/g" install/kubernetes/bpfmeter-agent.yaml

# Performs full code check before pushing to repository
prepare: check lint test
