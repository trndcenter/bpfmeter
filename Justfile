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

# Builds all crates
build:
    @echo "-> Building all crates"
    @cargo build --workspace

# Builds all crates
build-release:
    @echo "-> Building all crates"
    @cargo build --release --workspace

# Runs all tests
test:
    @echo "-> Running tests"
    @cargo test --workspace

# Performs full code check before pushing to repository
prepare: check lint test
