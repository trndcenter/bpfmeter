FROM rust:latest AS bpfmeter-local-builder

RUN apt update && apt install -y pkg-config libfreetype-dev libfontconfig1-dev

RUN rustup toolchain install nightly --component rust-src

RUN cargo install bpf-linker bindgen-cli
RUN cargo install --git https://github.com/aya-rs/aya -- aya-tool

WORKDIR /bpfmeter

# Copy manifest and source
COPY Cargo.toml Cargo.lock ./
COPY bpfmeter ./bpfmeter

# Build the binary
RUN cargo build --release --no-default-features

FROM gcr.io/distroless/cc-debian12
COPY --from=bpfmeter-local-builder /bpfmeter/target/release/bpfmeter /usr/local/bin/

ENTRYPOINT [ "/usr/local/bin/bpfmeter" ]

# Run bpfmeter to export data in OpenMetrics format:
LABEL usage="docker run --rm -it -p 9100:9100 --privileged bpfmeter run -P 9100"
