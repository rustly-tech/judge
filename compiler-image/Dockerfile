FROM rust:1.88.0-slim-bookworm@sha256:38bc5a86d998772d4aec2348656ed21438d20fcdce2795b56ca434cf21430d89

RUN rustup target add wasm32-wasip1 \
    && rustc --version --verbose \
    && rustup component remove cargo \
    && rm -f /usr/local/cargo/bin/rustfmt /usr/local/cargo/bin/clippy-driver \
    && useradd --no-create-home --uid 65532 --shell /usr/sbin/nologin compiler

USER 65532:65532
ENTRYPOINT ["rustc"]
