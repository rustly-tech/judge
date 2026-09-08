# Real-Rust end-to-end fixture

The sandbox suite in `crates/sandbox/tests/limits.rs` uses hand-written WAT so it
runs anywhere with no toolchain and no network. That is fast and precise, but it
is not the thing users actually submit.

This fixture closes the gap: CI compiles `sum.rs` to `wasm32-wasip1` with a real
`rustc`, stores it and `package.json` in an artifact directory addressed by CID,
and pushes it through the same worker pipeline a production job takes.

Reproduce it locally:

```sh
rustup target add wasm32-wasip1

rustc --target wasm32-wasip1 -O -o /tmp/sum.wasm tests/fixtures/sum.rs
cargo run -p rustly-judge-worker -- seed \
  --artifacts /tmp/artifacts tests/fixtures/package.json /tmp/sum.wasm

cargo run -p rustly-judge-worker -- run-local \
  --artifacts /tmp/artifacts \
  --package b3:<package cid> --source b3:<module cid> \
  --trust trusted --hidden
```

`run-local` exits non-zero on any verdict other than `AC`, so no assertion
scripting is needed.

`wrong.rs` is the same program with a deliberate off-by-one, used to prove the
pipeline reports `WA` rather than accepting everything — a judge that only ever
says "accepted" passes a happy-path test too.
