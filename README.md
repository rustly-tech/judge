# Rustly judge

Runs and checks Rustly exercises.

The judge reads a versioned Trial package, evaluates submitted Rust programs
against its test cases, and returns a structured verdict. User programs run
outside the API server.

## Repository guide

- `crates/problem` reads and validates Trial packages.
- `crates/checker` compares program output with expected results.
- `crates/grader` coordinates compilation and test cases.
- `crates/sandbox` enforces execution limits for WebAssembly programs.
- `crates/worker` leases jobs and reports results.
- `crates/broker` provides the worker-facing HTTP protocol.

Security assumptions, enforced limits, and open qualification work are recorded
in the [threat model](docs/THREAT_MODEL.md).

## Verify

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

The WebAssembly backend has adversarial tests for its documented limits. Native
execution and untrusted compilation remain disabled or experimental until their
isolation has been qualified.

## License

MIT or Apache-2.0, at your option.
