# rustly-tech/judge

Sandboxed Rust submission judging for [Rustly](https://rustly.tech).

## The rule this repository exists to enforce

**Compilation and execution are separate security domains.** Cargo runs
`build.rs` and expands procedural macros, so compiling untrusted Rust *is*
running untrusted code — before there is any module to sandbox. We do not pretend
one sandbox covers both.

The second rule: **an infrastructure failure is never reported as the user's
mistake.** `JE`, `IE`, and `SE` are a different class from `CE`/`WA`/`TLE`, and
the type system makes converting one into the other something you have to write
out deliberately.

## Status

| Component | Status |
| --- | --- |
| Wasmtime execution backend | **IMPLEMENTED**, every bound covered by an adversarial test |
| Native execution backend | **EXPERIMENTAL** — refuses to execute; see [the qualification checklist](docs/THREAT_MODEL.md#10-qualification-checklist-for-the-native-backend) |
| Trial package format v1 | **IMPLEMENTED** |
| Checkers: exact, trimmed lines, tokens, float tolerance | **IMPLEMENTED** |
| Custom checker modules | **PLANNED** — the grader refuses rather than accepting everything |
| Grader (compile once, run many) | **IMPLEMENTED** |
| Artifact cache with verify-on-read and quarantine | **IMPLEMENTED** |
| Worker pipeline (resolve → compile → grade → report) | **IMPLEMENTED** |
| Standalone broker | **IMPLEMENTED** for self-hosted and offline use |
| Cargo compile backend | **EXPERIMENTAL**, double-locked, **not for untrusted input** |
| Interactive problems | **PLANNED** — reserved in the format so adding it is not a break |

Nothing here is described as production-ready that is not covered by tests. The
compile-sandbox gap is stated plainly in
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md#31-the-compile-sandbox-gap-stated-plainly).

## What the sandbox enforces

Each row has a test that tries to break it (`crates/sandbox/tests/limits.rs`).

| Control | Mechanism |
| --- | --- |
| Work bound | Wasmtime fuel — deterministic, fair across heterogeneous workers |
| Wall clock | Epoch interruption from a watchdog thread |
| Memory | A `ResourceLimiter` that refuses growth and records the denial as `MLE` |
| Output | A capped sink that records overflow, so `OLE` is distinguishable from a short program |
| Stack | `max_wasm_stack`, so deep recursion traps instead of eating the host stack |
| Filesystem | No preopened directories |
| Environment | No inherited environment variables |
| Network | No sockets in the WASI context |
| Host imports | Only WASI is linked; anything else fails to instantiate |

Fuel *and* wall clock, because neither alone is sufficient: fuel is deterministic
but does not count time outside the guest, and wall clock is unfair across
machines of different speeds.

## Layout

```
crates/
  common/          verdicts, the error→verdict mapping, resource limits
  protocol/        versioned job, result-manifest, and worker contracts
  problem-format/  the Trial package format
  checker/         output comparison
  grader/          compile-once/run-many orchestration
  sandbox/         ExecutionBackend, Wasmtime backend, native stub
  cache/           content-addressed artifact cache with quarantine
services/
  broker/          a standalone, self-hostable job broker
  worker/          resolve → compile → grade → report
```

### Where the broker lives

In the hosted deployment the broker is part of the **control plane**
(`rustly-tech/core`, `/api/v1/judge/*`), because leasing a job is a decision
about trust and authority and belongs with identity and hidden tests.

`services/broker` here is for the deployments where that is not what you want:
offline classrooms, self-hosted pools, developing a worker, and this repository's
own tests. It speaks the identical protocol, which keeps the protocol honest by
having two independent implementations of it.

## Judging a submission locally

No network, no broker, no database:

```sh
# Build a Trial package and a module, both addressed by CID.
mkdir -p /tmp/artifacts
# ... write package JSON and a .wasm into /tmp/artifacts named by their CIDs ...

cargo run -p rustly-judge-worker -- run-local \
  --artifacts /tmp/artifacts \
  --package b3:<package cid> \
  --source  b3:<module cid> \
  --trust trusted --hidden
```

It prints the result manifest and exits non-zero on any verdict other than `AC`,
so it works as a CI assertion with no extra scripting. `--redacted` prints the
submitter-safe manifest instead.

Running a broker and a worker together:

```sh
cargo run -p rustly-judge-broker            # 127.0.0.1:8090
cargo run -p rustly-judge-worker -- serve \
  --broker http://127.0.0.1:8090 \
  --artifacts /tmp/artifacts \
  --worker-id dev-1 --trust volunteer
```

The standalone broker has no authentication. Expose it only on a trusted network;
it still filters hidden tests structurally, so a misconfiguration degrades to
"no hidden tests dispatched", never to "hidden tests leaked".

## Tests

```sh
cargo test --workspace                       # hermetic; no toolchain, no network
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all --check
```

The sandbox suite uses hand-written WAT modules so it runs anywhere with no extra
toolchain and no network. A separate CI job compiles genuine Rust to
`wasm32-wasip1` and pushes it through the same pipeline, so the WAT is a fast,
precise complement to the real thing rather than a substitute for it.

## Verdicts

`AC` `CE` `WA` `TLE` `MLE` `OLE` `RTE` `JE` `IE` `SE`

`JE` and `IE` are **system faults**: retryable, recorded for operators, and never
a statement about the submitter. When aggregating a test set a system fault
dominates, because a submission we could not judge is unjudged, not wrong.

## Security

Read [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) before changing anything in
`crates/sandbox`, `crates/cache`, or the trust-class handling in
`crates/protocol`. Report vulnerabilities privately — see
[SECURITY.md](https://github.com/rustly-tech/.github/blob/main/SECURITY.md).

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
