# Rustly judge threat model

This document says what the judge defends against, what it does **not** yet
defend against, and what would have to be true before we claim otherwise.

Maturity words are used literally: **IMPLEMENTED** (built and tested),
**QUALIFIED** (validated against an adversarial corpus and safe to depend on for
the stated purpose), **EXPERIMENTAL** (runs, envelope unsettled), **PLANNED**
(design only).

## 1. What we are protecting

| Asset | Why it matters | Consequence of loss |
| --- | --- | --- |
| Judge host integrity | Workers hold credentials and touch the data plane | Arbitrary code execution, lateral movement |
| Hidden tests | They are the authority behind every accepted verdict | Judging integrity destroyed for every user, permanently |
| Verdict integrity | Rank and progress derive from verdicts | Forged solves, corrupted ranking |
| Other users' submissions | People's own work | Privacy breach, plagiarism |
| Availability and cost | $0 mode must fail closed financially | Denial of service, unexpected spend |

## 2. The adversary

A submitter who can supply arbitrary Rust source and arbitrary stdin, repeatedly,
and who reads our source code. They may also operate a volunteer worker.

Out of scope for this document: a malicious Rustly operator, physical access, and
compromise of the Rust toolchain supply chain itself.

## 3. Two security domains

**Compilation and execution are separate domains.** Cargo runs `build.rs` at
build time and expands procedural macros inside the compiler process. Both are
arbitrary native code written by the submitter. Nothing about the execution
sandbox protects the compile step, because the compile step happens *before*
there is a module to sandbox.

| Domain | Backend | Status |
| --- | --- | --- |
| Execution | `rustly_sandbox::WasmtimeBackend` | **IMPLEMENTED**, adversarially tested (`crates/sandbox/tests/limits.rs`) |
| Execution | `rustly_sandbox::NativeBackend` | **EXPERIMENTAL**, refuses to execute |
| Compilation | `rustly_judge_worker::compile::PrecompiledModule` | **IMPLEMENTED** - executes nothing, so it is safe by construction |
| Compilation | `rustly_judge_worker::compile::CargoCompiler` | **EXPERIMENTAL**, double-locked, **not for untrusted input** |

### 3.1 The compile-sandbox gap, stated plainly

We do **not** currently have a qualified sandbox for compiling untrusted Rust.

`CargoCompiler` is behind the `cargo-compiler` Cargo feature *and* must be
unlocked at runtime by calling `unlock_for_trusted_input()`. Two locks, because
one feature flag is too easy to switch on in a deployment script. Its
`is_qualified_for_untrusted_code()` returns `false` unconditionally: unlocking
asserts something about the *input*, never about the backend.

Until that gap is closed, a production deployment judging public submissions must
compile in operator-controlled, disposable infrastructure that is treated as
already compromised, and hand the resulting module to a worker for execution.
The `PrecompiledModule` path exists precisely so that split is expressible.

## 4. Execution sandbox: what is enforced

Enforced by `WasmtimeBackend`, each with a test that tries to break it.

| Control | Mechanism | Test |
| --- | --- | --- |
| Work bound | Wasmtime fuel | `an_infinite_loop_is_stopped_by_the_work_bound` |
| Wall clock | Epoch interruption from a watchdog thread | `an_infinite_loop_is_stopped_by_the_wall_clock_when_fuel_is_plentiful` |
| Memory | `ResourceLimiter` refusing growth, recorded as `MLE` | `growing_memory_past_the_bound_is_reported_as_mle_not_as_a_trap` |
| Output | Capped sink that records overflow | `flooding_stdout_is_reported_as_ole_and_the_capture_stays_bounded` |
| Stack | `max_wasm_stack` | `unbounded_recursion_hits_the_stack_limit_instead_of_the_host_stack` |
| Filesystem | No preopened directories | `the_guest_has_no_preopened_directories` |
| Environment | No inherited environment | `the_guest_has_no_environment_variables` |
| Network | No network in the WASI context | no sockets are ever granted |
| Host imports | Only WASI is linked | `a_module_importing_anything_outside_wasi_fails_to_instantiate` |
| Determinism | Fuel accounting is host-independent | `the_same_module_run_twice_produces_the_same_outcome` |

Both a work bound and a wall-clock bound exist because neither alone is enough.
Fuel is deterministic and fair across heterogeneous workers - a slow volunteer
machine must not fail a submission a fast one accepts - but it does not count
time spent outside the guest. Wall clock is the backstop.

### 4.1 Residual risk in the execution sandbox

* **Wasmtime itself.** A JIT bug is a sandbox escape. Mitigated by tracking
  releases (Dependabot, `cargo-audit`, `cargo-deny`) and by keeping the engine
  configuration minimal: no GC, no component model, no threads.
* **Side channels.** Timing and cache side channels between concurrent guests are
  not addressed. This matters little today - there are no cross-tenant secrets in
  a guest - but it would matter if a future feature put one there.
* **Resource exhaustion of the host.** Bounds are per execution. A worker running
  many executions concurrently still needs host-level limits; that belongs to
  deployment, not to this crate.

## 5. Hidden tests

The rule: **hidden tests are never dispatched to a non-trusted worker.**

It is enforced in four independent places, so a mistake in one is caught by
another:

1. `TrustClass::may_receive_hidden_tests` - the single definition, `Trusted` only.
2. The broker computes `includes_hidden_tests` per lease from the leasing
   worker's trust class, never from the queue's own record and never from the
   worker's request body.
3. The worker's `JobSpec::validate` **refuses** a job carrying hidden tests when
   its own trust class does not permit them, even if the broker made a mistake.
4. `TrialPackage::public_only` **deletes** hidden cases rather than flagging
   them. A flag protects nothing once the bytes are on someone else's machine.

Publication is separately defended: `ResultManifest::redacted_for_submitter`
strips a hidden case's identity and its failure reason, because "expected 9973,
got 9971" leaks the answer as surely as the test file would.
`rustly_grader::is_safe_for_submitter` fails loudly on a manifest that was not
redacted.

## 6. Volunteer capacity and artifact quarantine

A volunteer worker can lie about what it computed. Therefore:

* Volunteer and community workers receive **public tests only**.
* Compiled artifacts they produce enter `Trust::Quarantined`. A quarantined
  artifact reads as **absent** to the judging path, so a caller that forgets to
  check trust gets a cache miss and a rebuild, not an unverified binary.
* Promotion requires trusted capacity to reproduce the artifact bit for bit. A
  mismatch destroys the quarantined copy and is reported as an integrity failure.

**A volunteer verdict is not authoritative.** Volunteer capacity accelerates the
public-test feedback loop; the accepted-verdict state in the control plane comes
from trusted workers running the hidden set.

## 7. Cache integrity

The cache is disposable. Every compiled artifact is rebuildable, so a corrupt
entry must cause a clean retry, never a wrong verdict.

* Content is addressed by BLAKE3 and **verified on every read**, not only on
  write. A cache that verifies only on write is trusting the filesystem.
* A failing entry is evicted before the error is returned, so the next read is a
  clean miss rather than a repeat failure.
* Compiled artifacts are looked up by a **build key** (source CID, environment,
  compiler identity) that indexes into content-addressed storage. The same source
  compiled by a different toolchain is a different artifact; serving one for the
  other would be a silent correctness bug.
* Cache failures map to `IE`, which is retryable, and never to `CE` or `WA`.

## 8. Verdict honesty

`JE`, `IE`, and `SE` are a different class from `CE`, `WA`, `TLE`, `MLE`, `OLE`,
`RTE`. This is enforced in the type system (`JudgeError::verdict`,
`Verdict::class`) and asserted by `no_judge_error_can_ever_become_ce_or_wa`.

When aggregating a test set, a system fault **dominates**: if any case could not
be judged, the submission is unjudged. Reporting `WA` because the object store
was down would be a lie the user cannot act on.

## 9. GitHub Actions is not the judge

CI builds and tests the judge **software**. It never executes user submissions.
Using Actions as production judging compute would be an abuse of the Terms and
would put untrusted code on runners with repository credentials.

## 10. Qualification checklist for the native backend

Every item must be true, and independently reviewed by someone who did not
implement it, before `NativeBackend::is_qualified_for_untrusted_code` may return
`true`. The list is mirrored in `NativeBackend::QUALIFICATION_REQUIREMENTS` so
shortening it is a visible diff.

- [ ] Deny-by-default seccomp-BPF syscall filter with an audited allowlist
- [ ] User namespace with no mapped privileged uid
- [ ] cgroup v2 limits for CPU, memory, and PIDs
- [ ] Read-only root filesystem, no `/proc`, `/sys`, or device access
- [ ] Network namespace with no interfaces
- [ ] `no_new_privs` set, all capabilities dropped
- [ ] rlimits for file size, open descriptors, address space
- [ ] An adversarial escape corpus the backend survives
- [ ] Independent review

## 11. Reporting

Report privately. See
[SECURITY.md](https://github.com/rustly-tech/.github/blob/main/SECURITY.md).
A sandbox escape, a hidden-test disclosure, a resource-limit bypass, or a verdict
forgery is critical by default.
