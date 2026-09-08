//! Adversarial tests for the Wasmtime sandbox.
//!
//! Every bound the judge claims to enforce is exercised here by a module that
//! deliberately tries to break it. The modules are written in WAT rather than
//! compiled from Rust so the suite runs on any machine with no extra toolchain
//! and no network - `cargo test` alone must be able to prove these properties.
//!
//! A separate CI job compiles genuine Rust to `wasm32-wasip1` and runs it
//! through the same backend, so the WAT here is a fast, precise complement to
//! the real thing rather than a substitute for it.

use rustly_judge_common::{LimitViolation, Limits, Verdict};
use rustly_sandbox::{
    ExecutionBackend, ExecutionOutcome, ExecutionRequest, TerminationReason, WasmtimeBackend,
};

fn run(wat: &str, limits: Limits) -> ExecutionOutcome {
    run_with_stdin(wat, limits, b"")
}

fn run_with_stdin(wat: &str, limits: Limits, stdin: &[u8]) -> ExecutionOutcome {
    let module = wat::parse_str(wat).expect("test module must assemble");
    let backend = WasmtimeBackend::new().expect("backend must construct");
    backend
        .execute(ExecutionRequest {
            module: &module,
            stdin,
            args: &[],
            limits,
        })
        .expect("a misbehaving guest is an outcome, never a judge error")
}

fn violation(outcome: &ExecutionOutcome) -> Option<LimitViolation> {
    match outcome.termination {
        TerminationReason::LimitExceeded { violation } => Some(violation),
        _ => None,
    }
}

/// Escape bytes for a WAT string literal, which cannot contain a raw newline.
fn wat_escape(payload: &str) -> String {
    payload
        .bytes()
        .map(|b| match b {
            b'\n' => "\\n".to_owned(),
            b'\t' => "\\t".to_owned(),
            b'"' => "\\\"".to_owned(),
            b'\\' => "\\\\".to_owned(),
            0x20..=0x7e => (b as char).to_string(),
            other => format!("\\{other:02x}"),
        })
        .collect()
}

/// Writes `payload` from address 1024 to fd 1, `count` times.
fn writer(payload: &str, count: u32) -> String {
    format!(
        r#"(module
  (import "wasi_snapshot_preview1" "fd_write"
    (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 1024) "{payload}")
  (func (export "_start")
    (local $i i32)
    (i32.store (i32.const 8) (i32.const 1024))
    (i32.store (i32.const 12) (i32.const {len}))
    (loop $l
      (drop (call $fd_write (i32.const 1) (i32.const 8) (i32.const 1) (i32.const 20)))
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br_if $l (i32.lt_u (local.get $i) (i32.const {count}))))))"#,
        payload = wat_escape(payload),
        len = payload.len(),
    )
}

#[test]
fn a_well_behaved_program_exits_cleanly_and_its_output_is_captured() {
    let outcome = run(&writer("42\n", 1), Limits::default());
    assert_eq!(outcome.termination, TerminationReason::Exited { code: 0 });
    assert_eq!(outcome.stdout_lossy(), "42\n");
    assert!(outcome.is_clean_exit());
    assert_eq!(
        outcome.termination_verdict(),
        None,
        "a clean exit leaves correctness to the checker, not the sandbox"
    );
    assert!(
        outcome.fuel_consumed.unwrap() > 0,
        "fuel accounting must be live"
    );
}

#[test]
fn an_infinite_loop_is_stopped_by_the_work_bound() {
    let outcome = run(
        r#"(module (memory (export "memory") 1) (func (export "_start") (loop $l (br $l))))"#,
        Limits {
            fuel: 1_000_000,
            wall_ms: 60_000,
            ..Limits::default()
        },
    );
    assert_eq!(violation(&outcome), Some(LimitViolation::Fuel));
    assert_eq!(
        outcome.termination_verdict(),
        Some(Verdict::TimeLimitExceeded)
    );
}

#[test]
fn an_infinite_loop_is_stopped_by_the_wall_clock_when_fuel_is_plentiful() {
    let outcome = run(
        r#"(module (memory (export "memory") 1) (func (export "_start") (loop $l (br $l))))"#,
        // Fuel high enough that the wall-clock watchdog must be what stops it.
        Limits {
            fuel: u64::MAX / 2,
            wall_ms: 250,
            ..Limits::default()
        },
    );
    assert_eq!(violation(&outcome), Some(LimitViolation::Wall));
    assert_eq!(
        outcome.termination_verdict(),
        Some(Verdict::TimeLimitExceeded)
    );
    assert!(
        outcome.wall_ms >= 200,
        "the guest should have run for about the budget"
    );
    assert!(
        outcome.wall_ms < 10_000,
        "the watchdog must actually interrupt it"
    );
}

#[test]
fn the_watchdog_does_not_delay_a_fast_program() {
    let started = std::time::Instant::now();
    let outcome = run(
        &writer("x", 1),
        Limits {
            wall_ms: 30_000,
            ..Limits::default()
        },
    );
    assert!(outcome.is_clean_exit());
    assert!(
        started.elapsed().as_secs() < 5,
        "the watchdog must exit as soon as the guest finishes, not sleep out the budget"
    );
}

#[test]
fn growing_memory_past_the_bound_is_reported_as_mle_not_as_a_trap() {
    let outcome = run(
        r#"(module (memory (export "memory") 1)
             (func (export "_start") (drop (memory.grow (i32.const 2000)))))"#,
        Limits {
            memory_bytes: 2 * 1024 * 1024,
            ..Limits::default()
        },
    );
    assert_eq!(violation(&outcome), Some(LimitViolation::Memory));
    assert_eq!(
        outcome.termination_verdict(),
        Some(Verdict::MemoryLimitExceeded)
    );
}

#[test]
fn memory_growth_within_the_bound_succeeds_and_is_recorded_as_the_peak() {
    let outcome = run(
        r#"(module (memory (export "memory") 1)
             (func (export "_start") (drop (memory.grow (i32.const 8)))))"#,
        Limits {
            memory_bytes: 8 * 1024 * 1024,
            ..Limits::default()
        },
    );
    assert!(outcome.is_clean_exit());
    assert!(
        outcome.peak_memory_bytes >= 9 * 65_536,
        "peak memory should reflect the grown size, got {}",
        outcome.peak_memory_bytes
    );
}

#[test]
fn flooding_stdout_is_reported_as_ole_and_the_capture_stays_bounded() {
    let limits = Limits {
        output_bytes: 1024,
        ..Limits::default()
    };
    let outcome = run(&writer(&"A".repeat(256), 200), limits);

    assert_eq!(violation(&outcome), Some(LimitViolation::Output));
    assert_eq!(
        outcome.termination_verdict(),
        Some(Verdict::OutputLimitExceeded)
    );
    assert!(
        outcome.stdout.len() <= 1024,
        "captured output must stay inside the bound, got {} bytes",
        outcome.stdout.len()
    );
}

#[test]
fn output_exactly_at_the_bound_is_not_an_overflow() {
    let limits = Limits {
        output_bytes: 256,
        ..Limits::default()
    };
    let outcome = run(&writer(&"B".repeat(256), 1), limits);
    assert!(
        outcome.is_clean_exit(),
        "256 bytes into a 256-byte budget is fine"
    );
    assert_eq!(outcome.stdout.len(), 256);
}

#[test]
fn an_unreachable_instruction_is_a_runtime_error_not_a_judge_error() {
    let outcome = run(
        r#"(module (memory (export "memory") 1) (func (export "_start") unreachable))"#,
        Limits::default(),
    );
    assert!(matches!(
        outcome.termination,
        TerminationReason::Trapped { .. }
    ));
    assert_eq!(outcome.termination_verdict(), Some(Verdict::RuntimeError));
}

#[test]
fn integer_division_by_zero_traps_cleanly() {
    let outcome = run(
        r#"(module (memory (export "memory") 1)
             (func (export "_start") (drop (i32.div_s (i32.const 1) (i32.const 0)))))"#,
        Limits::default(),
    );
    match &outcome.termination {
        TerminationReason::Trapped { detail } => {
            assert!(
                detail.contains("divide by zero"),
                "unexpected detail: {detail}"
            );
        }
        other => panic!("expected a trap, got {other:?}"),
    }
}

#[test]
fn an_out_of_bounds_memory_access_traps_rather_than_reading_host_memory() {
    let outcome = run(
        r#"(module (memory (export "memory") 1)
             (func (export "_start") (drop (i32.load (i32.const 0x7fffff00)))))"#,
        Limits::default(),
    );
    match &outcome.termination {
        TerminationReason::Trapped { detail } => {
            assert!(
                detail.contains("out of bounds"),
                "unexpected detail: {detail}"
            );
        }
        other => panic!("expected a trap, got {other:?}"),
    }
}

#[test]
fn unbounded_recursion_hits_the_stack_limit_instead_of_the_host_stack() {
    let outcome = run(
        r#"(module (memory (export "memory") 1)
             (func $f (call $f))
             (func (export "_start") (call $f)))"#,
        Limits {
            fuel: u64::MAX / 2,
            wall_ms: 30_000,
            ..Limits::default()
        },
    );
    match &outcome.termination {
        TerminationReason::Trapped { detail } => {
            assert!(detail.contains("stack"), "unexpected detail: {detail}");
        }
        other => panic!("expected a stack-exhaustion trap, got {other:?}"),
    }
}

#[test]
fn proc_exit_with_a_non_zero_code_is_a_runtime_error() {
    let outcome = run(
        r#"(module
             (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
             (memory (export "memory") 1)
             (func (export "_start") (call $exit (i32.const 3))))"#,
        Limits::default(),
    );
    assert_eq!(outcome.termination, TerminationReason::Exited { code: 3 });
    assert_eq!(outcome.termination_verdict(), Some(Verdict::RuntimeError));
}

#[test]
fn proc_exit_with_zero_is_a_clean_exit() {
    let outcome = run(
        r#"(module
             (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
             (memory (export "memory") 1)
             (func (export "_start") (call $exit (i32.const 0))))"#,
        Limits::default(),
    );
    assert_eq!(outcome.termination, TerminationReason::Exited { code: 0 });
}

#[test]
fn stdin_is_readable_and_is_exactly_what_the_test_case_supplied() {
    // Read up to 16 bytes from fd 0 into memory, then write them back to fd 1.
    let wat = r#"(module
  (import "wasi_snapshot_preview1" "fd_read"
    (func $fd_read (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_write"
    (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (func (export "_start")
    (i32.store (i32.const 8) (i32.const 1024))
    (i32.store (i32.const 12) (i32.const 16))
    (drop (call $fd_read (i32.const 0) (i32.const 8) (i32.const 1) (i32.const 20)))
    (i32.store (i32.const 12) (i32.load (i32.const 20)))
    (drop (call $fd_write (i32.const 1) (i32.const 8) (i32.const 1) (i32.const 24)))))"#;

    let outcome = run_with_stdin(wat, Limits::default(), b"7 11\n");
    assert!(outcome.is_clean_exit());
    assert_eq!(outcome.stdout_lossy(), "7 11\n");
}

#[test]
fn the_guest_has_no_preopened_directories() {
    // fd_prestat_get(3) returns errno 8 (EBADF) when nothing is preopened.
    // Anything else would mean the guest can reach a host directory.
    let wat = r#"(module
  (import "wasi_snapshot_preview1" "fd_prestat_get"
    (func $prestat (param i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_write"
    (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (func (export "_start")
    (i32.store8 (i32.const 1024)
      (i32.add (i32.const 48) (call $prestat (i32.const 3) (i32.const 64))))
    (i32.store (i32.const 8) (i32.const 1024))
    (i32.store (i32.const 12) (i32.const 1))
    (drop (call $fd_write (i32.const 1) (i32.const 8) (i32.const 1) (i32.const 20)))))"#;

    let outcome = run(wat, Limits::default());
    assert!(outcome.is_clean_exit());
    assert_ne!(
        outcome.stdout_lossy(),
        "0",
        "fd_prestat_get(3) must not succeed: the guest would have a directory"
    );
}

#[test]
fn the_guest_has_no_environment_variables() {
    // environ_sizes_get writes the count at address 64. It must be zero: an
    // inherited environment could leak host secrets into a judged program.
    let wat = r#"(module
  (import "wasi_snapshot_preview1" "environ_sizes_get"
    (func $sizes (param i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_write"
    (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (func (export "_start")
    (drop (call $sizes (i32.const 64) (i32.const 68)))
    (i32.store8 (i32.const 1024) (i32.add (i32.const 48) (i32.load (i32.const 64))))
    (i32.store (i32.const 8) (i32.const 1024))
    (i32.store (i32.const 12) (i32.const 1))
    (drop (call $fd_write (i32.const 1) (i32.const 8) (i32.const 1) (i32.const 20)))))"#;

    let outcome = run(wat, Limits::default());
    assert!(outcome.is_clean_exit());
    assert_eq!(
        outcome.stdout_lossy(),
        "0",
        "the guest environment must be empty"
    );
}

#[test]
fn a_module_importing_anything_outside_wasi_fails_to_instantiate() {
    let module = wat::parse_str(
        r#"(module
             (import "host" "escape" (func $escape))
             (memory (export "memory") 1)
             (func (export "_start") (call $escape)))"#,
    )
    .unwrap();

    let backend = WasmtimeBackend::new().unwrap();
    let error = backend
        .execute(ExecutionRequest {
            module: &module,
            stdin: b"",
            args: &[],
            limits: Limits::default(),
        })
        .expect_err("only WASI is linked; nothing else may be imported");

    // A module we could not have produced is a judge-side problem, and it is a
    // JE rather than a CE so the user is never blamed for it.
    assert_eq!(error.verdict(), Verdict::JudgeError);
}

#[test]
fn limits_that_disable_a_bound_are_rejected_before_anything_runs() {
    let module =
        wat::parse_str(r#"(module (memory (export "memory") 1) (func (export "_start")))"#)
            .unwrap();
    let backend = WasmtimeBackend::new().unwrap();

    let error = backend
        .execute(ExecutionRequest {
            module: &module,
            stdin: b"",
            args: &[],
            limits: Limits {
                fuel: 0,
                ..Limits::default()
            },
        })
        .expect_err("fuel: 0 is malformed, not unlimited");
    assert_eq!(error.verdict(), Verdict::JudgeError);
}

#[test]
fn the_same_module_run_twice_produces_the_same_outcome() {
    let wat = writer("deterministic\n", 1);
    let first = run(&wat, Limits::default());
    let second = run(&wat, Limits::default());

    assert_eq!(first.termination, second.termination);
    assert_eq!(first.stdout, second.stdout);
    assert_eq!(
        first.fuel_consumed, second.fuel_consumed,
        "fuel is the deterministic bound; it must not vary between runs"
    );
}

#[test]
fn a_guest_cannot_exhaust_the_host_by_writing_to_stderr_either() {
    let wat = format!(
        r#"(module
  (import "wasi_snapshot_preview1" "fd_write"
    (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 1024) "{}")
  (func (export "_start")
    (local $i i32)
    (i32.store (i32.const 8) (i32.const 1024))
    (i32.store (i32.const 12) (i32.const 256))
    (loop $l
      (drop (call $fd_write (i32.const 2) (i32.const 8) (i32.const 1) (i32.const 20)))
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br_if $l (i32.lt_u (local.get $i) (i32.const 200))))))"#,
        "E".repeat(256)
    );

    let outcome = run(
        &wat,
        Limits {
            output_bytes: 512,
            ..Limits::default()
        },
    );
    assert_eq!(violation(&outcome), Some(LimitViolation::Output));
    assert!(outcome.stderr.len() <= 512);
}
