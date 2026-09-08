//! Grading tests.
//!
//! Most cases use a scripted backend so that aggregation, fail-fast, and
//! system-fault handling are tested precisely rather than approximately. Two
//! cases use the real Wasmtime backend, so the wiring between grader, sandbox,
//! and checker is proven end to end rather than assumed.

use std::sync::Mutex;

use rustly_judge_common::{JudgeError, LimitViolation, Limits, Verdict};
use rustly_problem_format::{
    Checker, Environment, Mode, Scoring, TestCase, TrialPackage, Visibility, FORMAT_VERSION,
};
use rustly_sandbox::{
    ExecutionBackend, ExecutionOutcome, ExecutionRequest, ExecutionResult, TerminationReason,
    WasmtimeBackend,
};

use rustly_grader::{grade, is_safe_for_submitter, GradeRequest};

/// A backend that replays a fixed script, so aggregation logic can be tested
/// without depending on what a particular WASM module happens to do.
struct ScriptedBackend {
    script: Mutex<Vec<ExecutionResult>>,
    qualified: bool,
    calls: Mutex<usize>,
}

impl ScriptedBackend {
    fn new(script: Vec<ExecutionResult>) -> Self {
        Self {
            script: Mutex::new(script),
            qualified: true,
            calls: Mutex::new(0),
        }
    }

    fn unqualified() -> Self {
        Self {
            script: Mutex::new(vec![]),
            qualified: false,
            calls: Mutex::new(0),
        }
    }

    fn calls(&self) -> usize {
        *self.calls.lock().unwrap()
    }
}

impl ExecutionBackend for ScriptedBackend {
    fn id(&self) -> &'static str {
        "scripted"
    }

    fn is_qualified_for_untrusted_code(&self) -> bool {
        self.qualified
    }

    fn execute(&self, _request: ExecutionRequest<'_>) -> ExecutionResult {
        *self.calls.lock().unwrap() += 1;
        let mut script = self.script.lock().unwrap();
        if script.is_empty() {
            panic!("the scripted backend was called more times than the test expected");
        }
        script.remove(0)
    }
}

fn ok(stdout: &str) -> ExecutionResult {
    Ok(ExecutionOutcome {
        termination: TerminationReason::Exited { code: 0 },
        stdout: stdout.as_bytes().to_vec(),
        stderr: vec![],
        wall_ms: 1,
        fuel_consumed: Some(100),
        peak_memory_bytes: 65_536,
    })
}

fn limit(violation: LimitViolation) -> ExecutionResult {
    Ok(ExecutionOutcome {
        termination: TerminationReason::LimitExceeded { violation },
        stdout: vec![],
        stderr: vec![],
        wall_ms: 2_000,
        fuel_consumed: Some(0),
        peak_memory_bytes: 0,
    })
}

fn case(id: &str, visibility: Visibility, expected: &str) -> TestCase {
    TestCase {
        id: id.into(),
        visibility,
        stdin: String::new(),
        expected_stdout: expected.into(),
        args: vec![],
        group: None,
        limits: None,
    }
}

fn package(tests: Vec<TestCase>, fail_fast: bool) -> TrialPackage {
    TrialPackage {
        format_version: FORMAT_VERSION,
        slug: "ownership-move-or-borrow".into(),
        version: 3,
        mode: Mode::Batch,
        environment: Environment::default(),
        limits: Limits::default(),
        checker: Checker::TrimmedLines,
        scoring: Scoring::AllOrNothing,
        fail_fast,
        groups: vec![],
        tests,
    }
}

fn request<'a>(package: &'a TrialPackage, module: &'a [u8]) -> GradeRequest<'a> {
    GradeRequest {
        job_id: "job-1",
        module,
        package,
        compiler_diagnostics: None,
        compile_ms: 850,
        used_cached_artifact: false,
    }
}

#[test]
fn every_passing_case_yields_accepted() {
    let package = package(
        vec![
            case("public-1", Visibility::Public, "3\n"),
            case("hidden-1", Visibility::Hidden, "5\n"),
        ],
        true,
    );
    let backend = ScriptedBackend::new(vec![ok("3\n"), ok("5\n")]);

    let manifest = grade(&backend, request(&package, b"module")).unwrap();
    assert_eq!(manifest.verdict, Verdict::Accepted);
    assert_eq!(manifest.tests.len(), 2);
    assert_eq!(
        manifest.trial_version, 3,
        "the verdict is tied to a content version"
    );
    assert!(manifest
        .tests
        .iter()
        .all(|t| t.verdict == Verdict::Accepted));
}

#[test]
fn compile_once_run_many_executes_the_same_module_per_case() {
    let package = package(
        vec![
            case("public-1", Visibility::Public, "1\n"),
            case("public-2", Visibility::Public, "2\n"),
            case("public-3", Visibility::Public, "3\n"),
        ],
        true,
    );
    let backend = ScriptedBackend::new(vec![ok("1\n"), ok("2\n"), ok("3\n")]);

    let manifest = grade(&backend, request(&package, b"module")).unwrap();
    assert_eq!(manifest.verdict, Verdict::Accepted);
    assert_eq!(
        backend.calls(),
        3,
        "one execution per case, one compilation for all"
    );
    assert_eq!(
        manifest.compile_ms, 850,
        "compilation is not repeated per case"
    );
}

#[test]
fn public_cases_run_before_hidden_ones() {
    let package = package(
        vec![
            case("z-hidden", Visibility::Hidden, "h\n"),
            case("a-public", Visibility::Public, "p\n"),
        ],
        false,
    );
    let backend = ScriptedBackend::new(vec![ok("p\n"), ok("h\n")]);

    let manifest = grade(&backend, request(&package, b"module")).unwrap();
    let ids: Vec<&str> = manifest.tests.iter().map(|t| t.test_id.as_str()).collect();
    assert_eq!(
        ids,
        ["a-public", "z-hidden"],
        "a learner sees the actionable failure first"
    );
}

#[test]
fn fail_fast_stops_at_the_first_user_failure() {
    let package = package(
        vec![
            case("public-1", Visibility::Public, "1\n"),
            case("public-2", Visibility::Public, "2\n"),
            case("public-3", Visibility::Public, "3\n"),
        ],
        true,
    );
    let backend = ScriptedBackend::new(vec![ok("1\n"), ok("wrong\n")]);

    let manifest = grade(&backend, request(&package, b"module")).unwrap();
    assert_eq!(manifest.verdict, Verdict::WrongAnswer);
    assert_eq!(manifest.tests.len(), 2);
    assert_eq!(backend.calls(), 2);
}

#[test]
fn without_fail_fast_every_case_runs() {
    let package = package(
        vec![
            case("public-1", Visibility::Public, "1\n"),
            case("public-2", Visibility::Public, "2\n"),
            case("public-3", Visibility::Public, "3\n"),
        ],
        false,
    );
    let backend = ScriptedBackend::new(vec![ok("wrong\n"), ok("2\n"), ok("wrong\n")]);

    let manifest = grade(&backend, request(&package, b"module")).unwrap();
    assert_eq!(manifest.verdict, Verdict::WrongAnswer);
    assert_eq!(manifest.tests.len(), 3);
}

#[test]
fn a_system_fault_dominates_and_stops_the_run_immediately() {
    let package = package(
        vec![
            case("public-1", Visibility::Public, "1\n"),
            case("public-2", Visibility::Public, "2\n"),
            case("public-3", Visibility::Public, "3\n"),
        ],
        false,
    );
    // The first case is a plain wrong answer; the second cannot be executed.
    let backend = ScriptedBackend::new(vec![
        ok("wrong\n"),
        Err(JudgeError::Infrastructure(
            "object store unreachable".into(),
        )),
    ]);

    let error = grade(&backend, request(&package, b"module")).unwrap_err();
    assert_eq!(
        error.verdict(),
        Verdict::InternalError,
        "a submission we could not judge must not be reported as wrong"
    );
    assert!(error.is_retryable());
}

#[test]
fn cache_corruption_produces_a_retryable_internal_error_not_a_wrong_answer() {
    let package = package(vec![case("public-1", Visibility::Public, "1\n")], true);
    let backend = ScriptedBackend::new(vec![Err(JudgeError::CacheIntegrity {
        cid: "b3:abc".into(),
        detail: "hash mismatch".into(),
    })]);

    let error = grade(&backend, request(&package, b"module")).unwrap_err();
    assert_eq!(error.verdict(), Verdict::InternalError);
    assert!(error.is_retryable());
}

#[test]
fn limit_violations_map_to_their_own_verdicts() {
    for (violation, expected) in [
        (LimitViolation::Wall, Verdict::TimeLimitExceeded),
        (LimitViolation::Fuel, Verdict::TimeLimitExceeded),
        (LimitViolation::Memory, Verdict::MemoryLimitExceeded),
        (LimitViolation::Output, Verdict::OutputLimitExceeded),
    ] {
        let package = package(vec![case("public-1", Visibility::Public, "1\n")], true);
        let backend = ScriptedBackend::new(vec![limit(violation)]);
        let manifest = grade(&backend, request(&package, b"module")).unwrap();
        assert_eq!(manifest.verdict, expected, "{violation:?}");
        assert!(
            manifest.tests[0].detail.is_some(),
            "a learner needs to know which limit"
        );
    }
}

#[test]
fn an_unqualified_backend_never_receives_the_module() {
    let package = package(vec![case("public-1", Visibility::Public, "1\n")], true);
    let backend = ScriptedBackend::unqualified();

    let error = grade(&backend, request(&package, b"module")).unwrap_err();
    assert_eq!(error.verdict(), Verdict::JudgeError);
    assert_eq!(
        backend.calls(),
        0,
        "the module must not reach an unqualified backend"
    );
}

#[test]
fn a_malformed_package_is_rejected_before_anything_executes() {
    let mut package = package(vec![case("public-1", Visibility::Public, "1\n")], true);
    package.format_version = 99;
    let backend = ScriptedBackend::new(vec![ok("1\n")]);

    let error = grade(&backend, request(&package, b"module")).unwrap_err();
    assert_eq!(error.verdict(), Verdict::JudgeError);
    assert_eq!(backend.calls(), 0);
}

#[test]
fn hidden_case_reasons_must_be_redacted_before_publication() {
    let package = package(
        vec![
            case("public-1", Visibility::Public, "1\n"),
            case("hidden-secret", Visibility::Hidden, "9973\n"),
        ],
        false,
    );
    let backend = ScriptedBackend::new(vec![ok("1\n"), ok("9971\n")]);

    let manifest = grade(&backend, request(&package, b"module")).unwrap();
    assert_eq!(manifest.verdict, Verdict::WrongAnswer);
    assert!(
        !is_safe_for_submitter(&manifest),
        "the raw manifest carries the hidden answer and must not be published"
    );

    let redacted = manifest.redacted_for_submitter();
    assert!(is_safe_for_submitter(&redacted));
    let json = serde_json::to_string(&redacted).unwrap();
    assert!(!json.contains("9973"), "expected answer leaked: {json}");
    assert!(
        !json.contains("9971"),
        "submitted answer leaked from a hidden case: {json}"
    );
    assert!(!json.contains("hidden-secret"));
}

#[test]
fn compile_errors_preserve_raw_diagnostics_verbatim() {
    let package = package(vec![case("public-1", Visibility::Public, "1\n")], true);
    let raw = "error[E0382]: borrow of moved value: `s`\n --> src/main.rs:4:20\n";

    let manifest = rustly_grader::compile_error("job-1", &package, raw.to_owned(), 420);
    assert_eq!(manifest.verdict, Verdict::CompileError);
    assert_eq!(
        manifest.compiler_diagnostics.as_deref(),
        Some(raw),
        "rustc output must survive byte for byte; explaining it is the UI's job"
    );
    assert!(manifest.tests.is_empty());
}

#[test]
fn a_judge_error_becomes_a_manifest_with_the_errors_own_verdict() {
    let package = package(vec![case("public-1", Visibility::Public, "1\n")], true);
    let error = JudgeError::Infrastructure("queue unreachable".into());
    let manifest = rustly_grader::manifest_for_error("job-1", &package, &error);

    assert_eq!(manifest.verdict, Verdict::InternalError);
    assert_ne!(manifest.verdict, Verdict::CompileError);
    assert_eq!(manifest.trial_version, package.version);
}

// ---------------------------------------------------------------------------
// End-to-end through the real Wasmtime backend.
// ---------------------------------------------------------------------------

/// A WASI module that prints `text` and exits.
fn printing_module(text: &str) -> Vec<u8> {
    let escaped: String = text
        .bytes()
        .map(|b| match b {
            b'\n' => "\\n".to_owned(),
            0x20..=0x7e => (b as char).to_string(),
            other => format!("\\{other:02x}"),
        })
        .collect();

    wat::parse_str(format!(
        r#"(module
  (import "wasi_snapshot_preview1" "fd_write"
    (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 1024) "{escaped}")
  (func (export "_start")
    (i32.store (i32.const 8) (i32.const 1024))
    (i32.store (i32.const 12) (i32.const {len}))
    (drop (call $fd_write (i32.const 1) (i32.const 8) (i32.const 1) (i32.const 20)))))"#,
        len = text.len()
    ))
    .expect("test module must assemble")
}

#[test]
fn end_to_end_accepted_through_the_real_sandbox() {
    let backend = WasmtimeBackend::new().unwrap();
    let package = package(vec![case("public-1", Visibility::Public, "42\n")], true);
    let module = printing_module("42\n");

    let manifest = grade(&backend, request(&package, &module)).unwrap();
    assert_eq!(manifest.verdict, Verdict::Accepted);
    assert_eq!(manifest.environment_id, "rust-1.88-wasm32-wasip1");
    assert!(manifest.tests[0].fuel_consumed.unwrap() > 0);
    assert!(manifest.hash().starts_with("b3:"));
}

#[test]
fn end_to_end_wrong_answer_through_the_real_sandbox() {
    let backend = WasmtimeBackend::new().unwrap();
    let package = package(vec![case("public-1", Visibility::Public, "42\n")], true);
    let module = printing_module("41\n");

    let manifest = grade(&backend, request(&package, &module)).unwrap();
    assert_eq!(manifest.verdict, Verdict::WrongAnswer);
    let detail = manifest.tests[0].detail.as_deref().unwrap();
    assert!(detail.contains("line 1"), "{detail}");
}

#[test]
fn end_to_end_time_limit_through_the_real_sandbox() {
    let backend = WasmtimeBackend::new().unwrap();
    let mut package = package(vec![case("public-1", Visibility::Public, "x\n")], true);
    package.limits = Limits {
        fuel: 100_000,
        ..Limits::default()
    };

    let module = wat::parse_str(
        r#"(module (memory (export "memory") 1) (func (export "_start") (loop $l (br $l))))"#,
    )
    .unwrap();

    let manifest = grade(&backend, request(&package, &module)).unwrap();
    assert_eq!(manifest.verdict, Verdict::TimeLimitExceeded);
}
