//! End-to-end judging, offline.
//!
//! Real artifact source, real Wasmtime sandbox, real grader, real cache. The
//! only substitution is the compile step, which uses `PrecompiledModule` so the
//! test needs no Rust toolchain in the sandbox and no network. CI runs the same
//! pipeline with a genuinely `cargo`-compiled `wasm32-wasip1` binary.

use rustly_judge_cache::{ArtifactCache, Trust};
use rustly_judge_common::{Limits, Verdict};
use rustly_judge_protocol::{Backend, JobSpec, TrustClass, PROTOCOL_VERSION};
use rustly_judge_worker::compile::PrecompiledModule;
use rustly_judge_worker::pipeline::{artifact_key, JobContext};
use rustly_judge_worker::{run_job, LocalArtifacts};
use rustly_problem_format::{
    Checker, Environment, Mode, Scoring, TestCase, TrialPackage, Visibility, FORMAT_VERSION,
};
use rustly_sandbox::WasmtimeBackend;

/// A module that echoes stdin to stdout, so a test case's expected output is
/// simply its input.
fn echo_module() -> Vec<u8> {
    wat::parse_str(
        r#"(module
  (import "wasi_snapshot_preview1" "fd_read"
    (func $fd_read (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_write"
    (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (func (export "_start")
    (i32.store (i32.const 8) (i32.const 1024))
    (i32.store (i32.const 12) (i32.const 512))
    (drop (call $fd_read (i32.const 0) (i32.const 8) (i32.const 1) (i32.const 20)))
    (i32.store (i32.const 12) (i32.load (i32.const 20)))
    (drop (call $fd_write (i32.const 1) (i32.const 8) (i32.const 1) (i32.const 24)))))"#,
    )
    .expect("test module must assemble")
}

/// A module that always prints a fixed string, whatever the input.
fn constant_module(text: &str) -> Vec<u8> {
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
    .unwrap()
}

fn package(tests: Vec<TestCase>) -> TrialPackage {
    TrialPackage {
        format_version: FORMAT_VERSION,
        slug: "echo".into(),
        version: 2,
        mode: Mode::Batch,
        environment: Environment::default(),
        limits: Limits::default(),
        checker: Checker::TrimmedLines,
        scoring: Scoring::AllOrNothing,
        fail_fast: true,
        groups: vec![],
        tests,
    }
}

fn case(id: &str, visibility: Visibility, stdin: &str, expected: &str) -> TestCase {
    TestCase {
        id: id.into(),
        visibility,
        stdin: stdin.into(),
        expected_stdout: expected.into(),
        args: vec![],
        group: None,
        limits: None,
    }
}

struct Fixture {
    _dir: tempfile::TempDir,
    artifacts: LocalArtifacts,
    sandbox: WasmtimeBackend,
    package_cid: String,
    source_cid: String,
    environment_id: String,
    trial_version: u32,
}

fn fixture(package: &TrialPackage, module: &[u8]) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let artifacts = LocalArtifacts::new(dir.path());
    let package_cid = artifacts
        .put(&serde_json::to_vec(package).unwrap())
        .unwrap();
    let source_cid = artifacts.put(module).unwrap();
    Fixture {
        _dir: dir,
        artifacts,
        sandbox: WasmtimeBackend::new().unwrap(),
        package_cid,
        source_cid,
        environment_id: package.environment.id.clone(),
        trial_version: package.version,
    }
}

impl Fixture {
    fn spec(&self, hidden: bool) -> JobSpec {
        JobSpec {
            protocol_version: PROTOCOL_VERSION,
            job_id: "job-1".into(),
            source_cid: self.source_cid.clone(),
            trial_package_cid: self.package_cid.clone(),
            trial_version: self.trial_version,
            environment_id: self.environment_id.clone(),
            limits: Limits::default(),
            backend: Backend::Wasmtime,
            includes_hidden_tests: hidden,
        }
    }

    fn context<'a>(
        &'a self,
        trust: TrustClass,
        cache: Option<&'a ArtifactCache>,
    ) -> JobContext<'a> {
        JobContext {
            artifacts: &self.artifacts,
            compiler: &PrecompiledModule,
            sandbox: &self.sandbox,
            cache,
            trust_class: trust,
            worker_id: "worker-test",
        }
    }
}

#[test]
fn a_correct_submission_is_accepted_end_to_end() {
    let package = package(vec![
        case("public-1", Visibility::Public, "hello\n", "hello\n"),
        case("hidden-1", Visibility::Hidden, "secret\n", "secret\n"),
    ]);
    let f = fixture(&package, &echo_module());

    let report = run_job(&f.context(TrustClass::Trusted, None), &f.spec(true)).unwrap();
    assert_eq!(report.verdict(), Verdict::Accepted);
    assert_eq!(report.manifest.tests.len(), 2);
    assert_eq!(report.manifest.trial_version, 2);
    assert_eq!(report.manifest.environment_id, "rust-1.88-wasm32-wasip1");
    assert!(report.manifest.hash().starts_with("b3:"));
}

#[test]
fn a_wrong_submission_is_rejected_with_actionable_public_detail() {
    let package = package(vec![case(
        "public-1",
        Visibility::Public,
        "hello\n",
        "hello\n",
    )]);
    let f = fixture(&package, &constant_module("goodbye\n"));

    let report = run_job(&f.context(TrustClass::Trusted, None), &f.spec(false)).unwrap();
    assert_eq!(report.verdict(), Verdict::WrongAnswer);
    let detail = report.redacted.tests[0].detail.as_deref().unwrap();
    assert!(
        detail.contains("hello"),
        "a public case may show the expected value: {detail}"
    );
}

#[test]
fn a_volunteer_worker_never_holds_hidden_test_data() {
    let package = package(vec![
        case("public-1", Visibility::Public, "hello\n", "hello\n"),
        case("hidden-secret", Visibility::Hidden, "9973\n", "9973\n"),
    ]);
    let f = fixture(&package, &echo_module());

    // The broker would never set this, but even if it did, the worker refuses.
    let mut spec = f.spec(true);
    spec.includes_hidden_tests = true;
    let error = run_job(&f.context(TrustClass::Volunteer, None), &spec).unwrap_err();
    assert_eq!(error.verdict(), Verdict::SecurityEvent);

    // With the correct flag, the volunteer judges only the public case.
    let report = run_job(&f.context(TrustClass::Volunteer, None), &f.spec(false)).unwrap();
    assert_eq!(report.manifest.tests.len(), 1);
    assert_eq!(report.manifest.tests[0].test_id, "public-1");

    let json = serde_json::to_string(&report.manifest).unwrap();
    assert!(
        !json.contains("9973"),
        "hidden data reached a volunteer manifest: {json}"
    );
    assert!(!json.contains("hidden-secret"));
}

#[test]
fn the_published_manifest_never_reveals_why_a_hidden_case_failed() {
    let package = package(vec![
        case("public-1", Visibility::Public, "hello\n", "hello\n"),
        case(
            "hidden-secret",
            Visibility::Hidden,
            "9973\n",
            "expected-9973\n",
        ),
    ]);
    let f = fixture(&package, &echo_module());

    let report = run_job(&f.context(TrustClass::Trusted, None), &f.spec(true)).unwrap();
    assert_eq!(report.verdict(), Verdict::WrongAnswer);

    let published = serde_json::to_string(&report.redacted).unwrap();
    assert!(
        !published.contains("expected-9973"),
        "the answer leaked: {published}"
    );
    assert!(
        !published.contains("hidden-secret"),
        "the case id leaked: {published}"
    );
    // The submitter still learns that a hidden case failed.
    assert_eq!(report.redacted.tests[1].verdict, Verdict::WrongAnswer);
}

#[test]
fn source_that_is_not_a_module_is_a_compile_error_with_raw_diagnostics() {
    let package = package(vec![case("public-1", Visibility::Public, "hi\n", "hi\n")]);
    let f = fixture(&package, b"fn main() { let s = String::new(); }");

    let report = run_job(&f.context(TrustClass::Trusted, None), &f.spec(false)).unwrap();
    assert_eq!(report.verdict(), Verdict::CompileError);
    assert!(report.manifest.compiler_diagnostics.is_some());
    assert!(report.manifest.tests.is_empty());
}

#[test]
fn a_missing_artifact_is_retryable_infrastructure_not_a_user_verdict() {
    let package = package(vec![case("public-1", Visibility::Public, "hi\n", "hi\n")]);
    let f = fixture(&package, &echo_module());

    let mut spec = f.spec(false);
    spec.source_cid = rustly_judge_cache::cid(b"never stored");

    let error = run_job(&f.context(TrustClass::Trusted, None), &spec).unwrap_err();
    assert_eq!(error.verdict(), Verdict::InternalError);
    assert!(error.is_retryable());
}

#[test]
fn a_tampered_artifact_is_refused_rather_than_judged() {
    let package = package(vec![case("public-1", Visibility::Public, "hi\n", "hi\n")]);
    let f = fixture(&package, &echo_module());

    std::fs::write(f.artifacts.root().join(&f.source_cid), b"\0asmTAMPERED").unwrap();
    let error = run_job(&f.context(TrustClass::Trusted, None), &f.spec(false)).unwrap_err();
    assert_eq!(error.verdict(), Verdict::InternalError);
}

#[test]
fn a_job_asking_for_the_wrong_environment_is_refused() {
    let package = package(vec![case("public-1", Visibility::Public, "hi\n", "hi\n")]);
    let f = fixture(&package, &echo_module());

    let mut spec = f.spec(false);
    spec.environment_id = "rust-1.60-wasm32-unknown".into();

    let error = run_job(&f.context(TrustClass::Trusted, None), &spec).unwrap_err();
    assert_eq!(
        error.verdict(),
        Verdict::JudgeError,
        "a verdict is only meaningful against the environment the package declares"
    );
}

#[test]
fn a_job_selecting_the_unqualified_native_backend_is_refused() {
    let package = package(vec![case("public-1", Visibility::Public, "hi\n", "hi\n")]);
    let f = fixture(&package, &echo_module());

    let mut spec = f.spec(false);
    spec.backend = Backend::Native;

    let error = run_job(&f.context(TrustClass::Trusted, None), &spec).unwrap_err();
    assert_eq!(error.verdict(), Verdict::SecurityEvent);
}

#[test]
fn the_artifact_cache_accelerates_without_changing_the_verdict() {
    let package = package(vec![case(
        "public-1",
        Visibility::Public,
        "hello\n",
        "hello\n",
    )]);
    let f = fixture(&package, &echo_module());

    let dir = tempfile::tempdir().unwrap();
    let cache = ArtifactCache::open(dir.path()).unwrap();
    let spec = f.spec(false);

    let cold = run_job(&f.context(TrustClass::Trusted, Some(&cache)), &spec).unwrap();
    assert_eq!(cold.verdict(), Verdict::Accepted);
    assert!(!cold.manifest.used_cached_artifact);

    let warm = run_job(&f.context(TrustClass::Trusted, Some(&cache)), &spec).unwrap();
    assert_eq!(
        warm.verdict(),
        Verdict::Accepted,
        "a cache hit must not change the verdict"
    );
    assert!(warm.manifest.used_cached_artifact);
}

#[test]
fn a_corrupt_cache_entry_causes_a_clean_rebuild_not_a_wrong_verdict() {
    let package = package(vec![case(
        "public-1",
        Visibility::Public,
        "hello\n",
        "hello\n",
    )]);
    let f = fixture(&package, &echo_module());

    let dir = tempfile::tempdir().unwrap();
    let cache = ArtifactCache::open(dir.path()).unwrap();
    let spec = f.spec(false);

    run_job(&f.context(TrustClass::Trusted, Some(&cache)), &spec).unwrap();

    // Corrupt the cached artifact exactly as a bad disk would.
    let key = artifact_key(&spec.source_cid, &spec.environment_id, "precompiled");
    let stored = rustly_judge_cache::cid(&echo_module());
    std::fs::write(cache.path_of(&stored, Trust::Verified), b"\0asmCORRUPT").unwrap();
    let _ = key;

    let report = run_job(&f.context(TrustClass::Trusted, Some(&cache)), &spec).unwrap();
    assert_eq!(
        report.verdict(),
        Verdict::Accepted,
        "cache corruption must cause a clean rebuild, never a wrong verdict"
    );
    assert!(!report.manifest.used_cached_artifact);
}

#[test]
fn a_volunteer_workers_artifacts_are_quarantined_not_served_to_judging() {
    let package = package(vec![case(
        "public-1",
        Visibility::Public,
        "hello\n",
        "hello\n",
    )]);
    let f = fixture(&package, &echo_module());

    let dir = tempfile::tempdir().unwrap();
    let cache = ArtifactCache::open(dir.path()).unwrap();
    let spec = f.spec(false);

    run_job(&f.context(TrustClass::Volunteer, Some(&cache)), &spec).unwrap();

    let key = artifact_key(&spec.source_cid, &spec.environment_id, "precompiled");
    assert!(
        !cache.contains_build(&key),
        "a volunteer's build must not be usable for judging until it is reproduced"
    );
    assert!(
        cache.get_build(&key, Trust::Quarantined).unwrap().is_some(),
        "it is still kept, for diagnostics and later verification"
    );

    // The next run rebuilds rather than trusting the quarantined artifact.
    let report = run_job(&f.context(TrustClass::Volunteer, Some(&cache)), &spec).unwrap();
    assert!(!report.manifest.used_cached_artifact);
}

#[test]
fn a_malformed_package_is_a_judge_error_and_never_blames_the_submitter() {
    let dir = tempfile::tempdir().unwrap();
    let artifacts = LocalArtifacts::new(dir.path());
    let package_cid = artifacts.put(b"{ not json").unwrap();
    let source_cid = artifacts.put(&echo_module()).unwrap();
    let sandbox = WasmtimeBackend::new().unwrap();

    let spec = JobSpec {
        protocol_version: PROTOCOL_VERSION,
        job_id: "job-1".into(),
        source_cid,
        trial_package_cid: package_cid,
        trial_version: 1,
        environment_id: "rust-1.88-wasm32-wasip1".into(),
        limits: Limits::default(),
        backend: Backend::Wasmtime,
        includes_hidden_tests: false,
    };
    let context = JobContext {
        artifacts: &artifacts,
        compiler: &PrecompiledModule,
        sandbox: &sandbox,
        cache: None,
        trust_class: TrustClass::Trusted,
        worker_id: "w",
    };

    let error = run_job(&context, &spec).unwrap_err();
    assert_eq!(error.verdict(), Verdict::JudgeError);
    assert_ne!(error.verdict(), Verdict::CompileError);
}

#[test]
fn a_program_that_exceeds_the_time_limit_gets_tle_not_a_hung_worker() {
    let mut package = package(vec![case("public-1", Visibility::Public, "", "x\n")]);
    package.limits = Limits {
        fuel: 200_000,
        wall_ms: 2_000,
        ..Limits::default()
    };

    let spinner = wat::parse_str(
        r#"(module (memory (export "memory") 1) (func (export "_start") (loop $l (br $l))))"#,
    )
    .unwrap();
    let f = fixture(&package, &spinner);

    let started = std::time::Instant::now();
    let report = run_job(&f.context(TrustClass::Trusted, None), &f.spec(false)).unwrap();
    assert_eq!(report.verdict(), Verdict::TimeLimitExceeded);
    assert!(
        started.elapsed().as_secs() < 20,
        "the worker must not hang on a runaway program"
    );
}
