//! Grading: turn a compiled module and a Trial package into a verdict.
//!
//! # Compile once, run many
//!
//! Compilation is by far the most expensive step, and it does not depend on the
//! test case. The grader takes an **already compiled** module and runs every
//! case against it. Compilation itself is the worker's job, because it is a
//! separate security domain: `build.rs` and procedural macros mean compiling
//! untrusted Rust is running untrusted code.
//!
//! # Rules encoded here
//!
//! * A system fault on **any** case makes the whole submission a system fault.
//!   Reporting `WA` because one case could not be executed would be a lie.
//! * `fail_fast` stops early, but only on a *user* fault. A system fault always
//!   stops immediately, because continuing would produce a misleading result.
//! * Public cases run before hidden ones, so a failing submission gets the most
//!   actionable feedback first.
//! * A backend that is not qualified for untrusted code never sees user code.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use rustly_checker::{check, Match};
use rustly_judge_common::{JudgeError, Result, Verdict, VerdictClass};
use rustly_judge_protocol::{ResultManifest, TestOutcome, PROTOCOL_VERSION};
use rustly_problem_format::{TrialPackage, Visibility};
use rustly_sandbox::{ensure_qualified, ExecutionBackend, ExecutionRequest};

/// What the grader was given.
#[derive(Debug, Clone)]
pub struct GradeRequest<'a> {
    /// Job identifier, recorded in the manifest.
    pub job_id: &'a str,
    /// Immutable Trial package identifier, recorded in the manifest.
    pub trial_package_cid: &'a str,
    /// The compiled module.
    pub module: &'a [u8],
    /// The Trial package. Hidden cases must already have been removed if this
    /// worker is not entitled to them.
    pub package: &'a TrialPackage,
    /// Raw compiler diagnostics, preserved verbatim.
    pub compiler_diagnostics: Option<String>,
    /// Compilation time, milliseconds.
    pub compile_ms: u64,
    /// Whether a cached artifact was reused. Metrics only.
    pub used_cached_artifact: bool,
}

/// Grade a compiled submission.
///
/// Returns a full [`ResultManifest`]. A `JudgeError` is returned only when the
/// judge itself could not proceed; a misbehaving submission is a manifest with
/// a user-fault verdict.
pub fn grade(backend: &dyn ExecutionBackend, request: GradeRequest<'_>) -> Result<ResultManifest> {
    // Refuse before the module is ever handed to an unqualified backend.
    ensure_qualified(backend)?;
    request.package.validate()?;

    let mut outcomes: Vec<TestOutcome> = Vec::with_capacity(request.package.tests.len());
    let mut verdict = Verdict::Accepted;
    let mut execution_ms = 0_u64;

    for test in request.package.ordered_tests() {
        let limits = request.package.limits_for(test);
        let outcome = backend.execute(ExecutionRequest {
            module: request.module,
            stdin: test.stdin.as_bytes(),
            args: &test.args,
            limits,
        })?;

        execution_ms = execution_ms.saturating_add(outcome.wall_ms);

        let (case_verdict, detail) = match outcome.termination_verdict() {
            Some(v) => (v, describe(&outcome)),
            None => match check(
                &request.package.checker,
                &test.expected_stdout,
                &outcome.stdout_lossy(),
            )? {
                Match::Accepted => (Verdict::Accepted, None),
                Match::Rejected { detail } => (Verdict::WrongAnswer, Some(detail)),
            },
        };

        outcomes.push(TestOutcome {
            test_id: test.id.clone(),
            visibility: test.visibility,
            verdict: case_verdict,
            wall_ms: outcome.wall_ms,
            fuel_consumed: outcome.fuel_consumed,
            peak_memory_bytes: outcome.peak_memory_bytes,
            detail,
        });

        verdict = verdict.worst(case_verdict);

        if case_verdict.class() == VerdictClass::SystemFault {
            // Never keep going: the remaining results would be meaningless and
            // the aggregate would look like a user failure.
            tracing::warn!(
                job_id = request.job_id,
                test_id = %test.id,
                verdict = case_verdict.code(),
                "stopping: a system fault makes the rest of the run meaningless"
            );
            break;
        }
        if request.package.fail_fast && case_verdict != Verdict::Accepted {
            break;
        }
    }

    Ok(ResultManifest {
        protocol_version: PROTOCOL_VERSION,
        job_id: request.job_id.to_owned(),
        trial_package_cid: request.trial_package_cid.to_owned(),
        trial_version: request.package.version,
        environment_id: request.package.environment.id.clone(),
        verdict,
        tests: outcomes,
        compiler_diagnostics: request.compiler_diagnostics,
        compile_ms: request.compile_ms,
        execution_ms,
        used_cached_artifact: request.used_cached_artifact,
    })
}

/// Build a manifest for a submission that failed to compile.
///
/// Raw diagnostics are preserved verbatim: explaining a `rustc` error is the
/// UI's job, and replacing it would take away the thing a learner most needs to
/// get used to reading.
pub fn compile_error(
    job_id: &str,
    trial_package_cid: &str,
    package: &TrialPackage,
    diagnostics: String,
    compile_ms: u64,
) -> ResultManifest {
    ResultManifest {
        protocol_version: PROTOCOL_VERSION,
        job_id: job_id.to_owned(),
        trial_package_cid: trial_package_cid.to_owned(),
        trial_version: package.version,
        environment_id: package.environment.id.clone(),
        verdict: Verdict::CompileError,
        tests: vec![],
        compiler_diagnostics: Some(diagnostics),
        compile_ms,
        execution_ms: 0,
        used_cached_artifact: false,
    }
}

/// Turn a non-clean termination into a submitter-safe explanation.
fn describe(outcome: &rustly_sandbox::ExecutionOutcome) -> Option<String> {
    use rustly_sandbox::TerminationReason;
    match &outcome.termination {
        TerminationReason::Exited { code: 0 } => None,
        TerminationReason::Exited { code } => Some(format!("the program exited with code {code}")),
        TerminationReason::Trapped { detail } => Some(format!("the program aborted: {detail}")),
        TerminationReason::LimitExceeded { violation } => Some(match violation {
            rustly_judge_common::LimitViolation::Wall => {
                "the program ran longer than the time limit".into()
            }
            rustly_judge_common::LimitViolation::Fuel => {
                "the program did more work than the limit allows".into()
            }
            rustly_judge_common::LimitViolation::Memory => {
                "the program tried to use more memory than the limit allows".into()
            }
            rustly_judge_common::LimitViolation::Output => {
                "the program printed more than the output limit allows".into()
            }
        }),
    }
}

/// Whether a manifest may be published to the submitter as-is.
///
/// Belt and braces around [`ResultManifest::redacted_for_submitter`]: this
/// returns `false` for any manifest that still carries a hidden case's identity
/// or reason, so a caller that forgets to redact fails loudly.
pub fn is_safe_for_submitter(manifest: &ResultManifest) -> bool {
    manifest.tests.iter().all(|test| {
        test.visibility != Visibility::Hidden || (test.detail.is_none() && test.test_id == "hidden")
    })
}

/// Convert a judge error into the manifest that should be reported.
///
/// Used when execution could not even begin. The verdict comes from the error's
/// own classification, so an infrastructure failure cannot become a `CE`.
pub fn manifest_for_error(
    job_id: &str,
    trial_package_cid: &str,
    package: &TrialPackage,
    error: &JudgeError,
) -> ResultManifest {
    ResultManifest {
        protocol_version: PROTOCOL_VERSION,
        job_id: job_id.to_owned(),
        trial_package_cid: trial_package_cid.to_owned(),
        trial_version: package.version,
        environment_id: package.environment.id.clone(),
        verdict: error.verdict(),
        tests: vec![],
        compiler_diagnostics: None,
        compile_ms: 0,
        execution_ms: 0,
        used_cached_artifact: false,
    }
}
