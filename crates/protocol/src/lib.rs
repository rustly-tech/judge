//! Judge wire contracts.
//!
//! Three independently meaningful shapes live here, all carrying
//! [`PROTOCOL_VERSION`]:
//!
//! * [`JobSpec`] - what a worker is asked to do. Identifiers and limits only.
//! * [`ResultManifest`] - the full per-test record, stored in the data plane.
//! * [`ResultSummary`] - the small thing reported to the control plane: a
//!   verdict, timings, and the **hash** of the manifest.
//!
//! The split is the point. Diagnostics can be large and are a user's own data;
//! they belong in content-addressed storage. The control plane records a verdict
//! and a hash, so a result can be audited later without the API ever having
//! carried it.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use rustly_judge_common::{Limits, Verdict};
use rustly_problem_format::Visibility;
use serde::{Deserialize, Serialize};

/// Version of the job, result, and worker protocols.
pub const PROTOCOL_VERSION: u32 = 1;

/// How much a worker is trusted. Mirrors the control plane's classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustClass {
    /// Anonymous donated capacity.
    Volunteer,
    /// Known community operator.
    Community,
    /// Operator-run infrastructure.
    Trusted,
}

impl TrustClass {
    /// Whether this class may receive hidden test material.
    pub const fn may_receive_hidden_tests(self) -> bool {
        matches!(self, Self::Trusted)
    }

    /// Whether artifacts from this class must be quarantined until reproduced.
    pub const fn requires_artifact_quarantine(self) -> bool {
        !matches!(self, Self::Trusted)
    }
}

/// Execution backend selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Backend {
    /// Wasmtime. The only backend qualified for untrusted submissions.
    Wasmtime,
    /// Native isolation. EXPERIMENTAL and qualification-gated.
    Native,
}

/// A unit of judging work.
///
/// Carries no source and no test data: only content identifiers the worker
/// resolves through the data plane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobSpec {
    /// Protocol version of this payload.
    pub protocol_version: u32,
    /// Immutable job identifier.
    pub job_id: String,
    /// CID of the submitted source.
    pub source_cid: String,
    /// CID of the Trial package.
    pub trial_package_cid: String,
    /// Trial content version, for verdict traceability.
    pub trial_version: u32,
    /// Environment identifier the package requires.
    pub environment_id: String,
    /// Bounds to enforce.
    pub limits: Limits,
    /// Backend to use.
    pub backend: Backend,
    /// Whether the referenced package includes hidden tests.
    ///
    /// Only ever `true` for a [`TrustClass::Trusted`] worker.
    pub includes_hidden_tests: bool,
}

impl JobSpec {
    /// Reject a job that violates a protocol invariant.
    ///
    /// The hidden-test rule is checked here as well as at the broker. It is
    /// cheap, and a worker that would leak hidden tests should refuse the job
    /// even if the broker made a mistake.
    pub fn validate(&self, worker_trust: TrustClass) -> Result<(), String> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(format!(
                "job speaks protocol v{}, this worker speaks v{PROTOCOL_VERSION}",
                self.protocol_version
            ));
        }
        if self.includes_hidden_tests && !worker_trust.may_receive_hidden_tests() {
            return Err(format!(
                "refusing a job with hidden tests as a {worker_trust:?} worker"
            ));
        }
        if self.backend == Backend::Native {
            return Err(
                "the native backend is EXPERIMENTAL and not qualified for submissions".into(),
            );
        }
        self.limits
            .validate()
            .map_err(|why| format!("invalid limits: {why}"))?;
        Ok(())
    }
}

/// The outcome of one test case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestOutcome {
    /// Test identifier from the package.
    pub test_id: String,
    /// Whether the case was public or hidden.
    pub visibility: Visibility,
    /// Verdict for this case.
    pub verdict: Verdict,
    /// Wall-clock duration, milliseconds.
    pub wall_ms: u64,
    /// Work units consumed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fuel_consumed: Option<u64>,
    /// Peak memory, bytes.
    pub peak_memory_bytes: u64,
    /// Submitter-safe explanation of a failure.
    ///
    /// For a hidden case this must never quote the input or the expected
    /// output; [`ResultManifest::redacted_for_submitter`] enforces that.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// The full record of a judged submission.
///
/// Stored in the data plane and addressed by [`ResultManifest::hash`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResultManifest {
    /// Protocol version of this payload.
    pub protocol_version: u32,
    /// Job this manifest describes.
    pub job_id: String,
    /// Immutable Trial package judged for this result.
    pub trial_package_cid: String,
    /// Trial content version judged against.
    pub trial_version: u32,
    /// Environment used.
    pub environment_id: String,
    /// Final verdict.
    pub verdict: Verdict,
    /// Per-test outcomes.
    pub tests: Vec<TestOutcome>,
    /// Compiler diagnostics, verbatim.
    ///
    /// Raw `rustc` output is preserved exactly. Explaining a diagnostic is a
    /// job for the UI; replacing it is never acceptable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compiler_diagnostics: Option<String>,
    /// Compilation time, milliseconds.
    pub compile_ms: u64,
    /// Total execution time across cases, milliseconds.
    pub execution_ms: u64,
    /// Whether a cached compilation artifact was reused. Metrics only.
    pub used_cached_artifact: bool,
}

impl ResultManifest {
    /// Canonical hash of this manifest.
    ///
    /// Computed over the canonical JSON encoding, so the control plane can
    /// record a value that later proves which manifest produced a verdict.
    pub fn hash(&self) -> String {
        let canonical = serde_json::to_vec(self).expect("a manifest is always serialisable");
        format!("b3:{}", blake3::hash(&canonical).to_hex())
    }

    /// A copy safe to show the submitter.
    ///
    /// Hidden-case details are stripped: a failure message is allowed to say
    /// *that* a hidden case failed, never *why*, because "expected 42, got 41"
    /// leaks the answer.
    pub fn redacted_for_submitter(&self) -> ResultManifest {
        let mut manifest = self.clone();
        for test in &mut manifest.tests {
            if test.visibility == Visibility::Hidden {
                test.test_id = "hidden".into();
                test.detail = None;
            }
        }
        manifest
    }

    /// A small summary for the control plane.
    pub fn summary(&self, worker_id: impl Into<String>) -> ResultSummary {
        ResultSummary {
            protocol_version: PROTOCOL_VERSION,
            worker_id: worker_id.into(),
            trial_package_cid: self.trial_package_cid.clone(),
            verdict: self.verdict,
            result_manifest_hash: self.hash(),
            peak_memory_bytes: self
                .tests
                .iter()
                .map(|t| t.peak_memory_bytes)
                .max()
                .unwrap_or(0),
            execution_ms: self.execution_ms,
            compile_ms: self.compile_ms,
            used_cached_artifact: self.used_cached_artifact,
        }
    }
}

/// What the worker reports to the control plane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResultSummary {
    /// Protocol version of this payload.
    pub protocol_version: u32,
    /// Reporting worker.
    pub worker_id: String,
    /// Immutable Trial package that produced this result.
    pub trial_package_cid: String,
    /// Final verdict.
    pub verdict: Verdict,
    /// Hash of the full manifest in the data plane.
    pub result_manifest_hash: String,
    /// Peak memory across cases, bytes.
    pub peak_memory_bytes: u64,
    /// Total execution time, milliseconds.
    pub execution_ms: u64,
    /// Compilation time, milliseconds.
    pub compile_ms: u64,
    /// Whether a cached artifact was reused. Metrics only; never affects the verdict.
    pub used_cached_artifact: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn job() -> JobSpec {
        JobSpec {
            protocol_version: PROTOCOL_VERSION,
            job_id: "job-1".into(),
            source_cid: "b3:aa".into(),
            trial_package_cid: "b3:bb".into(),
            trial_version: 1,
            environment_id: "rust-1.88-wasm32-wasip1".into(),
            limits: Limits::default(),
            backend: Backend::Wasmtime,
            includes_hidden_tests: false,
        }
    }

    fn manifest() -> ResultManifest {
        ResultManifest {
            protocol_version: PROTOCOL_VERSION,
            job_id: "job-1".into(),
            trial_package_cid: "b3:bb".into(),
            trial_version: 1,
            environment_id: "rust-1.88-wasm32-wasip1".into(),
            verdict: Verdict::WrongAnswer,
            tests: vec![
                TestOutcome {
                    test_id: "public-1".into(),
                    visibility: Visibility::Public,
                    verdict: Verdict::Accepted,
                    wall_ms: 3,
                    fuel_consumed: Some(1234),
                    peak_memory_bytes: 65_536,
                    detail: None,
                },
                TestOutcome {
                    test_id: "hidden-secret-case".into(),
                    visibility: Visibility::Hidden,
                    verdict: Verdict::WrongAnswer,
                    wall_ms: 4,
                    fuel_consumed: Some(2345),
                    peak_memory_bytes: 131_072,
                    detail: Some("line 1: expected \"9973\", got \"9971\"".into()),
                },
            ],
            compiler_diagnostics: None,
            compile_ms: 900,
            execution_ms: 7,
            used_cached_artifact: false,
        }
    }

    #[test]
    fn a_job_carries_identifiers_not_payloads() {
        let json = serde_json::to_string(&job()).unwrap();
        assert!(json.contains("b3:aa"));
        assert!(!json.contains("fn main"));
        assert!(!json.contains("expected_stdout"));
    }

    #[test]
    fn a_worker_refuses_hidden_tests_it_is_not_entitled_to() {
        let mut spec = job();
        spec.includes_hidden_tests = true;

        assert!(spec.validate(TrustClass::Trusted).is_ok());
        for class in [TrustClass::Volunteer, TrustClass::Community] {
            let error = spec.validate(class).unwrap_err();
            assert!(error.contains("refusing"), "{error}");
        }
    }

    #[test]
    fn a_worker_refuses_the_unqualified_native_backend() {
        let mut spec = job();
        spec.backend = Backend::Native;
        let error = spec.validate(TrustClass::Trusted).unwrap_err();
        assert!(error.contains("not qualified"), "{error}");
    }

    #[test]
    fn a_worker_refuses_a_job_from_a_different_protocol_version() {
        let mut spec = job();
        spec.protocol_version = 99;
        assert!(spec.validate(TrustClass::Trusted).is_err());
    }

    #[test]
    fn a_worker_refuses_a_job_with_an_unbounded_limit() {
        let mut spec = job();
        spec.limits.wall_ms = 0;
        assert!(spec.validate(TrustClass::Trusted).is_err());
    }

    #[test]
    fn redaction_removes_hidden_case_identity_and_reasons() {
        let redacted = manifest().redacted_for_submitter();
        let json = serde_json::to_string(&redacted).unwrap();

        assert!(!json.contains("9973"), "expected value leaked: {json}");
        assert!(!json.contains("9971"), "actual value leaked: {json}");
        assert!(
            !json.contains("hidden-secret-case"),
            "test id leaked: {json}"
        );

        // The submitter still learns that a hidden case failed, and the public
        // case's own detail survives.
        assert_eq!(redacted.tests[1].verdict, Verdict::WrongAnswer);
        assert_eq!(redacted.verdict, Verdict::WrongAnswer);
        assert_eq!(redacted.tests[0].test_id, "public-1");
    }

    #[test]
    fn redaction_keeps_public_case_details() {
        let mut m = manifest();
        m.tests[0].verdict = Verdict::WrongAnswer;
        m.tests[0].detail = Some("line 1: expected \"3\", got \"4\"".into());
        let redacted = m.redacted_for_submitter();
        assert_eq!(
            redacted.tests[0].detail.as_deref(),
            Some("line 1: expected \"3\", got \"4\"")
        );
    }

    #[test]
    fn the_manifest_hash_is_stable_and_content_sensitive() {
        let m = manifest();
        assert_eq!(m.hash(), m.clone().hash());
        assert!(m.hash().starts_with("b3:"));

        let mut changed = m.clone();
        changed.verdict = Verdict::Accepted;
        assert_ne!(m.hash(), changed.hash());
    }

    #[test]
    fn the_summary_reports_a_hash_not_the_manifest() {
        let m = manifest();
        let summary = m.summary("worker-1");
        assert_eq!(summary.result_manifest_hash, m.hash());
        assert_eq!(summary.verdict, m.verdict);
        assert_eq!(summary.peak_memory_bytes, 131_072);

        let json = serde_json::to_string(&summary).unwrap();
        assert!(
            !json.contains("9973"),
            "the summary must not carry diagnostics: {json}"
        );
        assert!(!json.contains("public-1"));
    }

    #[test]
    fn cache_reuse_never_changes_the_reported_verdict() {
        let mut cold = manifest();
        cold.used_cached_artifact = false;
        let mut warm = manifest();
        warm.used_cached_artifact = true;

        assert_eq!(cold.verdict, warm.verdict);
        assert_ne!(
            cold.hash(),
            warm.hash(),
            "the manifest still records which path ran"
        );
    }

    #[test]
    fn trust_classes_agree_with_the_control_plane() {
        assert!(TrustClass::Trusted.may_receive_hidden_tests());
        assert!(!TrustClass::Community.may_receive_hidden_tests());
        assert!(!TrustClass::Volunteer.may_receive_hidden_tests());
        assert!(TrustClass::Volunteer.requires_artifact_quarantine());
        assert!(!TrustClass::Trusted.requires_artifact_quarantine());
    }
}
