//! The job queue.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rustly_judge_protocol::{Backend, JobSpec, ResultSummary, TrustClass, PROTOCOL_VERSION};
use serde::{Deserialize, Serialize};

/// How long a lease is held before the job returns to the queue.
pub const LEASE_SECONDS: u64 = 120;

/// Seconds a worker should wait before re-polling an empty queue.
pub const EMPTY_QUEUE_BACKOFF_SECONDS: u32 = 5;

/// Maximum jobs one lease request may claim.
pub const MAX_LEASE_CAPACITY: u32 = 32;

/// A job waiting to be judged, or being judged.
#[derive(Debug, Clone)]
pub struct QueuedJob {
    /// The job specification, minus the hidden-test decision.
    pub spec: JobSpec,
    /// Whether the referenced package actually contains hidden tests.
    ///
    /// Kept separate from [`JobSpec::includes_hidden_tests`] on purpose: the
    /// spec field is *what this worker is told*, and it is computed per lease
    /// from the leasing worker's trust class. Storing them apart makes it
    /// impossible to accidentally hand a volunteer the queue's own copy.
    pub package_has_hidden_tests: bool,
}

#[derive(Debug)]
struct Lease {
    job: QueuedJob,
    worker_id: String,
    expires_at: Instant,
}

#[derive(Debug, Default)]
struct State {
    waiting: VecDeque<QueuedJob>,
    leased: Vec<Lease>,
    /// Job id paired with the summary that finalised it. Keeping the id here is
    /// what makes a duplicate report distinguishable from an unknown job.
    finished: Vec<(String, ResultSummary)>,
}

/// An in-memory job queue.
#[derive(Debug, Clone, Default)]
pub struct Queue {
    state: Arc<Mutex<State>>,
}

/// Why a result report was rejected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportError {
    /// No such job is leased.
    UnknownJob,
    /// The job is leased by a different worker.
    NotLeaseHolder,
    /// The reporting worker speaks a different protocol version.
    ProtocolMismatch,
}

impl std::fmt::Display for ReportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownJob => f.write_str("no such leased job"),
            Self::NotLeaseHolder => f.write_str("job is leased by another worker"),
            Self::ProtocolMismatch => f.write_str("unsupported protocol version"),
        }
    }
}

impl Queue {
    /// An empty queue.
    pub fn new() -> Self {
        Self::default()
    }

    /// Enqueue a job.
    pub fn submit(&self, job: QueuedJob) {
        self.state
            .lock()
            .expect("queue mutex is never poisoned")
            .waiting
            .push_back(job);
    }

    /// Number of jobs waiting to be leased.
    pub fn depth(&self) -> usize {
        self.state
            .lock()
            .expect("queue mutex is never poisoned")
            .waiting
            .len()
    }

    /// Number of jobs currently leased.
    pub fn in_flight(&self) -> usize {
        self.state
            .lock()
            .expect("queue mutex is never poisoned")
            .leased
            .len()
    }

    /// Results reported so far, in the order they were finalised.
    pub fn results(&self) -> Vec<ResultSummary> {
        self.state
            .lock()
            .expect("queue mutex is never poisoned")
            .finished
            .iter()
            .map(|(_, summary)| summary.clone())
            .collect()
    }

    /// The result recorded for `job_id`, if it has finished.
    pub fn result_for(&self, job_id: &str) -> Option<ResultSummary> {
        self.state
            .lock()
            .expect("queue mutex is never poisoned")
            .finished
            .iter()
            .find(|(id, _)| id == job_id)
            .map(|(_, summary)| summary.clone())
    }

    /// Lease up to `capacity` jobs for `worker_id`.
    ///
    /// The returned [`JobSpec`]s have `includes_hidden_tests` set from
    /// `trust_class`, never from the queue's own record. A non-trusted worker
    /// therefore cannot be told a package has hidden tests, and the worker's own
    /// [`JobSpec::validate`] refuses the job if it somehow is.
    pub fn lease(&self, worker_id: &str, trust_class: TrustClass, capacity: u32) -> Vec<JobSpec> {
        let mut state = self.state.lock().expect("queue mutex is never poisoned");

        // Reclaim expired leases first: a worker that vanished mid-job must not
        // strand the submission.
        let now = Instant::now();
        let expired: Vec<QueuedJob> = state
            .leased
            .iter()
            .filter(|lease| lease.expires_at <= now)
            .map(|lease| lease.job.clone())
            .collect();
        state.leased.retain(|lease| lease.expires_at > now);
        for job in expired {
            tracing::warn!(job_id = %job.spec.job_id, "reclaiming an expired lease");
            state.waiting.push_front(job);
        }

        let take = (capacity.clamp(1, MAX_LEASE_CAPACITY) as usize).min(state.waiting.len());
        let mut leased = Vec::with_capacity(take);
        for _ in 0..take {
            let Some(job) = state.waiting.pop_front() else {
                break;
            };

            let mut spec = job.spec.clone();
            spec.protocol_version = PROTOCOL_VERSION;
            spec.backend = Backend::Wasmtime;
            // The single place this decision is made.
            spec.includes_hidden_tests =
                job.package_has_hidden_tests && trust_class.may_receive_hidden_tests();

            state.leased.push(Lease {
                job,
                worker_id: worker_id.to_owned(),
                expires_at: now + Duration::from_secs(LEASE_SECONDS),
            });
            leased.push(spec);
        }
        leased
    }

    /// Record the result for `job_id`.
    ///
    /// Idempotent: a second report for a job that already finished is a no-op
    /// that succeeds and returns `false`, so a worker retrying after a network
    /// blip cannot produce two verdicts.
    pub fn report_for(&self, job_id: &str, summary: ResultSummary) -> Result<bool, ReportError> {
        if summary.protocol_version != PROTOCOL_VERSION {
            return Err(ReportError::ProtocolMismatch);
        }
        let mut state = self.state.lock().expect("queue mutex is never poisoned");

        let Some(index) = state
            .leased
            .iter()
            .position(|lease| lease.job.spec.job_id == job_id)
        else {
            if state.finished.iter().any(|(id, _)| id == job_id) {
                return Ok(false);
            }
            return Err(ReportError::UnknownJob);
        };

        if state.leased[index].worker_id != summary.worker_id {
            return Err(ReportError::NotLeaseHolder);
        }
        state.leased.remove(index);
        state.finished.push((job_id.to_owned(), summary));
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustly_judge_common::{Limits, Verdict};

    fn job(id: &str, hidden: bool) -> QueuedJob {
        QueuedJob {
            spec: JobSpec {
                protocol_version: PROTOCOL_VERSION,
                job_id: id.into(),
                source_cid: "b3:source".into(),
                trial_package_cid: "b3:package".into(),
                trial_version: 1,
                environment_id: "rust-1.88-wasm32-wasip1".into(),
                limits: Limits::default(),
                backend: Backend::Wasmtime,
                includes_hidden_tests: false,
            },
            package_has_hidden_tests: hidden,
        }
    }

    fn summary(worker: &str) -> ResultSummary {
        ResultSummary {
            protocol_version: PROTOCOL_VERSION,
            worker_id: worker.into(),
            verdict: Verdict::Accepted,
            result_manifest_hash: "b3:manifest".into(),
            peak_memory_bytes: 1024,
            execution_ms: 5,
            compile_ms: 500,
            used_cached_artifact: false,
        }
    }

    #[test]
    fn jobs_are_leased_in_submission_order() {
        let queue = Queue::new();
        for id in ["a", "b", "c"] {
            queue.submit(job(id, false));
        }
        assert_eq!(queue.depth(), 3);

        let leased = queue.lease("w1", TrustClass::Trusted, 2);
        assert_eq!(
            leased.iter().map(|j| j.job_id.as_str()).collect::<Vec<_>>(),
            ["a", "b"]
        );
        assert_eq!(queue.depth(), 1);
        assert_eq!(queue.in_flight(), 2);
    }

    #[test]
    fn hidden_tests_are_offered_only_to_a_trusted_worker() {
        for (class, expected) in [
            (TrustClass::Volunteer, false),
            (TrustClass::Community, false),
            (TrustClass::Trusted, true),
        ] {
            let queue = Queue::new();
            queue.submit(job("j", true));
            let leased = queue.lease("w", class, 1);
            assert_eq!(
                leased[0].includes_hidden_tests,
                expected,
                "{class:?} must{} be offered hidden tests",
                if expected { "" } else { " not" }
            );
        }
    }

    #[test]
    fn a_package_without_hidden_tests_never_claims_to_have_them() {
        let queue = Queue::new();
        queue.submit(job("j", false));
        let leased = queue.lease("w", TrustClass::Trusted, 1);
        assert!(!leased[0].includes_hidden_tests);
    }

    #[test]
    fn a_lease_always_selects_the_qualified_backend() {
        let queue = Queue::new();
        let mut queued = job("j", false);
        queued.spec.backend = Backend::Native;
        queue.submit(queued);

        let leased = queue.lease("w", TrustClass::Trusted, 1);
        assert_eq!(
            leased[0].backend,
            Backend::Wasmtime,
            "the broker must not dispatch to the unqualified native backend"
        );
    }

    #[test]
    fn capacity_is_clamped() {
        let queue = Queue::new();
        for i in 0..100 {
            queue.submit(job(&format!("j{i}"), false));
        }
        assert_eq!(
            queue.lease("w", TrustClass::Trusted, u32::MAX).len(),
            MAX_LEASE_CAPACITY as usize
        );
        assert_eq!(
            queue.lease("w", TrustClass::Trusted, 0).len(),
            1,
            "zero means one, not none"
        );
    }

    #[test]
    fn leasing_an_empty_queue_returns_nothing_rather_than_blocking() {
        assert!(Queue::new().lease("w", TrustClass::Trusted, 4).is_empty());
    }

    #[test]
    fn only_the_lease_holder_may_report() {
        let queue = Queue::new();
        queue.submit(job("j", false));
        queue.lease("w1", TrustClass::Trusted, 1);

        assert_eq!(
            queue.report_for("j", summary("w2")),
            Err(ReportError::NotLeaseHolder)
        );
        assert_eq!(queue.report_for("j", summary("w1")), Ok(true));
        assert_eq!(queue.results().len(), 1);
        assert_eq!(queue.in_flight(), 0);
    }

    #[test]
    fn reporting_twice_is_idempotent_rather_than_an_error() {
        let queue = Queue::new();
        queue.submit(job("j", false));
        queue.lease("w1", TrustClass::Trusted, 1);

        assert_eq!(queue.report_for("j", summary("w1")), Ok(true));
        assert_eq!(
            queue.report_for("j", summary("w1")),
            Ok(false),
            "a retry after a network blip must not create a second verdict"
        );
        assert_eq!(queue.results().len(), 1);
    }

    #[test]
    fn reporting_an_unknown_job_is_rejected() {
        assert_eq!(
            Queue::new().report_for("nope", summary("w1")),
            Err(ReportError::UnknownJob)
        );
    }

    #[test]
    fn a_mismatched_protocol_version_is_rejected() {
        let queue = Queue::new();
        queue.submit(job("j", false));
        queue.lease("w1", TrustClass::Trusted, 1);

        let mut bad = summary("w1");
        bad.protocol_version = 99;
        assert_eq!(
            queue.report_for("j", bad),
            Err(ReportError::ProtocolMismatch)
        );
    }
}
