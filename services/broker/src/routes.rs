//! HTTP surface, matching the control plane's judge broker protocol.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use rustly_judge_protocol::{JobSpec, ResultSummary, TrustClass, PROTOCOL_VERSION};
use serde::{Deserialize, Serialize};

use crate::queue::{Queue, QueuedJob, ReportError, EMPTY_QUEUE_BACKOFF_SECONDS};

/// A worker's request for work.
#[derive(Debug, Clone, Deserialize)]
pub struct LeaseRequest {
    /// Protocol version the worker speaks.
    pub protocol_version: u32,
    /// Worker identifier.
    pub worker_id: String,
    /// Declared trust class.
    ///
    /// This broker has no credentials, so the declaration is taken at face
    /// value. That is exactly why it must only be exposed on a trusted network,
    /// and why hidden tests are still filtered structurally by the queue: a
    /// misconfiguration degrades to "no hidden tests dispatched", never to
    /// "hidden tests leaked".
    pub trust_class: TrustClass,
    /// Jobs requested.
    pub capacity: u32,
}

/// Leased work.
#[derive(Debug, Clone, Serialize)]
pub struct LeaseResponse {
    /// Leased jobs, possibly empty.
    pub jobs: Vec<JobSpec>,
    /// Seconds to wait before re-polling an empty queue.
    pub poll_after_seconds: u32,
}

/// Broker health and queue depth.
#[derive(Debug, Clone, Serialize)]
pub struct StatusResponse {
    /// Always `"ok"` if the process is serving.
    pub status: &'static str,
    /// Protocol version this broker speaks.
    pub protocol_version: u32,
    /// Jobs waiting to be leased.
    pub queue_depth: usize,
    /// Jobs currently leased.
    pub in_flight: usize,
    /// Jobs finished.
    pub finished: usize,
}

/// Build the router.
pub fn router(queue: Queue) -> Router {
    Router::new()
        .route("/status", get(status))
        .route("/api/v1/judge/leases", post(lease))
        .route("/api/v1/judge/jobs/{job_id}/result", post(report))
        .route("/api/v1/judge/jobs", post(submit))
        .with_state(queue)
}

async fn status(State(queue): State<Queue>) -> Json<StatusResponse> {
    Json(StatusResponse {
        status: "ok",
        protocol_version: PROTOCOL_VERSION,
        queue_depth: queue.depth(),
        in_flight: queue.in_flight(),
        finished: queue.results().len(),
    })
}

async fn lease(
    State(queue): State<Queue>,
    Json(body): Json<LeaseRequest>,
) -> Result<Json<LeaseResponse>, (StatusCode, Json<ErrorBody>)> {
    if body.protocol_version != PROTOCOL_VERSION {
        return Err(error(
            StatusCode::BAD_REQUEST,
            format!("this broker speaks protocol v{PROTOCOL_VERSION}"),
        ));
    }
    let jobs = queue.lease(&body.worker_id, body.trust_class, body.capacity);
    Ok(Json(LeaseResponse {
        jobs,
        poll_after_seconds: EMPTY_QUEUE_BACKOFF_SECONDS,
    }))
}

async fn report(
    State(queue): State<Queue>,
    Path(job_id): Path<String>,
    Json(summary): Json<ResultSummary>,
) -> Result<Json<ReportAck>, (StatusCode, Json<ErrorBody>)> {
    match queue.report_for(&job_id, summary) {
        Ok(accepted) => Ok(Json(ReportAck { accepted })),
        Err(ReportError::UnknownJob) => {
            Err(error(StatusCode::NOT_FOUND, "no such leased job".into()))
        }
        Err(ReportError::NotLeaseHolder) => Err(error(
            StatusCode::FORBIDDEN,
            "job is leased by another worker".into(),
        )),
        Err(ReportError::ProtocolMismatch) => Err(error(
            StatusCode::BAD_REQUEST,
            "unsupported protocol version".into(),
        )),
        Err(ReportError::PackageMismatch) => Err(error(
            StatusCode::BAD_REQUEST,
            "result package does not match leased job".into(),
        )),
    }
}

async fn submit(
    State(queue): State<Queue>,
    Json(body): Json<SubmitRequest>,
) -> (StatusCode, Json<SubmitAck>) {
    let job_id = body.spec.job_id.clone();
    queue.submit(QueuedJob {
        spec: body.spec,
        package_has_hidden_tests: body.package_has_hidden_tests,
    });
    (
        StatusCode::ACCEPTED,
        Json(SubmitAck {
            job_id,
            queue_depth: queue.depth(),
        }),
    )
}

/// Enqueue a job. Used by an operator or a test harness, not by workers.
#[derive(Debug, Clone, Deserialize)]
pub struct SubmitRequest {
    /// The job.
    pub spec: JobSpec,
    /// Whether the referenced package contains hidden tests.
    #[serde(default)]
    pub package_has_hidden_tests: bool,
}

/// Acknowledgement of a submitted job.
#[derive(Debug, Clone, Serialize)]
pub struct SubmitAck {
    /// The job identifier.
    pub job_id: String,
    /// Queue depth after enqueueing.
    pub queue_depth: usize,
}

/// Acknowledgement of a reported result.
#[derive(Debug, Clone, Serialize)]
pub struct ReportAck {
    /// Whether this report finalised the job. `false` means it was a duplicate.
    pub accepted: bool,
}

/// A uniform error body.
#[derive(Debug, Clone, Serialize)]
pub struct ErrorBody {
    /// Human-readable message.
    pub message: String,
}

fn error(status: StatusCode, message: String) -> (StatusCode, Json<ErrorBody>) {
    (status, Json(ErrorBody { message }))
}
