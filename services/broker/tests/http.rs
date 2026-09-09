//! HTTP-level tests for the standalone broker.
//!
//! Drives the real router, so the wire shapes a worker depends on are exercised
//! rather than assumed.

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use http_body_util::BodyExt as _;
use rustly_judge_broker::{routes, Queue};
use rustly_judge_common::Limits;
use rustly_judge_protocol::{Backend, JobSpec, PROTOCOL_VERSION};
use serde_json::{json, Value};
use tower::ServiceExt as _;

async fn call(
    app: &axum::Router,
    method: Method,
    uri: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let builder = Request::builder().method(method).uri(uri);
    let request = match body {
        Some(value) => builder
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&value).unwrap()))
            .unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    };
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    (status, value)
}

fn spec(job_id: &str) -> JobSpec {
    JobSpec {
        protocol_version: PROTOCOL_VERSION,
        job_id: job_id.into(),
        source_cid: "b3:source".into(),
        trial_package_cid: "b3:package".into(),
        trial_version: 1,
        environment_id: "rust-1.88-wasm32-wasip1".into(),
        limits: Limits::default(),
        backend: Backend::Wasmtime,
        includes_hidden_tests: false,
    }
}

fn app() -> axum::Router {
    routes::router(Queue::new())
}

#[tokio::test]
async fn status_reports_protocol_version_and_queue_depth() {
    let app = app();
    let (status, body) = call(&app, Method::GET, "/status", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ok");
    assert_eq!(body["protocol_version"], PROTOCOL_VERSION);
    assert_eq!(body["queue_depth"], 0);
}

#[tokio::test]
async fn the_full_submit_lease_report_cycle_works_over_http() {
    let app = app();

    let (status, ack) = call(
        &app,
        Method::POST,
        "/api/v1/judge/jobs",
        Some(json!({ "spec": spec("job-1"), "package_has_hidden_tests": true })),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(ack["job_id"], "job-1");
    assert_eq!(ack["queue_depth"], 1);

    let (status, lease) = call(
        &app,
        Method::POST,
        "/api/v1/judge/leases",
        Some(json!({
            "protocol_version": PROTOCOL_VERSION,
            "worker_id": "worker-1",
            "trust_class": "trusted",
            "capacity": 4
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(lease["jobs"].as_array().unwrap().len(), 1);
    assert_eq!(lease["jobs"][0]["job_id"], "job-1");
    assert_eq!(lease["jobs"][0]["includes_hidden_tests"], true);
    assert_eq!(lease["jobs"][0]["backend"], "wasmtime");

    let (status, ack) = call(
        &app,
        Method::POST,
        "/api/v1/judge/jobs/job-1/result",
        Some(json!({
            "protocol_version": PROTOCOL_VERSION,
            "worker_id": "worker-1",
            "trial_package_cid": "b3:package",
            "verdict": "AC",
            "result_manifest_hash": "b3:manifest",
            "peak_memory_bytes": 65536,
            "execution_ms": 4,
            "compile_ms": 700,
            "used_cached_artifact": false
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(ack["accepted"], true);

    let (_, body) = call(&app, Method::GET, "/status", None).await;
    assert_eq!(body["queue_depth"], 0);
    assert_eq!(body["in_flight"], 0);
    assert_eq!(body["finished"], 1);
}

#[tokio::test]
async fn a_volunteer_worker_is_never_offered_hidden_tests_over_the_wire() {
    let app = app();
    call(
        &app,
        Method::POST,
        "/api/v1/judge/jobs",
        Some(json!({ "spec": spec("job-1"), "package_has_hidden_tests": true })),
    )
    .await;

    let (_, lease) = call(
        &app,
        Method::POST,
        "/api/v1/judge/leases",
        Some(json!({
            "protocol_version": PROTOCOL_VERSION,
            "worker_id": "volunteer-1",
            "trust_class": "volunteer",
            "capacity": 1
        })),
    )
    .await;
    assert_eq!(lease["jobs"][0]["includes_hidden_tests"], false);
}

#[tokio::test]
async fn only_the_lease_holder_may_report_a_result() {
    let app = app();
    call(
        &app,
        Method::POST,
        "/api/v1/judge/jobs",
        Some(json!({ "spec": spec("job-1") })),
    )
    .await;
    call(
        &app,
        Method::POST,
        "/api/v1/judge/leases",
        Some(json!({
            "protocol_version": PROTOCOL_VERSION,
            "worker_id": "worker-1",
            "trust_class": "trusted",
            "capacity": 1
        })),
    )
    .await;

    let report = json!({
        "protocol_version": PROTOCOL_VERSION,
        "worker_id": "worker-2",
        "trial_package_cid": "b3:package",
        "verdict": "AC",
        "result_manifest_hash": "b3:manifest",
        "peak_memory_bytes": 0,
        "execution_ms": 1,
        "compile_ms": 1,
        "used_cached_artifact": false
    });
    let (status, _) = call(
        &app,
        Method::POST,
        "/api/v1/judge/jobs/job-1/result",
        Some(report),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn reporting_an_unknown_job_is_a_404() {
    let app = app();
    let (status, _) = call(
        &app,
        Method::POST,
        "/api/v1/judge/jobs/nope/result",
        Some(json!({
            "protocol_version": PROTOCOL_VERSION,
            "worker_id": "w",
            "trial_package_cid": "b3:package",
            "verdict": "AC",
            "result_manifest_hash": "b3:m",
            "peak_memory_bytes": 0,
            "execution_ms": 0,
            "compile_ms": 0,
            "used_cached_artifact": false
        })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_worker_speaking_a_different_protocol_version_is_refused() {
    let app = app();
    let (status, _) = call(
        &app,
        Method::POST,
        "/api/v1/judge/leases",
        Some(json!({
            "protocol_version": 99,
            "worker_id": "w",
            "trust_class": "trusted",
            "capacity": 1
        })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn an_empty_queue_returns_no_jobs_and_a_backoff() {
    let app = app();
    let (status, lease) = call(
        &app,
        Method::POST,
        "/api/v1/judge/leases",
        Some(json!({
            "protocol_version": PROTOCOL_VERSION,
            "worker_id": "w",
            "trust_class": "trusted",
            "capacity": 8
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(lease["jobs"].as_array().unwrap().is_empty());
    assert!(lease["poll_after_seconds"].as_u64().unwrap() >= 1);
}
