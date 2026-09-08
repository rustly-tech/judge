//! A standalone judge broker.
//!
//! # What this is, and what it is not
//!
//! In the hosted Rustly deployment the broker lives in the **control plane**
//! (`rustly-tech/core`, `/api/v1/judge/*`), because leasing a job is a decision
//! about trust and authority, and that belongs with identity and hidden tests.
//!
//! This binary exists for the deployments where that is not what you want:
//!
//! * running the judge standalone, offline, in a classroom or a lab;
//! * a self-hosted Rustly with its own worker pool;
//! * developing and testing a worker without running the whole control plane;
//! * the judge's own integration tests.
//!
//! It speaks the **identical** worker protocol, so a worker binary cannot tell
//! the difference. That is the point: it keeps the protocol honest by having two
//! independent implementations of it.
//!
//! Status: **IMPLEMENTED** for the queue semantics below and covered by tests.
//! It has no authentication, so it must only be exposed on a trusted network -
//! it enforces the hidden-test rule structurally instead (see [`Queue::lease`]).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod queue;
pub mod routes;

pub use queue::{Queue, QueuedJob};
