//! The judge worker.
//!
//! # The pipeline
//!
//! ```text
//! lease job  ->  resolve CIDs  ->  compile  ->  grade (run many)  ->  report
//!                     |               |              |
//!               ArtifactSource   CompileBackend   ExecutionBackend
//! ```
//!
//! Every step behind a trait, so the whole pipeline is testable offline with no
//! network, no cargo, and no broker.
//!
//! # Two security domains
//!
//! Compilation and execution are **separate** security domains. Cargo may invoke
//! `build.rs` and procedural macros, so compiling untrusted Rust is running
//! untrusted code. The execution sandbox ([`rustly_sandbox::WasmtimeBackend`])
//! is implemented and adversarially tested. The **compile** sandbox is not:
//! [`compile::CargoCompiler`] is `EXPERIMENTAL`, is behind a Cargo feature, and
//! additionally refuses to run unless it is unlocked at runtime with an explicit
//! acknowledgement. See `docs/THREAT_MODEL.md`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod artifacts;
pub mod compile;
pub mod pipeline;

pub use artifacts::{ArtifactSource, LocalArtifacts};
pub use compile::{CompileBackend, CompileOutput, PrecompiledModule};
pub use pipeline::{run_job, JobReport};
