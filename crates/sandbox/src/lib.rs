//! Sandboxed execution.
//!
//! # Two security domains
//!
//! Compilation and execution are **separate** security domains, because Cargo
//! may invoke `build.rs` and procedural macros. Compiling untrusted Rust is
//! running untrusted code. A backend that is safe for running a finished
//! `.wasm` module is not automatically safe for producing one.
//!
//! This crate covers the **runtime** domain. Compilation is handled by the
//! worker, and its isolation is tracked separately and is not yet qualified.
//!
//! # Backend status
//!
//! | Backend | Status | Used for |
//! | --- | --- | --- |
//! | [`WasmtimeBackend`] | **IMPLEMENTED**, limits covered by tests | Untrusted submissions |
//! | [`NativeBackend`] | **EXPERIMENTAL**, refuses to run without a qualification token | Nothing yet |
//!
//! We do not claim the native backend is a security boundary. It exists so the
//! abstraction is real rather than hypothetical, and it fails closed.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod backend;
#[cfg(feature = "native-backend")]
pub mod native;
#[cfg(feature = "wasmtime-backend")]
pub mod wasmtime_backend;

pub use backend::{
    ensure_qualified, ExecutionBackend, ExecutionOutcome, ExecutionRequest, ExecutionResult,
    TerminationReason,
};
#[cfg(feature = "native-backend")]
pub use native::NativeBackend;
#[cfg(feature = "wasmtime-backend")]
pub use wasmtime_backend::WasmtimeBackend;
