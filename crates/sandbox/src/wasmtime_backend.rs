//! The Wasmtime/WASI execution backend.
//!
//! Status: **IMPLEMENTED**, with every bound covered by an adversarial test in
//! `tests/limits.rs`. This is the only backend used for untrusted submissions.
//!
//! # What the guest gets
//!
//! A WASI preview 1 environment with **no** network, **no** preopened
//! directories, **no** environment variables, and **no** inherited stdio. It
//! gets stdin bytes supplied by the test case and two capped output sinks.
//!
//! # How each bound is enforced
//!
//! | Bound | Mechanism | Detected as |
//! | --- | --- | --- |
//! | Work | Wasmtime fuel | `Trap::OutOfFuel` -> `LimitViolation::Fuel` |
//! | Wall clock | Epoch interruption from a watchdog thread | `Trap::Interrupt` -> `LimitViolation::Wall` |
//! | Memory | A `ResourceLimiter` that refuses growth past the bound | a recorded denial -> `LimitViolation::Memory` |
//! | Output | A capped sink that records overflow | a recorded overflow -> `LimitViolation::Output` |
//! | Instances / tables | The same `ResourceLimiter` | refused growth |
//!
//! Fuel and wall clock both exist because neither alone is sufficient. Fuel is
//! deterministic and fair across heterogeneous workers - a slow volunteer
//! machine must not fail a submission a fast one accepts - but it does not
//! count time spent outside the guest. Wall clock is the backstop.
//!
//! Memory and output are checked **before** the termination reason, because a
//! guest that hits either usually goes on to trap or exit non-zero; reporting
//! `RTE` there would blame the user's logic for a limit they hit.

use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use rustly_judge_common::{JudgeError, LimitViolation, Limits, Result};
use wasmtime::{Config, Engine, Linker, Module, ResourceLimiter, Store, Trap};
use wasmtime_wasi::cli::{IsTerminal, StdoutStream};
use wasmtime_wasi::p1::{self, WasiP1Ctx};
use wasmtime_wasi::p2::pipe::MemoryInputPipe;
use wasmtime_wasi::p2::{OutputStream, Pollable, StreamError, StreamResult};
use wasmtime_wasi::WasiCtxBuilder;

use crate::backend::{
    ExecutionBackend, ExecutionOutcome, ExecutionRequest, ExecutionResult, TerminationReason,
};

/// Guest stack limit. Deep recursion becomes a clean `StackOverflow` trap
/// rather than an unbounded host stack.
const MAX_WASM_STACK_BYTES: usize = 512 * 1024;

/// A Wasmtime-backed sandbox.
pub struct WasmtimeBackend {
    engine: Engine,
}

impl std::fmt::Debug for WasmtimeBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WasmtimeBackend").finish_non_exhaustive()
    }
}

impl WasmtimeBackend {
    /// Build a backend with a hardened engine configuration.
    pub fn new() -> Result<Self> {
        let mut config = Config::new();
        config
            .consume_fuel(true)
            .epoch_interruption(true)
            // A short backtrace is enough to explain a trap to a learner and
            // bounds the work done on a failing submission.
            .wasm_backtrace_max_frames(std::num::NonZeroUsize::new(16))
            .max_wasm_stack(MAX_WASM_STACK_BYTES);

        let engine = Engine::new(&config)
            .map_err(|e| JudgeError::Sandbox(format!("engine configuration rejected: {e}")))?;
        Ok(Self { engine })
    }

    /// The underlying engine, for callers that pre-compile modules.
    pub fn engine(&self) -> &Engine {
        &self.engine
    }
}

impl ExecutionBackend for WasmtimeBackend {
    fn id(&self) -> &'static str {
        "wasmtime"
    }

    fn is_qualified_for_untrusted_code(&self) -> bool {
        true
    }

    fn execute(&self, request: ExecutionRequest<'_>) -> ExecutionResult {
        let limits = request.limits;
        limits
            .validate()
            .map_err(|why| JudgeError::MalformedPackage(format!("invalid limits: {why}")))?;

        let module = Module::new(&self.engine, request.module).map_err(|e| {
            // A module that will not validate is a judge-side problem: the
            // compile step should never have produced it.
            JudgeError::Sandbox(format!("module failed validation: {e}"))
        })?;

        let stdout = CappedSink::new(limits.output_bytes as usize);
        let stderr = CappedSink::new(limits.output_bytes as usize);

        let wasi = WasiCtxBuilder::new()
            .stdin(MemoryInputPipe::new(request.stdin.to_vec()))
            .stdout(stdout.clone())
            .stderr(stderr.clone())
            .args(request.args)
            // Deliberately absent: inherit_env, inherit_network, preopened_dir.
            // The guest has no environment, no sockets, and no filesystem.
            .build_p1();

        let mut store = Store::new(
            &self.engine,
            HostState {
                wasi,
                limiter: MemoryLimiter::new(limits),
            },
        );
        store.limiter(|state| &mut state.limiter);
        store
            .set_fuel(limits.fuel)
            .map_err(|e| JudgeError::Sandbox(format!("could not set fuel: {e}")))?;
        store.set_epoch_deadline(1);

        let mut linker: Linker<HostState> = Linker::new(&self.engine);
        p1::add_to_linker_sync(&mut linker, |state: &mut HostState| &mut state.wasi)
            .map_err(|e| JudgeError::Sandbox(format!("could not link WASI: {e}")))?;

        let watchdog = Watchdog::start(&self.engine, Duration::from_millis(limits.wall_ms));
        let started = Instant::now();

        let outcome: std::result::Result<Trapish, JudgeError> = (|| {
            let instance = linker.instantiate(&mut store, &module).map_err(classify)?;
            let start = instance
                .get_typed_func::<(), ()>(&mut store, "_start")
                .map_err(|e| {
                    JudgeError::MalformedPackage(format!("module has no WASI `_start` export: {e}"))
                })?;
            start.call(&mut store, ()).map_err(classify)?;
            Ok(Trapish::Exited(0))
        })();

        let wall_ms = started.elapsed().as_millis() as u64;
        watchdog.stop();

        let fuel_consumed = store
            .get_fuel()
            .ok()
            .map(|left| limits.fuel.saturating_sub(left));
        let peak_memory_bytes = store.data().limiter.peak_memory as u64;
        let memory_denied = store.data().limiter.memory_denied;

        // Guest exit, fuel exhaustion, and traps all arrive through Wasmtime's
        // error channel. `interpret` separates those from genuine host
        // failures, which propagate as JE/IE instead.
        let trapish = match outcome {
            Ok(t) => t,
            Err(error) => interpret(error)?,
        };

        let output_overflowed = stdout.overflowed() || stderr.overflowed();

        // Order matters. A guest that hits the output or memory bound normally
        // goes on to trap; blaming the user's logic for a limit they hit would
        // be wrong and unactionable.
        let termination = if output_overflowed {
            TerminationReason::LimitExceeded {
                violation: LimitViolation::Output,
            }
        } else if memory_denied {
            TerminationReason::LimitExceeded {
                violation: LimitViolation::Memory,
            }
        } else {
            match trapish {
                Trapish::Exited(code) => TerminationReason::Exited { code },
                Trapish::Limit(violation) => TerminationReason::LimitExceeded { violation },
                Trapish::Trap(detail) => TerminationReason::Trapped { detail },
            }
        };

        Ok(ExecutionOutcome {
            termination,
            stdout: stdout.take(),
            stderr: stderr.take(),
            wall_ms,
            fuel_consumed,
            peak_memory_bytes,
        })
    }
}

/// How guest execution ended, before limit post-processing.
enum Trapish {
    Exited(i32),
    Limit(LimitViolation),
    Trap(String),
}

/// Turn a Wasmtime error into either a guest-visible outcome or a judge error.
fn classify(error: wasmtime::Error) -> JudgeError {
    // `proc_exit` surfaces as I32Exit and is a normal termination, not a failure.
    if let Some(exit) = error.downcast_ref::<wasmtime_wasi::I32Exit>() {
        return JudgeError::Sandbox(format!("__exit:{}", exit.0));
    }
    match error.downcast_ref::<Trap>() {
        Some(Trap::OutOfFuel) => JudgeError::Sandbox("__limit:fuel".into()),
        Some(Trap::Interrupt) => JudgeError::Sandbox("__limit:wall".into()),
        Some(trap) => JudgeError::Sandbox(format!("__trap:{trap}")),
        // Not a guest trap: a link failure, an unknown import, or a host-side
        // error. The user's program did not do anything wrong, so this must
        // never become CE, WA, or RTE.
        None => JudgeError::MalformedPackage(format!("module could not be run: {error}")),
    }
}

/// Reinterpret the sentinel errors produced by [`classify`].
///
/// Wasmtime reports guest exit, fuel exhaustion, and traps through the same
/// error channel as genuine host failures. This keeps the distinction explicit
/// rather than letting a guest trap be reported as a judge error.
fn interpret(error: JudgeError) -> std::result::Result<Trapish, JudgeError> {
    let JudgeError::Sandbox(message) = &error else {
        return Err(error);
    };
    if let Some(code) = message.strip_prefix("__exit:") {
        return Ok(Trapish::Exited(
            code.parse().unwrap_or(i32::from(!code.is_empty())),
        ));
    }
    match message.as_str() {
        "__limit:fuel" => Ok(Trapish::Limit(LimitViolation::Fuel)),
        "__limit:wall" => Ok(Trapish::Limit(LimitViolation::Wall)),
        other => match other.strip_prefix("__trap:") {
            Some(detail) => Ok(Trapish::Trap(detail.to_owned())),
            None => Err(error),
        },
    }
}

struct HostState {
    wasi: WasiP1Ctx,
    limiter: MemoryLimiter,
}

/// Enforces memory, table, and instance bounds, and records whether growth was
/// ever refused so the outcome can be reported as `MLE` rather than a trap.
struct MemoryLimiter {
    max_memory: usize,
    max_table_elements: usize,
    max_instances: usize,
    peak_memory: usize,
    memory_denied: bool,
}

impl MemoryLimiter {
    fn new(limits: Limits) -> Self {
        Self {
            max_memory: limits.memory_bytes as usize,
            max_table_elements: limits.table_elements as usize,
            max_instances: limits.instances as usize,
            peak_memory: 0,
            memory_denied: false,
        }
    }
}

impl ResourceLimiter for MemoryLimiter {
    fn memory_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        if desired > self.max_memory {
            self.memory_denied = true;
            return Ok(false);
        }
        self.peak_memory = self.peak_memory.max(desired);
        Ok(true)
    }

    fn table_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        Ok(desired <= self.max_table_elements)
    }

    fn instances(&self) -> usize {
        self.max_instances
    }

    fn memories(&self) -> usize {
        1
    }
}

/// Interrupts a runaway guest by advancing the engine epoch.
///
/// A thread rather than a timer because the guest runs synchronously on this
/// thread and cannot be polled. The watchdog waits on a channel so it exits
/// immediately when execution finishes, instead of sleeping out the full budget
/// on every fast test.
struct Watchdog {
    stop: std::sync::mpsc::Sender<()>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Watchdog {
    fn start(engine: &Engine, budget: Duration) -> Self {
        let (stop, rx) = std::sync::mpsc::channel();
        let engine = engine.clone();
        let handle = std::thread::spawn(move || {
            if rx.recv_timeout(budget).is_err() {
                engine.increment_epoch();
            }
        });
        Self {
            stop,
            handle: Some(handle),
        }
    }

    fn stop(mut self) {
        let _ = self.stop.send(());
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// An output sink that stops at a byte budget and remembers that it did.
///
/// Truncation alone is not enough: the judge must be able to say *why* output
/// stopped, so `OLE` is distinguishable from a program that simply printed less
/// than expected.
///
/// The sink buffers one byte beyond the budget on purpose. WASI asks for a
/// write permit before every write, so a sink that is exactly full is
/// indistinguishable from one that has been overrun - a program that printed
/// exactly the budget would be reported as `OLE`. The extra byte makes
/// "reached the budget" and "exceeded the budget" different states. The spare
/// byte is trimmed before the output is returned.
#[derive(Clone)]
struct CappedSink {
    budget: usize,
    state: Arc<Mutex<SinkState>>,
}

#[derive(Default)]
struct SinkState {
    buffer: Vec<u8>,
    overflowed: bool,
}

impl CappedSink {
    fn new(budget: usize) -> Self {
        Self {
            budget,
            state: Arc::new(Mutex::new(SinkState::default())),
        }
    }

    /// Bytes that may still be buffered, including the one-byte overrun slot.
    fn room(&self, buffered: usize) -> usize {
        (self.budget + 1).saturating_sub(buffered)
    }

    fn overflowed(&self) -> bool {
        self.state
            .lock()
            .expect("sink mutex is never poisoned")
            .overflowed
    }

    /// Take the captured output, trimmed to the budget.
    fn take(&self) -> Vec<u8> {
        let mut buffer = std::mem::take(
            &mut self
                .state
                .lock()
                .expect("sink mutex is never poisoned")
                .buffer,
        );
        buffer.truncate(self.budget);
        buffer
    }
}

impl tokio::io::AsyncWrite for CappedSink {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let mut state = self.state.lock().expect("sink mutex is never poisoned");
        let room = self.room(state.buffer.len());
        if room == 0 {
            state.overflowed = true;
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "output limit exceeded",
            )));
        }
        let take = room.min(buf.len());
        state.buffer.extend_from_slice(&buf[..take]);
        if take < buf.len() || state.buffer.len() > self.budget {
            state.overflowed = true;
        }
        Poll::Ready(Ok(take))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl IsTerminal for CappedSink {
    fn is_terminal(&self) -> bool {
        false
    }
}

impl StdoutStream for CappedSink {
    fn async_stream(&self) -> Box<dyn tokio::io::AsyncWrite + Send + Sync> {
        Box::new(self.clone())
    }

    /// Override the default adapter.
    ///
    /// The default wraps `async_stream` in a buffered `AsyncWriteStream` whose
    /// writes complete on a background task. That would make overflow detection
    /// racy: the judge reads the overflow flag as soon as the guest returns.
    /// A direct synchronous stream makes `OLE` deterministic.
    fn p2_stream(&self) -> Box<dyn OutputStream> {
        Box::new(self.clone())
    }
}

#[wasmtime_wasi::async_trait]
impl Pollable for CappedSink {
    async fn ready(&mut self) {}
}

impl OutputStream for CappedSink {
    fn write(&mut self, bytes: bytes::Bytes) -> StreamResult<()> {
        let mut state = self.state.lock().expect("sink mutex is never poisoned");
        let room = self.room(state.buffer.len());
        if bytes.len() > room {
            state.buffer.extend_from_slice(&bytes[..room]);
            state.overflowed = true;
            return Err(StreamError::Closed);
        }
        state.buffer.extend_from_slice(&bytes);
        if state.buffer.len() > self.budget {
            state.overflowed = true;
        }
        Ok(())
    }

    fn flush(&mut self) -> StreamResult<()> {
        Ok(())
    }

    fn check_write(&mut self) -> StreamResult<usize> {
        let mut state = self.state.lock().expect("sink mutex is never poisoned");
        match self.room(state.buffer.len()) {
            0 => {
                state.overflowed = true;
                Err(StreamError::Closed)
            }
            room => Ok(room),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sentinel_errors_are_interpreted_as_guest_outcomes_not_judge_failures() {
        assert!(matches!(
            interpret(JudgeError::Sandbox("__exit:0".into())).unwrap(),
            Trapish::Exited(0)
        ));
        assert!(matches!(
            interpret(JudgeError::Sandbox("__exit:101".into())).unwrap(),
            Trapish::Exited(101)
        ));
        assert!(matches!(
            interpret(JudgeError::Sandbox("__limit:fuel".into())).unwrap(),
            Trapish::Limit(LimitViolation::Fuel)
        ));
        assert!(matches!(
            interpret(JudgeError::Sandbox("__limit:wall".into())).unwrap(),
            Trapish::Limit(LimitViolation::Wall)
        ));
        assert!(matches!(
            interpret(JudgeError::Sandbox("__trap:unreachable".into())).unwrap(),
            Trapish::Trap(_)
        ));
    }

    #[test]
    fn a_real_judge_failure_is_not_swallowed_by_the_sentinel_channel() {
        let error = JudgeError::Infrastructure("object store unreachable".into());
        assert!(interpret(error).is_err());
        assert!(interpret(JudgeError::Sandbox("engine configuration rejected".into())).is_err());
    }

    #[test]
    fn the_capped_sink_records_overflow_rather_than_silently_truncating() {
        let sink = CappedSink::new(8);
        let mut stream = sink.clone();

        OutputStream::write(&mut stream, bytes::Bytes::from_static(b"1234")).unwrap();
        assert!(!sink.overflowed());

        // This write does not fit. The sink keeps what it can, records the
        // overflow, and closes rather than silently dropping the rest.
        let error = OutputStream::write(&mut stream, bytes::Bytes::from_static(b"567890"))
            .expect_err("a write past the cap must fail");
        assert!(matches!(error, StreamError::Closed));
        assert!(sink.overflowed());
        assert_eq!(sink.take(), b"12345678", "output is trimmed to the budget");
    }

    #[test]
    fn writing_exactly_the_budget_is_not_an_overflow() {
        // WASI requests a write permit before every write, so a sink that is
        // exactly full must still be distinguishable from one that overran.
        let sink = CappedSink::new(4);
        let mut stream = sink.clone();

        assert_eq!(OutputStream::check_write(&mut stream).unwrap(), 5);
        OutputStream::write(&mut stream, bytes::Bytes::from_static(b"abcd")).unwrap();
        assert!(!sink.overflowed(), "exactly the budget is fine");
        assert_eq!(OutputStream::check_write(&mut stream).unwrap(), 1);
        assert!(
            !sink.overflowed(),
            "asking for a permit must not itself be an overflow"
        );
        assert_eq!(sink.take(), b"abcd");
    }

    #[test]
    fn one_byte_past_the_budget_is_an_overflow() {
        let sink = CappedSink::new(4);
        let mut stream = sink.clone();
        OutputStream::write(&mut stream, bytes::Bytes::from_static(b"abcde")).unwrap();
        assert!(sink.overflowed());
        assert_eq!(
            sink.take(),
            b"abcd",
            "the spare byte never reaches the caller"
        );
    }

    #[test]
    fn the_limiter_denies_growth_past_the_bound_and_records_it() {
        let mut limiter = MemoryLimiter::new(Limits {
            memory_bytes: 1024,
            ..Limits::default()
        });
        assert!(limiter.memory_growing(0, 512, None).unwrap());
        assert!(!limiter.memory_denied);
        assert_eq!(limiter.peak_memory, 512);

        assert!(!limiter.memory_growing(512, 4096, None).unwrap());
        assert!(
            limiter.memory_denied,
            "a denial must be recorded so it can be reported as MLE"
        );
        assert_eq!(
            limiter.peak_memory, 512,
            "a denied grow must not raise the peak"
        );
    }

    #[test]
    fn the_backend_declares_itself_qualified_for_untrusted_code() {
        let backend = WasmtimeBackend::new().unwrap();
        assert_eq!(backend.id(), "wasmtime");
        assert!(backend.is_qualified_for_untrusted_code());
    }
}
