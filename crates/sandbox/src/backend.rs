//! The execution-backend abstraction.

use rustly_judge_common::{JudgeError, LimitViolation, Limits, Result, Verdict};
use serde::{Deserialize, Serialize};

/// One execution request.
#[derive(Debug, Clone)]
pub struct ExecutionRequest<'a> {
    /// The compiled module to run.
    pub module: &'a [u8],
    /// Bytes written to the guest's stdin.
    pub stdin: &'a [u8],
    /// Command-line arguments passed to the guest.
    pub args: &'a [String],
    /// Bounds to enforce.
    pub limits: Limits,
}

/// How an execution ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "reason")]
pub enum TerminationReason {
    /// The guest returned normally.
    Exited {
        /// Process exit code as reported by WASI.
        code: i32,
    },
    /// The guest trapped: unreachable, out-of-bounds, integer divide by zero,
    /// an explicit panic, or a stack overflow.
    Trapped {
        /// Short description, safe to show a user.
        detail: String,
    },
    /// A bound was exceeded.
    LimitExceeded {
        /// Which bound.
        violation: LimitViolation,
    },
}

/// What an execution produced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionOutcome {
    /// How it ended.
    pub termination: TerminationReason,
    /// Captured stdout, truncated at the output bound.
    pub stdout: Vec<u8>,
    /// Captured stderr, truncated at the output bound.
    pub stderr: Vec<u8>,
    /// Wall-clock duration, milliseconds.
    pub wall_ms: u64,
    /// Work units consumed, when the backend measures them.
    pub fuel_consumed: Option<u64>,
    /// Peak linear memory observed, bytes.
    pub peak_memory_bytes: u64,
}

impl ExecutionOutcome {
    /// The verdict implied by termination alone.
    ///
    /// A clean exit yields `None`: correctness is the checker's job, not the
    /// sandbox's. The sandbox only reports how the program *ended*.
    pub fn termination_verdict(&self) -> Option<Verdict> {
        match &self.termination {
            TerminationReason::Exited { code: 0 } => None,
            TerminationReason::Exited { .. } => Some(Verdict::RuntimeError),
            TerminationReason::Trapped { .. } => Some(Verdict::RuntimeError),
            TerminationReason::LimitExceeded { violation } => Some(violation.verdict()),
        }
    }

    /// Whether the guest exited cleanly.
    pub fn is_clean_exit(&self) -> bool {
        matches!(self.termination, TerminationReason::Exited { code: 0 })
    }

    /// Stdout as UTF-8, lossily. Guest output is arbitrary bytes.
    pub fn stdout_lossy(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.stdout)
    }
}

/// Result of asking a backend to execute something.
pub type ExecutionResult = Result<ExecutionOutcome>;

/// A sandboxed execution backend.
///
/// Implementations must enforce every bound in [`Limits`] and must not give the
/// guest network access, host filesystem access outside an explicitly granted
/// directory, an environment, or a real clock beyond what WASI defines.
pub trait ExecutionBackend: Send + Sync {
    /// Stable identifier recorded in result manifests, e.g. `"wasmtime"`.
    fn id(&self) -> &'static str;

    /// Whether this backend has been qualified for untrusted submissions.
    ///
    /// A backend that returns `false` must not be handed user code. The grader
    /// checks this, so an unqualified backend cannot be used by accident.
    fn is_qualified_for_untrusted_code(&self) -> bool;

    /// Execute `request`.
    ///
    /// Returns `Err` only for *judge* failures. A guest that traps, loops
    /// forever, or floods stdout is a successful execution with a
    /// [`TerminationReason`] saying so - that is a fact about the user's
    /// program, not a failure of ours.
    fn execute(&self, request: ExecutionRequest<'_>) -> ExecutionResult;
}

/// Guard used by callers before handing a backend untrusted code.
pub fn ensure_qualified(backend: &dyn ExecutionBackend) -> Result<()> {
    if backend.is_qualified_for_untrusted_code() {
        return Ok(());
    }
    Err(JudgeError::Sandbox(format!(
        "backend `{}` is not qualified for untrusted code",
        backend.id()
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outcome(termination: TerminationReason) -> ExecutionOutcome {
        ExecutionOutcome {
            termination,
            stdout: b"hello".to_vec(),
            stderr: vec![],
            wall_ms: 1,
            fuel_consumed: Some(10),
            peak_memory_bytes: 65_536,
        }
    }

    #[test]
    fn a_clean_exit_leaves_the_verdict_to_the_checker() {
        let o = outcome(TerminationReason::Exited { code: 0 });
        assert_eq!(o.termination_verdict(), None);
        assert!(o.is_clean_exit());
        assert_eq!(o.stdout_lossy(), "hello");
    }

    #[test]
    fn a_non_zero_exit_or_trap_is_a_runtime_error() {
        assert_eq!(
            outcome(TerminationReason::Exited { code: 101 }).termination_verdict(),
            Some(Verdict::RuntimeError)
        );
        assert_eq!(
            outcome(TerminationReason::Trapped {
                detail: "unreachable".into()
            })
            .termination_verdict(),
            Some(Verdict::RuntimeError)
        );
    }

    #[test]
    fn limit_violations_carry_their_own_verdicts() {
        for (violation, expected) in [
            (LimitViolation::Wall, Verdict::TimeLimitExceeded),
            (LimitViolation::Fuel, Verdict::TimeLimitExceeded),
            (LimitViolation::Memory, Verdict::MemoryLimitExceeded),
            (LimitViolation::Output, Verdict::OutputLimitExceeded),
        ] {
            let o = outcome(TerminationReason::LimitExceeded { violation });
            assert_eq!(o.termination_verdict(), Some(expected));
        }
    }

    #[test]
    fn an_unqualified_backend_is_refused_before_it_sees_user_code() {
        struct Unqualified;
        impl ExecutionBackend for Unqualified {
            fn id(&self) -> &'static str {
                "unqualified"
            }
            fn is_qualified_for_untrusted_code(&self) -> bool {
                false
            }
            fn execute(&self, _: ExecutionRequest<'_>) -> ExecutionResult {
                panic!("must never be reached");
            }
        }

        let error = ensure_qualified(&Unqualified).unwrap_err();
        assert_eq!(error.verdict(), Verdict::JudgeError);
        assert!(error.to_string().contains("not qualified"));
    }

    #[test]
    fn termination_round_trips_through_json() {
        let value = serde_json::to_value(TerminationReason::LimitExceeded {
            violation: LimitViolation::Fuel,
        })
        .unwrap();
        assert_eq!(value["reason"], "limit_exceeded");
        assert_eq!(value["violation"], "fuel");
    }
}
