//! The native execution backend.
//!
//! # Status: EXPERIMENTAL - not a security boundary
//!
//! This backend exists so the [`ExecutionBackend`] abstraction is real rather
//! than hypothetical, and so the work needed to qualify native execution is
//! written down somewhere concrete. **It does not execute anything.**
//!
//! Native isolation on Linux means, at minimum: user namespaces, a seccomp-BPF
//! filter with a deny-by-default syscall policy, cgroup v2 limits for CPU,
//! memory and PIDs, a read-only root with no `/proc` or `/sys`, no network
//! namespace, `no_new_privs`, dropped capabilities, and rlimits for file size
//! and open descriptors. Each of those is a place to get it subtly wrong, and
//! getting it subtly wrong means arbitrary code execution on judge
//! infrastructure.
//!
//! Rustly will not claim a native sandbox is safe on the basis that it looked
//! right. Qualification means an independent adversarial corpus, reviewed by
//! someone who did not write it. Until that exists, this backend fails closed.
//!
//! See `docs/THREAT_MODEL.md` for the qualification checklist.

use rustly_judge_common::JudgeError;

use crate::backend::{ExecutionBackend, ExecutionRequest, ExecutionResult};

/// A placeholder for native process isolation.
///
/// Constructing it is allowed; using it is not. [`ExecutionBackend::execute`]
/// always returns a `JudgeError`, and
/// [`ExecutionBackend::is_qualified_for_untrusted_code`] always returns `false`,
/// so callers that route through [`crate::ensure_qualified`] never reach it.
#[derive(Debug, Clone, Copy, Default)]
pub struct NativeBackend;

impl NativeBackend {
    /// Requirements that must all be met, and independently reviewed, before
    /// this backend may run untrusted code.
    ///
    /// Listed in code so the gap is visible to anyone reading the crate, not
    /// only to anyone who opens the threat model.
    pub const QUALIFICATION_REQUIREMENTS: [&'static str; 9] = [
        "deny-by-default seccomp-BPF syscall filter, with an audited allowlist",
        "user namespace with no mapped privileged uid",
        "cgroup v2 limits for cpu, memory, and pids",
        "read-only root filesystem with no /proc, /sys, or device access",
        "network namespace with no interfaces",
        "no_new_privs set and all capabilities dropped",
        "rlimits for file size, open descriptors, and address space",
        "an adversarial escape corpus that the backend survives",
        "independent review by someone who did not implement it",
    ];
}

impl ExecutionBackend for NativeBackend {
    fn id(&self) -> &'static str {
        "native"
    }

    fn is_qualified_for_untrusted_code(&self) -> bool {
        false
    }

    fn execute(&self, _request: ExecutionRequest<'_>) -> ExecutionResult {
        Err(JudgeError::Sandbox(format!(
            "the native backend is EXPERIMENTAL and has not been qualified; {} requirements \
             remain unmet. Use the Wasmtime backend.",
            Self::QUALIFICATION_REQUIREMENTS.len()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustly_judge_common::{Limits, Verdict};

    #[test]
    fn the_native_backend_never_claims_to_be_safe() {
        assert!(!NativeBackend.is_qualified_for_untrusted_code());
        assert_eq!(NativeBackend.id(), "native");
    }

    #[test]
    fn it_refuses_to_execute_rather_than_pretending_to_work() {
        let error = NativeBackend
            .execute(ExecutionRequest {
                module: b"\0asm",
                stdin: b"",
                args: &[],
                limits: Limits::default(),
            })
            .expect_err("an unqualified backend must never execute");
        assert_eq!(error.verdict(), Verdict::JudgeError);
        assert!(error.to_string().contains("EXPERIMENTAL"));
    }

    #[test]
    fn the_qualification_gate_stops_it_before_it_sees_user_code() {
        let error = crate::ensure_qualified(&NativeBackend).unwrap_err();
        assert!(error.to_string().contains("not qualified"));
    }

    #[test]
    fn the_qualification_checklist_is_not_quietly_emptied() {
        // If someone shortens this list, they are asserting a requirement is
        // unnecessary. That should be a visible diff with a reviewer.
        assert_eq!(NativeBackend::QUALIFICATION_REQUIREMENTS.len(), 9);
        assert!(NativeBackend::QUALIFICATION_REQUIREMENTS
            .iter()
            .any(|r| r.contains("seccomp")));
        assert!(NativeBackend::QUALIFICATION_REQUIREMENTS
            .iter()
            .any(|r| r.contains("independent review")));
    }
}
