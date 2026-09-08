//! Judge errors.
//!
//! Every error maps to a verdict *class*, and the mapping is the point of this
//! module. A cache miss, a corrupt artifact, or an unreachable object store must
//! never surface as `CE` or `WA`.

use crate::verdict::Verdict;

/// Convenience alias.
pub type Result<T, E = JudgeError> = std::result::Result<T, E>;

/// Something went wrong while judging.
#[derive(Debug, thiserror::Error)]
pub enum JudgeError {
    /// The Trial package is malformed or internally inconsistent.
    ///
    /// The judge cannot judge; the user did nothing wrong. `JE`.
    #[error("malformed problem package: {0}")]
    MalformedPackage(String),

    /// A checker failed, crashed, or produced an unparseable result. `JE`.
    #[error("checker failed: {0}")]
    CheckerFailure(String),

    /// The sandbox could not be constructed or the engine failed. `JE`.
    #[error("sandbox failure: {0}")]
    Sandbox(String),

    /// Storage, cache, or network failure. `IE`.
    #[error("infrastructure failure: {0}")]
    Infrastructure(String),

    /// A cached artifact failed integrity verification. `IE`.
    ///
    /// Explicitly not `WA`: the cache is disposable, so this means retry and
    /// quarantine, never a wrong verdict for the user.
    #[error("cache integrity failure for {cid}: {detail}")]
    CacheIntegrity {
        /// Content identifier of the artifact that failed verification.
        cid: String,
        /// What was wrong.
        detail: String,
    },

    /// A sandbox policy was tripped in a way that indicates intent. `SE`.
    #[error("security policy tripped: {0}")]
    SecurityPolicy(String),
}

impl JudgeError {
    /// The verdict this error must be reported as.
    pub const fn verdict(&self) -> Verdict {
        match self {
            Self::MalformedPackage(_) | Self::CheckerFailure(_) | Self::Sandbox(_) => {
                Verdict::JudgeError
            }
            Self::Infrastructure(_) | Self::CacheIntegrity { .. } => Verdict::InternalError,
            Self::SecurityPolicy(_) => Verdict::SecurityEvent,
        }
    }

    /// Whether the job should be retried, possibly on another worker.
    pub const fn is_retryable(&self) -> bool {
        self.verdict().is_retryable()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verdict::VerdictClass;

    #[test]
    fn no_judge_error_can_ever_become_ce_or_wa() {
        let errors = [
            JudgeError::MalformedPackage("missing tests".into()),
            JudgeError::CheckerFailure("panicked".into()),
            JudgeError::Sandbox("engine init".into()),
            JudgeError::Infrastructure("object store unreachable".into()),
            JudgeError::CacheIntegrity {
                cid: "b3:x".into(),
                detail: "hash mismatch".into(),
            },
            JudgeError::SecurityPolicy("attempted socket open".into()),
        ];
        for error in errors {
            let verdict = error.verdict();
            assert_ne!(verdict, Verdict::CompileError, "{error}");
            assert_ne!(verdict, Verdict::WrongAnswer, "{error}");
        }
    }

    #[test]
    fn cache_corruption_is_retryable_infrastructure_not_a_user_verdict() {
        let error = JudgeError::CacheIntegrity {
            cid: "b3:deadbeef".into(),
            detail: "hash mismatch".into(),
        };
        assert_eq!(error.verdict(), Verdict::InternalError);
        assert!(
            error.is_retryable(),
            "a disposable cache must cause a clean retry"
        );
    }

    #[test]
    fn package_and_checker_faults_are_judge_errors() {
        assert_eq!(
            JudgeError::MalformedPackage("x".into()).verdict(),
            Verdict::JudgeError
        );
        assert_eq!(
            JudgeError::CheckerFailure("x".into()).verdict(),
            Verdict::JudgeError
        );
        assert_eq!(
            JudgeError::Sandbox("x".into()).verdict(),
            Verdict::JudgeError
        );
    }

    #[test]
    fn a_security_policy_trip_is_not_retried() {
        let error = JudgeError::SecurityPolicy("network syscall".into());
        assert_eq!(error.verdict(), Verdict::SecurityEvent);
        assert_eq!(error.verdict().class(), VerdictClass::UserFault);
        assert!(
            !error.is_retryable(),
            "retrying a policy violation just repeats it"
        );
    }
}
