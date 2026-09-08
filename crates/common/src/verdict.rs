//! Verdicts.

use serde::{Deserialize, Serialize};

/// A judge verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Verdict {
    /// Accepted.
    #[serde(rename = "AC")]
    Accepted,
    /// The user's code failed to compile.
    #[serde(rename = "CE")]
    CompileError,
    /// Wrong answer.
    #[serde(rename = "WA")]
    WrongAnswer,
    /// Wall-clock or work bound exceeded.
    #[serde(rename = "TLE")]
    TimeLimitExceeded,
    /// Memory bound exceeded.
    #[serde(rename = "MLE")]
    MemoryLimitExceeded,
    /// Output bound exceeded.
    #[serde(rename = "OLE")]
    OutputLimitExceeded,
    /// The user's program trapped or exited non-zero.
    #[serde(rename = "RTE")]
    RuntimeError,
    /// The judge failed: malformed package, checker crash, missing test data.
    #[serde(rename = "JE")]
    JudgeError,
    /// Rustly infrastructure failed: storage, queue, cache.
    #[serde(rename = "IE")]
    InternalError,
    /// A sandbox policy was tripped.
    #[serde(rename = "SE")]
    SecurityEvent,
}

/// Who a verdict is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerdictClass {
    /// The submission was correct.
    Accepted,
    /// The submission was wrong or exceeded a limit.
    UserFault,
    /// Rustly or the judge failed. Retryable; not the user's problem.
    SystemFault,
}

impl Verdict {
    /// Every verdict, in documentation order.
    pub const ALL: [Verdict; 10] = [
        Self::Accepted,
        Self::CompileError,
        Self::WrongAnswer,
        Self::TimeLimitExceeded,
        Self::MemoryLimitExceeded,
        Self::OutputLimitExceeded,
        Self::RuntimeError,
        Self::JudgeError,
        Self::InternalError,
        Self::SecurityEvent,
    ];

    /// The short code used on the wire and in the UI.
    pub const fn code(self) -> &'static str {
        match self {
            Self::Accepted => "AC",
            Self::CompileError => "CE",
            Self::WrongAnswer => "WA",
            Self::TimeLimitExceeded => "TLE",
            Self::MemoryLimitExceeded => "MLE",
            Self::OutputLimitExceeded => "OLE",
            Self::RuntimeError => "RTE",
            Self::JudgeError => "JE",
            Self::InternalError => "IE",
            Self::SecurityEvent => "SE",
        }
    }

    /// Classify the verdict.
    pub const fn class(self) -> VerdictClass {
        match self {
            Self::Accepted => VerdictClass::Accepted,
            Self::CompileError
            | Self::WrongAnswer
            | Self::TimeLimitExceeded
            | Self::MemoryLimitExceeded
            | Self::OutputLimitExceeded
            | Self::RuntimeError
            | Self::SecurityEvent => VerdictClass::UserFault,
            Self::JudgeError | Self::InternalError => VerdictClass::SystemFault,
        }
    }

    /// Whether the platform may transparently retry this submission.
    pub const fn is_retryable(self) -> bool {
        matches!(self.class(), VerdictClass::SystemFault)
    }

    /// The worse of two verdicts, for aggregating a test set.
    ///
    /// System faults dominate everything: if any test could not be judged, the
    /// whole submission is unjudged. Reporting `WA` because the cache was
    /// corrupt would be a lie, and the user cannot act on it.
    pub fn worst(self, other: Verdict) -> Verdict {
        fn severity(v: Verdict) -> u8 {
            match v.class() {
                VerdictClass::Accepted => 0,
                VerdictClass::UserFault => 1,
                VerdictClass::SystemFault => 2,
            }
        }
        match severity(self).cmp(&severity(other)) {
            std::cmp::Ordering::Less => other,
            std::cmp::Ordering::Greater => self,
            // Same class: keep the first, so the earliest failing test is the
            // one a user is shown.
            std::cmp::Ordering::Equal => self,
        }
    }
}

impl std::fmt::Display for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_stable_and_distinct() {
        let codes: Vec<_> = Verdict::ALL.iter().map(|v| v.code()).collect();
        assert_eq!(
            codes,
            ["AC", "CE", "WA", "TLE", "MLE", "OLE", "RTE", "JE", "IE", "SE"]
        );
        assert_eq!(
            codes.iter().collect::<std::collections::HashSet<_>>().len(),
            10
        );
    }

    #[test]
    fn wire_form_matches_the_code() {
        for v in Verdict::ALL {
            assert_eq!(
                serde_json::to_string(&v).unwrap(),
                format!("\"{}\"", v.code())
            );
        }
    }

    #[test]
    fn infrastructure_failure_is_never_user_fault() {
        for v in [Verdict::JudgeError, Verdict::InternalError] {
            assert_eq!(v.class(), VerdictClass::SystemFault);
            assert!(v.is_retryable());
        }
    }

    #[test]
    fn a_system_fault_dominates_a_wrong_answer() {
        assert_eq!(
            Verdict::WrongAnswer.worst(Verdict::InternalError),
            Verdict::InternalError
        );
        assert_eq!(
            Verdict::InternalError.worst(Verdict::WrongAnswer),
            Verdict::InternalError
        );
        assert_eq!(
            Verdict::Accepted.worst(Verdict::JudgeError),
            Verdict::JudgeError
        );
    }

    #[test]
    fn a_user_fault_dominates_accepted_and_the_first_failure_wins() {
        assert_eq!(
            Verdict::Accepted.worst(Verdict::WrongAnswer),
            Verdict::WrongAnswer
        );
        assert_eq!(
            Verdict::TimeLimitExceeded.worst(Verdict::WrongAnswer),
            Verdict::TimeLimitExceeded,
            "the earliest failing test is the one the user is shown"
        );
    }

    #[test]
    fn accepted_folds_to_accepted() {
        let verdict = [Verdict::Accepted; 5]
            .into_iter()
            .fold(Verdict::Accepted, Verdict::worst);
        assert_eq!(verdict, Verdict::Accepted);
    }

    #[test]
    fn a_security_event_is_the_users_problem_not_a_retry() {
        assert_eq!(Verdict::SecurityEvent.class(), VerdictClass::UserFault);
        assert!(!Verdict::SecurityEvent.is_retryable());
    }
}
