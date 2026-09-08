//! Output comparison.
//!
//! A checker answers one question: does this output match? It never decides a
//! verdict on its own, and it never guesses. A checker that cannot run - a
//! custom checker module that is not implemented, an unparseable float - returns
//! a **judge** error rather than quietly failing the submission.
//!
//! # Why `TrimmedLines` is the default
//!
//! A missing trailing newline is not a wrong answer. Teaching a beginner that it
//! is teaches them nothing about Rust and a great deal about our tooling. Exact
//! byte comparison remains available for problems where whitespace is the point.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use rustly_judge_common::{JudgeError, Result};
use rustly_problem_format::Checker;
use serde::{Deserialize, Serialize};

/// The result of comparing one output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Match {
    /// The output matched.
    Accepted,
    /// The output did not match.
    Rejected {
        /// Short, submitter-safe explanation of the first difference.
        detail: String,
    },
}

impl Match {
    /// Whether this is a match.
    pub fn is_accepted(&self) -> bool {
        matches!(self, Self::Accepted)
    }
}

/// Compare `actual` against `expected` under `checker`.
pub fn check(checker: &Checker, expected: &str, actual: &str) -> Result<Match> {
    match checker {
        Checker::Exact => Ok(compare_exact(expected, actual)),
        Checker::TrimmedLines => Ok(compare_trimmed(expected, actual)),
        Checker::Tokens => Ok(compare_tokens(expected, actual)),
        Checker::Float { absolute, relative } => compare_floats(expected, actual, *absolute, *relative),
        Checker::Custom { module_cid } => Err(JudgeError::CheckerFailure(format!(
            "custom checkers are PLANNED and not implemented; refusing to judge against {module_cid}"
        ))),
    }
}

fn compare_exact(expected: &str, actual: &str) -> Match {
    if expected == actual {
        return Match::Accepted;
    }
    Match::Rejected {
        detail: first_difference(expected, actual),
    }
}

/// Trim trailing whitespace on each line, and drop trailing blank lines.
fn normalise_lines(text: &str) -> Vec<&str> {
    let mut lines: Vec<&str> = text.lines().map(|line| line.trim_end()).collect();
    while lines.last().is_some_and(|line| line.is_empty()) {
        lines.pop();
    }
    lines
}

fn compare_trimmed(expected: &str, actual: &str) -> Match {
    let expected_lines = normalise_lines(expected);
    let actual_lines = normalise_lines(actual);
    if expected_lines == actual_lines {
        return Match::Accepted;
    }

    for (index, (want, got)) in expected_lines.iter().zip(actual_lines.iter()).enumerate() {
        if want != got {
            return Match::Rejected {
                detail: format!("line {}: expected {want:?}, got {got:?}", index + 1),
            };
        }
    }
    Match::Rejected {
        detail: format!(
            "expected {} line(s), got {}",
            expected_lines.len(),
            actual_lines.len()
        ),
    }
}

fn compare_tokens(expected: &str, actual: &str) -> Match {
    let want: Vec<&str> = expected.split_whitespace().collect();
    let got: Vec<&str> = actual.split_whitespace().collect();
    if want == got {
        return Match::Accepted;
    }
    for (index, (w, g)) in want.iter().zip(got.iter()).enumerate() {
        if w != g {
            return Match::Rejected {
                detail: format!("token {}: expected {w:?}, got {g:?}", index + 1),
            };
        }
    }
    Match::Rejected {
        detail: format!("expected {} token(s), got {}", want.len(), got.len()),
    }
}

fn compare_floats(expected: &str, actual: &str, absolute: f64, relative: f64) -> Result<Match> {
    let want: Vec<&str> = expected.split_whitespace().collect();
    let got: Vec<&str> = actual.split_whitespace().collect();

    if want.len() != got.len() {
        return Ok(Match::Rejected {
            detail: format!("expected {} value(s), got {}", want.len(), got.len()),
        });
    }

    for (index, (w, g)) in want.iter().zip(got.iter()).enumerate() {
        // An unparseable *expected* value is a broken package: a judge error,
        // not the submitter's fault.
        let want_value: f64 = w.parse().map_err(|_| {
            JudgeError::CheckerFailure(format!("expected output token {w:?} is not a number"))
        })?;
        let Ok(got_value) = g.parse::<f64>() else {
            return Ok(Match::Rejected {
                detail: format!("value {}: {g:?} is not a number", index + 1),
            });
        };

        if want_value.is_nan() || got_value.is_nan() {
            if want_value.is_nan() && got_value.is_nan() {
                continue;
            }
            return Ok(Match::Rejected {
                detail: format!(
                    "value {}: expected {want_value}, got {got_value}",
                    index + 1
                ),
            });
        }
        if want_value.is_infinite() || got_value.is_infinite() {
            if want_value == got_value {
                continue;
            }
            return Ok(Match::Rejected {
                detail: format!(
                    "value {}: expected {want_value}, got {got_value}",
                    index + 1
                ),
            });
        }

        let difference = (want_value - got_value).abs();
        let tolerance = absolute.max(relative * want_value.abs());
        if difference > tolerance {
            return Ok(Match::Rejected {
                detail: format!(
                    "value {}: expected {want_value}, got {got_value} (difference {difference:.3e} exceeds tolerance {tolerance:.3e})",
                    index + 1
                ),
            });
        }
    }
    Ok(Match::Accepted)
}

/// Describe the first difference without dumping the whole output.
fn first_difference(expected: &str, actual: &str) -> String {
    let position = expected
        .bytes()
        .zip(actual.bytes())
        .position(|(a, b)| a != b)
        .unwrap_or_else(|| expected.len().min(actual.len()));
    format!(
        "first difference at byte {position} (expected {} bytes, got {})",
        expected.len(),
        actual.len()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustly_judge_common::Verdict;

    #[test]
    fn exact_comparison_is_byte_for_byte() {
        assert!(check(&Checker::Exact, "3\n", "3\n").unwrap().is_accepted());
        assert!(!check(&Checker::Exact, "3\n", "3").unwrap().is_accepted());
        assert!(!check(&Checker::Exact, "3\n", "3 \n").unwrap().is_accepted());
    }

    #[test]
    fn a_missing_trailing_newline_is_not_a_wrong_answer() {
        let checker = Checker::TrimmedLines;
        assert!(check(&checker, "3\n", "3").unwrap().is_accepted());
        assert!(check(&checker, "3", "3\n").unwrap().is_accepted());
        assert!(check(&checker, "3\n", "3\n\n\n").unwrap().is_accepted());
        assert!(check(&checker, "3\n", "3   \n").unwrap().is_accepted());
    }

    #[test]
    fn trimming_does_not_forgive_a_genuinely_different_answer() {
        let result = check(&Checker::TrimmedLines, "3\n", "4\n").unwrap();
        assert!(!result.is_accepted());
        match result {
            Match::Rejected { detail } => assert!(detail.contains("line 1"), "{detail}"),
            Match::Accepted => unreachable!(),
        }
    }

    #[test]
    fn trimming_does_not_forgive_leading_whitespace() {
        assert!(!check(&Checker::TrimmedLines, "3\n", "  3\n")
            .unwrap()
            .is_accepted());
    }

    #[test]
    fn line_count_mismatches_are_explained() {
        let result = check(&Checker::TrimmedLines, "1\n2\n", "1\n").unwrap();
        match result {
            Match::Rejected { detail } => assert!(detail.contains("2 line(s), got 1"), "{detail}"),
            Match::Accepted => panic!("should not match"),
        }
    }

    #[test]
    fn token_comparison_ignores_layout_but_not_content() {
        let checker = Checker::Tokens;
        assert!(check(&checker, "1 2 3", "1\n2\n3\n").unwrap().is_accepted());
        assert!(check(&checker, "1 2 3", "  1   2 3  ")
            .unwrap()
            .is_accepted());
        assert!(!check(&checker, "1 2 3", "1 2 4").unwrap().is_accepted());
        assert!(!check(&checker, "1 2 3", "1 2").unwrap().is_accepted());
    }

    #[test]
    fn float_comparison_respects_absolute_tolerance() {
        let checker = Checker::Float {
            absolute: 1e-6,
            relative: 0.0,
        };
        assert!(check(&checker, "1.0000000", "1.0000005")
            .unwrap()
            .is_accepted());
        assert!(!check(&checker, "1.0", "1.001").unwrap().is_accepted());
    }

    #[test]
    fn float_comparison_respects_relative_tolerance_on_large_values() {
        let checker = Checker::Float {
            absolute: 0.0,
            relative: 1e-9,
        };
        assert!(check(&checker, "1e12", "1000000000001")
            .unwrap()
            .is_accepted());
        assert!(!check(&checker, "1e12", "1000010000000")
            .unwrap()
            .is_accepted());
    }

    #[test]
    fn float_comparison_handles_nan_and_infinity_without_panicking() {
        let checker = Checker::Float {
            absolute: 1e-9,
            relative: 1e-9,
        };
        assert!(check(&checker, "NaN", "NaN").unwrap().is_accepted());
        assert!(!check(&checker, "NaN", "1.0").unwrap().is_accepted());
        assert!(check(&checker, "inf", "inf").unwrap().is_accepted());
        assert!(!check(&checker, "inf", "-inf").unwrap().is_accepted());
    }

    #[test]
    fn unparseable_program_output_is_the_submitters_problem() {
        let checker = Checker::Float {
            absolute: 1e-9,
            relative: 0.0,
        };
        let result = check(&checker, "1.0", "banana").unwrap();
        assert!(
            !result.is_accepted(),
            "a non-numeric answer is a wrong answer"
        );
    }

    #[test]
    fn unparseable_expected_output_is_a_broken_package_not_a_wrong_answer() {
        let checker = Checker::Float {
            absolute: 1e-9,
            relative: 0.0,
        };
        let error = check(&checker, "banana", "1.0").unwrap_err();
        assert_eq!(
            error.verdict(),
            Verdict::JudgeError,
            "our broken package must never be reported as the submitter's mistake"
        );
    }

    #[test]
    fn an_unimplemented_custom_checker_refuses_rather_than_accepting_everything() {
        let checker = Checker::Custom {
            module_cid: "b3:abc".into(),
        };
        let error = check(&checker, "anything", "anything").unwrap_err();
        assert_eq!(error.verdict(), Verdict::JudgeError);
        assert!(error.to_string().contains("PLANNED"));
    }

    #[test]
    fn empty_output_comparisons_behave_sensibly() {
        assert!(check(&Checker::TrimmedLines, "", "").unwrap().is_accepted());
        assert!(check(&Checker::TrimmedLines, "", "\n\n")
            .unwrap()
            .is_accepted());
        assert!(!check(&Checker::TrimmedLines, "1\n", "")
            .unwrap()
            .is_accepted());
        assert!(check(&Checker::Tokens, "", "   ").unwrap().is_accepted());
    }

    #[test]
    fn rejection_details_are_short_enough_to_show_a_learner() {
        let expected = "x".repeat(100_000);
        let actual = "y".repeat(100_000);
        let Match::Rejected { detail } = check(&Checker::Exact, &expected, &actual).unwrap() else {
            panic!("should not match");
        };
        assert!(
            detail.len() < 200,
            "detail must summarise, not dump: {} bytes",
            detail.len()
        );
    }
}
