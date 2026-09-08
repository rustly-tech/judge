//! The Trial package format.
//!
//! A Trial package is the immutable, content-addressed unit the judge executes.
//! It is produced by the `content` repository, addressed by BLAKE3 CID, and
//! fetched from the data plane - it never travels through the control-plane API.
//!
//! # Format version
//!
//! [`FORMAT_VERSION`] is independent of this crate's version. Changing the
//! meaning of any field without bumping it is a breaking-change incident.
//!
//! # Public and hidden tests
//!
//! A package carries [`TestCase`]s marked [`Visibility::Public`] or
//! [`Visibility::Hidden`]. A package handed to a non-trusted worker is
//! [`TrialPackage::public_only`] - the hidden cases are not merely flagged, they
//! are **removed**, so there is nothing on that worker to leak.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::collections::BTreeSet;

use rustly_judge_common::{JudgeError, Limits, Result};
use serde::{Deserialize, Serialize};

/// Version of this package format.
pub const FORMAT_VERSION: u32 = 1;

/// Whether a test case may be shown to the submitter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Visibility {
    /// Shown in the UI and runnable locally.
    Public,
    /// Authoritative. Never leaves trusted infrastructure.
    Hidden,
}

/// How a test's output is compared to the expected output.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum Checker {
    /// Byte-for-byte equality.
    Exact,
    /// Equality after trimming trailing whitespace on each line and at the end.
    ///
    /// The default, because a missing trailing newline is not a wrong answer and
    /// teaching someone otherwise is teaching them nothing.
    #[default]
    TrimmedLines,
    /// Whitespace-separated token comparison.
    Tokens,
    /// Numeric comparison with a tolerance.
    Float {
        /// Absolute tolerance.
        absolute: f64,
        /// Relative tolerance.
        relative: f64,
    },
    /// A checker program supplied by the package.
    ///
    /// Status: **PLANNED**. The format reserves the shape; the grader rejects it
    /// rather than silently accepting every submission.
    Custom {
        /// CID of the checker module in the data plane.
        module_cid: String,
    },
}

/// One test case.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TestCase {
    /// Stable identifier, unique within the package.
    pub id: String,
    /// Whether it may be shown to the submitter.
    pub visibility: Visibility,
    /// Bytes written to the program's stdin.
    pub stdin: String,
    /// Expected stdout.
    pub expected_stdout: String,
    /// Command-line arguments.
    #[serde(default)]
    pub args: Vec<String>,
    /// Group this case belongs to, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// Per-case limit overrides.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<Limits>,
}

/// A group of test cases, scored and short-circuited together.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Group {
    /// Group name, referenced by [`TestCase::group`].
    pub name: String,
    /// Points awarded when every case in the group passes.
    #[serde(default)]
    pub points: u32,
    /// Stop running this group at its first failure.
    #[serde(default = "default_true")]
    pub fail_fast: bool,
}

fn default_true() -> bool {
    true
}

/// The execution environment a package requires.
///
/// Recorded so a verdict can be reproduced later. A submission judged under a
/// different toolchain is not the same submission.
///
/// This is **not** the judge's own MSRV. It is the Rust version learners write
/// against, which is a product decision made in the content repository. The
/// judge binary currently requires a newer toolchain to build than the one it
/// compiles submissions with, and those two numbers move independently.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Environment {
    /// Opaque identifier, e.g. `"rust-1.88-wasm32-wasip1"`.
    pub id: String,
    /// Rust edition, e.g. `"2021"`.
    pub edition: String,
    /// Toolchain channel or exact version.
    pub toolchain: String,
    /// Target triple.
    pub target: String,
}

impl Default for Environment {
    fn default() -> Self {
        Self {
            id: "rust-1.88-wasm32-wasip1".into(),
            edition: "2021".into(),
            toolchain: "1.88".into(),
            target: "wasm32-wasip1".into(),
        }
    }
}

/// How a package is judged overall.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scoring {
    /// Every case must pass. The default for Trials.
    AllOrNothing,
    /// Points accumulate per passing group.
    GroupPoints,
}

/// Interaction mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Fixed stdin, compare stdout.
    #[default]
    Batch,
    /// Two-way conversation with a judge program.
    ///
    /// Status: **PLANNED**. Reserved so adding it later is not a format break.
    Interactive,
}

/// A complete Trial package.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrialPackage {
    /// Format version. Must equal [`FORMAT_VERSION`].
    pub format_version: u32,
    /// Trial slug, for diagnostics.
    pub slug: String,
    /// Trial content version.
    pub version: u32,
    /// Interaction mode.
    #[serde(default)]
    pub mode: Mode,
    /// Required environment.
    #[serde(default)]
    pub environment: Environment,
    /// Default limits, overridable per case.
    #[serde(default)]
    pub limits: Limits,
    /// Output comparison.
    #[serde(default)]
    pub checker: Checker,
    /// Overall scoring.
    pub scoring: Scoring,
    /// Stop at the first failing case across the whole package.
    #[serde(default = "default_true")]
    pub fail_fast: bool,
    /// Groups.
    #[serde(default)]
    pub groups: Vec<Group>,
    /// Test cases.
    pub tests: Vec<TestCase>,
}

impl TrialPackage {
    /// Validate structural and referential integrity.
    ///
    /// A malformed package is a **judge** error, never a compile error: the
    /// submitter did not write it and must never be blamed for it.
    pub fn validate(&self) -> Result<()> {
        let bad = |why: String| Err(JudgeError::MalformedPackage(why));

        if self.format_version != FORMAT_VERSION {
            return bad(format!(
                "format_version {} is not supported (expected {FORMAT_VERSION})",
                self.format_version
            ));
        }
        if self.slug.is_empty() {
            return bad("slug must not be empty".into());
        }
        if self.version == 0 {
            return bad("version must be at least 1".into());
        }
        if self.tests.is_empty() {
            return bad("a package must contain at least one test".into());
        }
        self.limits
            .validate()
            .map_err(|why| JudgeError::MalformedPackage(format!("package limits: {why}")))?;

        let mut seen = BTreeSet::new();
        let group_names: BTreeSet<&str> = self.groups.iter().map(|g| g.name.as_str()).collect();
        if group_names.len() != self.groups.len() {
            return bad("group names must be unique".into());
        }

        for test in &self.tests {
            if test.id.is_empty() {
                return bad("every test needs a non-empty id".into());
            }
            if !seen.insert(test.id.as_str()) {
                return bad(format!("duplicate test id `{}`", test.id));
            }
            if let Some(limits) = &test.limits {
                limits.validate().map_err(|why| {
                    JudgeError::MalformedPackage(format!("limits for test `{}`: {why}", test.id))
                })?;
            }
            if let Some(group) = &test.group {
                if !group_names.contains(group.as_str()) {
                    return bad(format!(
                        "test `{}` references unknown group `{group}`",
                        test.id
                    ));
                }
            }
        }

        if self.scoring == Scoring::GroupPoints && self.groups.is_empty() {
            return bad("group_points scoring requires at least one group".into());
        }
        if let Checker::Float { absolute, relative } = self.checker {
            if !absolute.is_finite() || !relative.is_finite() || absolute < 0.0 || relative < 0.0 {
                return bad("float tolerances must be finite and non-negative".into());
            }
        }
        if !self
            .tests
            .iter()
            .any(|t| t.visibility == Visibility::Public)
        {
            return bad("a package must expose at least one public test".into());
        }
        Ok(())
    }

    /// The limits that apply to `test`.
    pub fn limits_for(&self, test: &TestCase) -> Limits {
        test.limits.unwrap_or(self.limits)
    }

    /// A copy with every hidden test **removed**.
    ///
    /// This is what a non-trusted worker receives. The hidden cases are deleted
    /// rather than flagged, because a flag protects nothing once the bytes are
    /// on someone else's machine.
    pub fn public_only(&self) -> TrialPackage {
        let mut package = self.clone();
        package.tests.retain(|t| t.visibility == Visibility::Public);
        package
    }

    /// Tests in the order they should run: public first, so a failing
    /// submission gets the most actionable feedback soonest.
    pub fn ordered_tests(&self) -> Vec<&TestCase> {
        let mut tests: Vec<&TestCase> = self.tests.iter().collect();
        tests.sort_by_key(|t| (t.visibility, t.id.clone()));
        tests
    }

    /// Whether the package contains any hidden test.
    pub fn has_hidden_tests(&self) -> bool {
        self.tests
            .iter()
            .any(|t| t.visibility == Visibility::Hidden)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_case(id: &str, visibility: Visibility) -> TestCase {
        TestCase {
            id: id.into(),
            visibility,
            stdin: "1 2\n".into(),
            expected_stdout: "3\n".into(),
            args: vec![],
            group: None,
            limits: None,
        }
    }

    fn package() -> TrialPackage {
        TrialPackage {
            format_version: FORMAT_VERSION,
            slug: "ownership-move-or-borrow".into(),
            version: 1,
            mode: Mode::Batch,
            environment: Environment::default(),
            limits: Limits::default(),
            checker: Checker::TrimmedLines,
            scoring: Scoring::AllOrNothing,
            fail_fast: true,
            groups: vec![],
            tests: vec![
                test_case("public-1", Visibility::Public),
                test_case("hidden-1", Visibility::Hidden),
            ],
        }
    }

    #[test]
    fn a_well_formed_package_validates() {
        assert!(package().validate().is_ok());
    }

    #[test]
    fn public_only_deletes_hidden_tests_rather_than_flagging_them() {
        let public = package().public_only();
        assert!(!public.has_hidden_tests());
        assert_eq!(public.tests.len(), 1);

        // The serialised form a volunteer worker would receive must contain no
        // trace of the hidden case.
        let json = serde_json::to_string(&public).unwrap();
        assert!(!json.contains("hidden-1"), "hidden test id leaked: {json}");
        assert!(!json.contains("\"hidden\""), "hidden marker leaked: {json}");
    }

    #[test]
    fn a_malformed_package_is_a_judge_error_never_a_compile_error() {
        let mut p = package();
        p.tests.clear();
        let error = p.validate().unwrap_err();
        assert_eq!(error.verdict(), rustly_judge_common::Verdict::JudgeError);
    }

    #[test]
    fn rejects_an_unsupported_format_version() {
        let mut p = package();
        p.format_version = 99;
        assert!(p.validate().is_err());
    }

    #[test]
    fn rejects_duplicate_test_ids() {
        let mut p = package();
        p.tests.push(test_case("public-1", Visibility::Public));
        assert!(p
            .validate()
            .unwrap_err()
            .to_string()
            .contains("duplicate test id"));
    }

    #[test]
    fn rejects_a_test_referencing_an_unknown_group() {
        let mut p = package();
        p.tests[0].group = Some("nope".into());
        assert!(p
            .validate()
            .unwrap_err()
            .to_string()
            .contains("unknown group"));
    }

    #[test]
    fn rejects_duplicate_group_names() {
        let mut p = package();
        p.groups = vec![
            Group {
                name: "g".into(),
                points: 1,
                fail_fast: true,
            },
            Group {
                name: "g".into(),
                points: 2,
                fail_fast: true,
            },
        ];
        assert!(p.validate().is_err());
    }

    #[test]
    fn rejects_a_package_with_no_public_test() {
        let mut p = package();
        p.tests.retain(|t| t.visibility == Visibility::Hidden);
        assert!(p
            .validate()
            .unwrap_err()
            .to_string()
            .contains("at least one public test"));
    }

    #[test]
    fn rejects_limits_that_disable_a_bound() {
        let mut p = package();
        p.limits.fuel = 0;
        assert!(p.validate().is_err());

        let mut p = package();
        p.tests[0].limits = Some(Limits {
            memory_bytes: 0,
            ..Limits::default()
        });
        assert!(p.validate().unwrap_err().to_string().contains("public-1"));
    }

    #[test]
    fn rejects_nonsensical_float_tolerances() {
        for checker in [
            Checker::Float {
                absolute: f64::NAN,
                relative: 0.0,
            },
            Checker::Float {
                absolute: -1.0,
                relative: 0.0,
            },
            Checker::Float {
                absolute: 0.0,
                relative: f64::INFINITY,
            },
        ] {
            let mut p = package();
            p.checker = checker;
            assert!(p.validate().is_err());
        }
    }

    #[test]
    fn group_scoring_requires_groups() {
        let mut p = package();
        p.scoring = Scoring::GroupPoints;
        assert!(p.validate().is_err());
        p.groups = vec![Group {
            name: "g".into(),
            points: 10,
            fail_fast: true,
        }];
        p.tests[0].group = Some("g".into());
        assert!(p.validate().is_ok());
    }

    #[test]
    fn per_test_limits_override_package_limits() {
        let mut p = package();
        let tight = Limits {
            wall_ms: 50,
            ..Limits::default()
        };
        p.tests[0].limits = Some(tight);
        assert_eq!(p.limits_for(&p.tests[0]).wall_ms, 50);
        assert_eq!(p.limits_for(&p.tests[1]), Limits::default());
    }

    #[test]
    fn public_tests_run_before_hidden_ones() {
        let ordered = package();
        let ids: Vec<&str> = ordered
            .ordered_tests()
            .iter()
            .map(|t| t.id.as_str())
            .collect();
        assert_eq!(ids, ["public-1", "hidden-1"]);
    }

    #[test]
    fn a_package_round_trips_through_json_and_toml() {
        let p = package();
        let json = serde_json::to_string(&p).unwrap();
        assert_eq!(serde_json::from_str::<TrialPackage>(&json).unwrap(), p);

        let text = toml::to_string(&p).unwrap();
        assert_eq!(toml::from_str::<TrialPackage>(&text).unwrap(), p);
    }

    #[test]
    fn the_default_checker_forgives_trailing_whitespace() {
        assert_eq!(Checker::default(), Checker::TrimmedLines);
    }
}
