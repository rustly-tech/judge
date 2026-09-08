//! Shared primitives for the Rustly judge.
//!
//! The single most important rule in this crate: **an infrastructure or cache
//! failure is never reported as a user error.** `JE`, `IE`, and `SE` are a
//! separate class from `CE`/`WA`/`TLE`, and the type system is arranged so that
//! turning one into the other requires writing it out deliberately.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod error;
pub mod limits;
pub mod verdict;

pub use error::{JudgeError, Result};
pub use limits::{LimitViolation, Limits};
pub use verdict::{Verdict, VerdictClass};
