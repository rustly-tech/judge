//! Resource limits and the violations they produce.
//!
//! Five independent bounds, each with its own verdict. Wall-clock alone is not
//! a fair limit across heterogeneous workers - a slow volunteer machine would
//! fail submissions a fast one accepts - so an abstract work bound (Wasmtime
//! fuel) runs alongside it. Fuel is deterministic; wall-clock is the backstop
//! for time spent outside the guest.

use serde::{Deserialize, Serialize};

/// Bounds enforced by the sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limits {
    /// Wall-clock limit for one execution, milliseconds.
    pub wall_ms: u64,
    /// Linear-memory limit, bytes.
    pub memory_bytes: u64,
    /// Combined stdout + stderr limit, bytes.
    pub output_bytes: u64,
    /// Abstract work bound, host-speed independent.
    pub fuel: u64,
    /// Maximum guest table elements, bounding indirect-call table growth.
    pub table_elements: u64,
    /// Maximum concurrent guest instances.
    pub instances: u64,
}

impl Default for Limits {
    /// Defaults used by the first vertical slice.
    fn default() -> Self {
        Self {
            wall_ms: 2_000,
            memory_bytes: 64 * 1024 * 1024,
            output_bytes: 256 * 1024,
            fuel: 500_000_000,
            table_elements: 10_000,
            instances: 1,
        }
    }
}

impl Limits {
    /// A deliberately tiny limit set, for tests that must trip a bound quickly.
    pub const fn tiny() -> Self {
        Self {
            wall_ms: 500,
            memory_bytes: 2 * 1024 * 1024,
            output_bytes: 1024,
            fuel: 100_000,
            table_elements: 128,
            instances: 1,
        }
    }

    /// Reject a limit set that would disable a bound.
    ///
    /// A package with `fuel: 0` or `memory_bytes: 0` is malformed, not
    /// "unlimited". Refusing it here is what stops an unbounded execution from
    /// being introduced by a content mistake.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.wall_ms == 0 {
            return Err("wall_ms must be greater than zero");
        }
        if self.memory_bytes == 0 {
            return Err("memory_bytes must be greater than zero");
        }
        if self.output_bytes == 0 {
            return Err("output_bytes must be greater than zero");
        }
        if self.fuel == 0 {
            return Err("fuel must be greater than zero");
        }
        if self.instances == 0 {
            return Err("instances must be greater than zero");
        }
        Ok(())
    }
}

/// Which bound was exceeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LimitViolation {
    /// Wall-clock limit.
    Wall,
    /// Work bound (fuel).
    Fuel,
    /// Memory limit.
    Memory,
    /// Output limit.
    Output,
}

impl LimitViolation {
    /// The verdict for this violation.
    pub const fn verdict(self) -> crate::verdict::Verdict {
        match self {
            // Both time-shaped bounds report TLE: from the user's point of view
            // the program did not finish in the allowed budget.
            Self::Wall | Self::Fuel => crate::verdict::Verdict::TimeLimitExceeded,
            Self::Memory => crate::verdict::Verdict::MemoryLimitExceeded,
            Self::Output => crate::verdict::Verdict::OutputLimitExceeded,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verdict::Verdict;

    #[test]
    fn defaults_bound_every_dimension() {
        let l = Limits::default();
        assert!(l.validate().is_ok());
        for value in [
            l.wall_ms,
            l.memory_bytes,
            l.output_bytes,
            l.fuel,
            l.instances,
        ] {
            assert!(value > 0);
        }
    }

    #[test]
    fn a_zero_bound_is_malformed_not_unlimited() {
        for mutate in [
            (|l: &mut Limits| l.wall_ms = 0) as fn(&mut Limits),
            |l| l.memory_bytes = 0,
            |l| l.output_bytes = 0,
            |l| l.fuel = 0,
            |l| l.instances = 0,
        ] {
            let mut limits = Limits::default();
            mutate(&mut limits);
            assert!(
                limits.validate().is_err(),
                "a zeroed bound must be rejected"
            );
        }
    }

    #[test]
    fn each_violation_maps_to_its_own_verdict() {
        assert_eq!(LimitViolation::Wall.verdict(), Verdict::TimeLimitExceeded);
        assert_eq!(LimitViolation::Fuel.verdict(), Verdict::TimeLimitExceeded);
        assert_eq!(
            LimitViolation::Memory.verdict(),
            Verdict::MemoryLimitExceeded
        );
        assert_eq!(
            LimitViolation::Output.verdict(),
            Verdict::OutputLimitExceeded
        );
    }

    #[test]
    fn no_violation_is_ever_a_system_fault() {
        for v in [
            LimitViolation::Wall,
            LimitViolation::Fuel,
            LimitViolation::Memory,
            LimitViolation::Output,
        ] {
            assert!(
                !v.verdict().is_retryable(),
                "{v:?} is the user's program, not our failure"
            );
        }
    }

    #[test]
    fn tiny_limits_are_valid_and_smaller_than_the_defaults() {
        let tiny = Limits::tiny();
        assert!(tiny.validate().is_ok());
        assert!(tiny.fuel < Limits::default().fuel);
        assert!(tiny.memory_bytes < Limits::default().memory_bytes);
    }
}
