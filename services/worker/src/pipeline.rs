//! The judging pipeline: resolve, compile, grade, report.

use rustly_grader::{compile_error, grade, manifest_for_error, GradeRequest};
use rustly_judge_cache::{ArtifactCache, Trust};
use rustly_judge_common::{JudgeError, Result, Verdict};
use rustly_judge_protocol::{JobSpec, ResultManifest, TrustClass};
use rustly_problem_format::TrialPackage;
use rustly_sandbox::ExecutionBackend;

use crate::artifacts::ArtifactSource;
use crate::compile::{CompileBackend, CompileOutput};

/// Everything the worker needs to judge one job.
pub struct JobContext<'a> {
    /// Where CIDs are resolved.
    pub artifacts: &'a dyn ArtifactSource,
    /// How source becomes a module.
    pub compiler: &'a dyn CompileBackend,
    /// How a module is executed.
    pub sandbox: &'a dyn ExecutionBackend,
    /// Optional compiled-artifact cache.
    pub cache: Option<&'a ArtifactCache>,
    /// This worker's trust class, from its credential.
    pub trust_class: TrustClass,
    /// This worker's identifier.
    pub worker_id: &'a str,
}

/// The result of judging one job.
#[derive(Debug, Clone)]
pub struct JobReport {
    /// The full manifest, for the data plane.
    pub manifest: ResultManifest,
    /// A copy safe to show the submitter.
    pub redacted: ResultManifest,
}

impl JobReport {
    fn new(manifest: ResultManifest) -> Self {
        let redacted = manifest.redacted_for_submitter();
        Self { manifest, redacted }
    }

    /// The verdict.
    pub fn verdict(&self) -> Verdict {
        self.manifest.verdict
    }
}

/// Judge one job end to end.
///
/// Returns `Err` only when the job should be **retried** - the queue was
/// unreachable, an artifact could not be resolved, a cache entry was corrupt.
/// Anything that is a statement about the submission comes back as a
/// [`JobReport`] with the appropriate verdict.
pub fn run_job(context: &JobContext<'_>, spec: &JobSpec) -> Result<JobReport> {
    if !context.compiler.is_qualified_for_untrusted_code() {
        return Err(JudgeError::SecurityPolicy(format!(
            "compiler backend {} is not qualified for submitted source",
            context.compiler.id()
        )));
    }

    // 1. Refuse a job this worker must not accept. Checked here as well as at
    //    the broker: a worker that would leak hidden tests should refuse even
    //    when the broker gets it wrong.
    spec.validate(context.trust_class).map_err(|why| {
        JudgeError::SecurityPolicy(format!("refusing job {}: {why}", spec.job_id))
    })?;

    // 2. Resolve inputs. A failure here is infrastructure, never the user's.
    let package_bytes = context.artifacts.fetch(&spec.trial_package_cid)?;
    let package: TrialPackage = serde_json::from_slice(&package_bytes).map_err(|e| {
        JudgeError::MalformedPackage(format!(
            "package {} is not valid JSON: {e}",
            spec.trial_package_cid
        ))
    })?;
    package.validate()?;

    // 3. A worker not entitled to hidden tests must not hold them even if the
    //    package it fetched contains them.
    let package = if spec.includes_hidden_tests {
        package
    } else {
        package.public_only()
    };
    if package.has_hidden_tests() && !context.trust_class.may_receive_hidden_tests() {
        return Err(JudgeError::SecurityPolicy(
            "package still contains hidden tests after filtering".into(),
        ));
    }

    if package.environment.id != spec.environment_id {
        return Err(JudgeError::MalformedPackage(format!(
            "job asks for environment {} but the package declares {}",
            spec.environment_id, package.environment.id
        )));
    }

    let source = context.artifacts.fetch(&spec.source_cid)?;

    // 4. Compile once. A cached artifact is an accelerator: a miss or a corrupt
    //    entry costs time, never correctness.
    let started = std::time::Instant::now();
    let cache_key = artifact_key(
        &spec.source_cid,
        &spec.environment_id,
        context.compiler.id(),
    );

    let mut used_cached_artifact = false;
    let cached = match context
        .cache
        .map(|cache| cache.get_build(&cache_key, Trust::Verified))
    {
        Some(Ok(entry)) => entry,
        Some(Err(error)) => {
            // The cache is disposable: log, discard, rebuild.
            tracing::warn!(%error, job_id = %spec.job_id, "ignoring a corrupt cache entry");
            None
        }
        None => None,
    };

    let compiled = match cached {
        Some(bytes) => {
            used_cached_artifact = true;
            CompileOutput::Module {
                bytes,
                diagnostics: None,
            }
        }
        None => context.compiler.compile(&source, &spec.environment_id)?,
    };
    let compile_ms = started.elapsed().as_millis() as u64;

    let (module, diagnostics) = match compiled {
        CompileOutput::Failed { diagnostics } => {
            return Ok(JobReport::new(compile_error(
                &spec.job_id,
                &spec.trial_package_cid,
                &package,
                diagnostics,
                compile_ms,
            )));
        }
        CompileOutput::Module { bytes, diagnostics } => (bytes, diagnostics),
    };

    if !used_cached_artifact {
        if let Some(cache) = context.cache {
            // An artifact built by a non-trusted worker is quarantined until
            // trusted capacity reproduces it.
            let trust = if context.trust_class.requires_artifact_quarantine() {
                Trust::Quarantined
            } else {
                Trust::Verified
            };
            if let Err(error) = cache.put_build(&cache_key, &module, trust) {
                tracing::warn!(%error, "could not cache the compiled artifact");
            }
        }
    }

    // 5. Run many.
    let manifest = match grade(
        context.sandbox,
        GradeRequest {
            job_id: &spec.job_id,
            trial_package_cid: &spec.trial_package_cid,
            module: &module,
            package: &package,
            compiler_diagnostics: diagnostics,
            compile_ms,
            used_cached_artifact,
        },
    ) {
        Ok(manifest) => manifest,
        Err(error) if error.is_retryable() => return Err(error),
        Err(error) => manifest_for_error(&spec.job_id, &spec.trial_package_cid, &package, &error),
    };

    Ok(JobReport::new(manifest))
}

/// The cache key for a compiled artifact.
///
/// Includes the environment and the compiler identity, not just the source: the
/// same source compiled by a different toolchain is a different artifact, and
/// serving one for the other would be a silent correctness bug.
pub fn artifact_key(source_cid: &str, environment_id: &str, compiler_id: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"rustly-artifact-v1\0");
    hasher.update(source_cid.as_bytes());
    hasher.update(b"\0");
    hasher.update(environment_id.as_bytes());
    hasher.update(b"\0");
    hasher.update(compiler_id.as_bytes());
    format!("b3:{}", hasher.finalize().to_hex())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_artifact_key_separates_toolchains_and_compilers() {
        let base = artifact_key("b3:source", "rust-1.88-wasm32-wasip1", "cargo");
        assert_ne!(
            base,
            artifact_key("b3:other", "rust-1.88-wasm32-wasip1", "cargo")
        );
        assert_ne!(
            base,
            artifact_key("b3:source", "rust-1.90-wasm32-wasip1", "cargo"),
            "a different toolchain must not reuse an artifact"
        );
        assert_ne!(
            base,
            artifact_key("b3:source", "rust-1.88-wasm32-wasip1", "precompiled"),
            "a different compiler must not reuse an artifact"
        );
        assert_eq!(
            base,
            artifact_key("b3:source", "rust-1.88-wasm32-wasip1", "cargo")
        );
        assert!(rustly_judge_cache::is_cid(&base));
    }

    #[test]
    fn the_key_is_not_trivially_confusable_by_field_concatenation() {
        // "ab" + "c" must not collide with "a" + "bc".
        assert_ne!(artifact_key("ab", "c", "x"), artifact_key("a", "bc", "x"));
    }
}
