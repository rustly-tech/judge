//! The Rustly judge worker binary.
//!
//! Two modes:
//!
//! * `run-local` - judge one job from local files. No network, no broker. This
//!   is what CI uses to prove the pipeline end to end, and what you use to
//!   reproduce a verdict on your own machine.
//! * `serve` - lease jobs from a broker, judge them, report results.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context as _};
use clap::{Parser, Subcommand};
use rustly_judge_cache::ArtifactCache;
use rustly_judge_common::Limits;
use rustly_judge_protocol::{Backend, JobSpec, ResultSummary, TrustClass, PROTOCOL_VERSION};
use rustly_judge_worker::compile::{CompileBackend, PrecompiledModule};
use rustly_judge_worker::pipeline::JobContext;
use rustly_judge_worker::{run_job, ArtifactSource, ContainerRustcCompiler, LocalArtifacts};
use rustly_sandbox::WasmtimeBackend;
use serde::{Deserialize, Serialize};

#[derive(Debug, Parser)]
#[command(
    name = "rustly-judge-worker",
    version,
    about = "The Rustly judge worker"
)]
struct Args {
    /// Emit JSON logs.
    #[arg(long, env = "RUSTLY_LOG_FORMAT", global = true)]
    json_logs: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Judge one job from local files and print the result manifest.
    RunLocal {
        /// Directory of artifacts named by CID.
        #[arg(long)]
        artifacts: PathBuf,
        /// CID of the Trial package.
        #[arg(long)]
        package: String,
        /// CID of the submitted source.
        #[arg(long)]
        source: String,
        /// Trust class to judge as.
        #[arg(long, value_parser = parse_trust, default_value = "trusted")]
        trust: TrustClass,
        /// Include hidden tests. Only meaningful for a trusted worker.
        #[arg(long)]
        hidden: bool,
        /// Print the submitter-safe manifest instead of the full one.
        #[arg(long)]
        redacted: bool,
        /// Immutable compiler image for raw Rust source. Omit for precompiled WASM.
        #[arg(long)]
        compiler_image: Option<String>,
    },

    /// Store files in an artifact directory and print their CIDs.
    ///
    /// The judge addresses everything by content, so this is how a package and a
    /// module get into a local artifact directory in the first place.
    Seed {
        /// Directory to write into.
        #[arg(long)]
        artifacts: PathBuf,
        /// Files to store.
        #[arg(required = true)]
        files: Vec<PathBuf>,
    },

    /// Lease jobs from a broker and judge them.
    Serve {
        /// Broker base URL, e.g. `http://127.0.0.1:8090`.
        #[arg(long, env = "RUSTLY_BROKER_URL")]
        broker: String,
        /// Directory of artifacts named by CID.
        #[arg(long, env = "RUSTLY_ARTIFACTS")]
        artifacts: PathBuf,
        /// Compiled-artifact cache directory.
        #[arg(long, env = "RUSTLY_CACHE")]
        cache: Option<PathBuf>,
        /// This worker's identifier.
        #[arg(long, env = "RUSTLY_WORKER_ID")]
        worker_id: String,
        /// Trust class to declare.
        #[arg(long, value_parser = parse_trust, default_value = "volunteer")]
        trust: TrustClass,
        /// Jobs to lease at a time.
        #[arg(long, default_value_t = 1)]
        capacity: u32,
        /// Immutable compiler image (`name@sha256:...`) for submitted Rust.
        #[arg(long, env = "RUSTLY_COMPILER_IMAGE")]
        compiler_image: Option<String>,
    },
}

fn parse_trust(value: &str) -> Result<TrustClass, String> {
    match value {
        "volunteer" => Ok(TrustClass::Volunteer),
        "community" => Ok(TrustClass::Community),
        "trusted" => Ok(TrustClass::Trusted),
        other => Err(format!("unknown trust class {other:?}")),
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct LeaseRequest {
    protocol_version: u32,
    worker_id: String,
    trust_class: TrustClass,
    capacity: u32,
}

#[derive(Debug, Deserialize)]
struct LeaseResponse {
    jobs: Vec<JobSpec>,
    poll_after_seconds: u32,
}

// Deliberately not `#[tokio::main]`.
//
// The sandbox is synchronous, and WASI preview 1 blocks internally. Calling it
// from a thread that is driving an async executor panics with "cannot start a
// runtime from within a runtime". `run-local` therefore runs with no runtime at
// all, and `serve` confines every execution to `spawn_blocking`.
fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    if args.json_logs {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(filter)
            .init();
    } else {
        tracing_subscriber::fmt()
            .compact()
            .with_env_filter(filter)
            .init();
    }

    match args.command {
        Command::RunLocal {
            artifacts,
            package,
            source,
            trust,
            hidden,
            redacted,
            compiler_image,
        } => {
            let artifacts = LocalArtifacts::new(artifacts);
            let sandbox = WasmtimeBackend::new().context("building the sandbox")?;

            // The environment, version, and limits are properties of the
            // package; reading them from there keeps a local run identical to a
            // brokered one.
            let spec = align_with_package(
                &artifacts,
                JobSpec {
                    protocol_version: PROTOCOL_VERSION,
                    job_id: "local".into(),
                    source_cid: source,
                    trial_package_cid: package,
                    trial_version: 0,
                    environment_id: String::new(),
                    limits: Limits::default(),
                    backend: Backend::Wasmtime,
                    includes_hidden_tests: hidden && trust.may_receive_hidden_tests(),
                },
            )?;

            let container = compiler_image
                .map(|image| ContainerRustcCompiler::new(image, &spec.environment_id))
                .transpose()
                .map_err(|error| anyhow::anyhow!("{error}"))?;
            let precompiled = PrecompiledModule;
            let compiler: &dyn CompileBackend = container
                .as_ref()
                .map_or(&precompiled, |value| value as &dyn CompileBackend);
            let context = JobContext {
                artifacts: &artifacts,
                compiler,
                sandbox: &sandbox,
                cache: None,
                trust_class: trust,
                worker_id: "local",
            };

            let report = run_job(&context, &spec).map_err(|e| anyhow::anyhow!("{e}"))?;
            let manifest = if redacted {
                &report.redacted
            } else {
                &report.manifest
            };
            println!("{}", serde_json::to_string_pretty(manifest)?);

            // A non-zero exit for a non-accepted verdict makes this usable as a
            // CI assertion without any extra scripting.
            if report.verdict() != rustly_judge_common::Verdict::Accepted {
                bail!("verdict: {}", report.verdict());
            }
        }

        Command::Seed { artifacts, files } => {
            let store = LocalArtifacts::new(&artifacts);
            for file in files {
                let bytes =
                    std::fs::read(&file).with_context(|| format!("reading {}", file.display()))?;
                let cid = store.put(&bytes).map_err(|e| anyhow::anyhow!("{e}"))?;
                println!("{cid}\t{}", file.display());
            }
        }

        Command::Serve {
            broker,
            artifacts,
            cache,
            worker_id,
            trust,
            capacity,
            compiler_image,
        } => {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .context("building the async runtime")?;
            runtime.block_on(serve(
                broker,
                artifacts,
                cache,
                worker_id,
                trust,
                capacity,
                compiler_image,
            ))?;
        }
    }
    Ok(())
}

/// Lease, judge, and report in a loop.
#[allow(clippy::too_many_arguments)]
async fn serve(
    broker: String,
    artifacts: PathBuf,
    cache: Option<PathBuf>,
    worker_id: String,
    trust: TrustClass,
    capacity: u32,
    compiler_image: Option<String>,
) -> anyhow::Result<()> {
    {
        let artifacts = Arc::new(LocalArtifacts::new(artifacts));
        let sandbox = WasmtimeBackend::new().context("building the sandbox")?;
        let cache = cache
            .map(ArtifactCache::open)
            .transpose()
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .context("building the HTTP client")?;
        let container = compiler_image
            .map(|image| {
                ContainerRustcCompiler::new(image, "rust-1.88-wasm32-wasip1")
                    .map_err(|error| anyhow::anyhow!("{error}"))
            })
            .transpose()?;
        if let Some(cleanup) = container.clone() {
            tokio::spawn(async move {
                wait_for_shutdown().await;
                cleanup.cancel_all();
                std::process::exit(130);
            });
        }
        let precompiled = PrecompiledModule;
        let compiler: &dyn CompileBackend = container
            .as_ref()
            .map_or(&precompiled, |value| value as &dyn CompileBackend);

        tracing::info!(%worker_id, ?trust, %broker, "worker starting");
        if trust == TrustClass::Trusted {
            tracing::warn!(
                "declaring the trusted class: this worker may receive hidden tests and must \
                     run on operator-controlled infrastructure"
            );
        }

        loop {
            let leased: LeaseResponse = client
                .post(format!("{broker}/api/v1/judge/leases"))
                .json(&LeaseRequest {
                    protocol_version: PROTOCOL_VERSION,
                    worker_id: worker_id.clone(),
                    trust_class: trust,
                    capacity,
                })
                .send()
                .await
                .context("leasing")?
                .error_for_status()
                .context("leasing")?
                .json()
                .await
                .context("decoding the lease response")?;

            if leased.jobs.is_empty() {
                tokio::time::sleep(Duration::from_secs(leased.poll_after_seconds.max(1) as u64))
                    .await;
                continue;
            }

            for spec in leased.jobs {
                let context = JobContext {
                    artifacts: artifacts.as_ref(),
                    compiler,
                    sandbox: &sandbox,
                    cache: cache.as_ref(),
                    trust_class: trust,
                    worker_id: &worker_id,
                };

                // `block_in_place` because the sandbox is synchronous and
                // WASI blocks internally. Running it directly on an async
                // worker thread panics; running it here also stops one
                // runaway submission from stalling the whole runtime.
                let judged = tokio::task::block_in_place(|| run_job(&context, &spec));

                let summary: ResultSummary = match judged {
                    Ok(report) => {
                        tracing::info!(
                            job_id = %spec.job_id,
                            verdict = %report.verdict(),
                            "judged"
                        );
                        report.manifest.summary(&worker_id)
                    }
                    Err(error) => {
                        // Retryable failures are reported honestly as JE/IE
                        // rather than dressed up as a user verdict.
                        tracing::warn!(job_id = %spec.job_id, %error, "job failed");
                        ResultSummary {
                            protocol_version: PROTOCOL_VERSION,
                            worker_id: worker_id.clone(),
                            verdict: error.verdict(),
                            result_manifest_hash: String::new(),
                            peak_memory_bytes: 0,
                            execution_ms: 0,
                            compile_ms: 0,
                            used_cached_artifact: false,
                        }
                    }
                };

                let response = client
                    .post(format!("{broker}/api/v1/judge/jobs/{}/result", spec.job_id))
                    .json(&summary)
                    .send()
                    .await;
                if let Err(error) = response {
                    tracing::error!(job_id = %spec.job_id, %error, "could not report a result");
                }
            }
        }
    }
}

async fn wait_for_shutdown() {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = terminate.recv() => {},
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// Read the package to fill in the fields the job spec must agree with.
fn align_with_package(artifacts: &LocalArtifacts, mut spec: JobSpec) -> anyhow::Result<JobSpec> {
    let bytes = artifacts
        .fetch(&spec.trial_package_cid)
        .map_err(|e| anyhow::anyhow!("resolving the package: {e}"))?;
    let package: rustly_problem_format::TrialPackage =
        serde_json::from_slice(&bytes).context("parsing the package")?;
    spec.environment_id = package.environment.id.clone();
    spec.trial_version = package.version;
    spec.limits = package.limits;
    Ok(spec)
}
