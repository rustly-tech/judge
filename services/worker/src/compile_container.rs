//! Sandboxed, dependency-free Rust compilation in a disposable container.
//!
//! Only a single UTF-8 `main.rs` enters the container. There is no Cargo
//! manifest, registry, dependency resolution, build script, or proc-macro
//! input. The container has no network, a read-only root, an unprivileged uid,
//! no capabilities, bounded CPU/memory/PIDs/files/output, and one writable
//! output directory. The caller pins the compiler image by digest.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rustly_judge_common::{JudgeError, Result};

use crate::compile::{CompileBackend, CompileOutput};

static NEXT_CONTAINER: AtomicU64 = AtomicU64::new(1);

/// Host-side bounds for one compiler container.
#[derive(Debug, Clone, Copy)]
pub struct CompilerLimits {
    /// Maximum submitted source size.
    pub source_bytes: usize,
    /// Maximum compiler stdout plus stderr retained.
    pub diagnostics_bytes: usize,
    /// Maximum produced WASI module size.
    pub artifact_bytes: usize,
    /// Wall-clock compilation limit.
    pub wall_time: Duration,
    /// Container memory ceiling.
    pub memory_bytes: u64,
    /// Container process ceiling.
    pub processes: u32,
    /// CPU cores available to the container.
    pub cpus: f32,
}

impl Default for CompilerLimits {
    fn default() -> Self {
        Self {
            source_bytes: 256 * 1024,
            diagnostics_bytes: 256 * 1024,
            artifact_bytes: 16 * 1024 * 1024,
            wall_time: Duration::from_secs(20),
            memory_bytes: 512 * 1024 * 1024,
            processes: 32,
            cpus: 1.0,
        }
    }
}

/// A direct-`rustc` compiler confined by Docker's OCI isolation controls.
#[derive(Debug, Clone)]
pub struct ContainerRustcCompiler {
    docker: PathBuf,
    image: String,
    environment_id: String,
    limits: CompilerLimits,
    active: Arc<Mutex<BTreeSet<String>>>,
}

impl ContainerRustcCompiler {
    /// Construct a compiler. `image` must be immutable (`name@sha256:...`).
    pub fn new(image: impl Into<String>, environment_id: impl Into<String>) -> Result<Self> {
        let image = image.into();
        let local_image_id = image.strip_prefix("sha256:").is_some_and(|digest| {
            digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
        });
        if !image.contains("@sha256:") && !local_image_id {
            return Err(JudgeError::SecurityPolicy(
                "compiler image must be pinned by sha256 digest".into(),
            ));
        }
        Ok(Self {
            docker: "docker".into(),
            image,
            environment_id: environment_id.into(),
            limits: CompilerLimits::default(),
            active: Arc::new(Mutex::new(BTreeSet::new())),
        })
    }

    /// Override limits, primarily for qualification tests.
    pub fn with_limits(mut self, limits: CompilerLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Override the Docker-compatible CLI path.
    pub fn with_docker(mut self, docker: impl Into<PathBuf>) -> Self {
        self.docker = docker.into();
        self
    }

    /// Force-remove every compiler container currently owned by this worker.
    ///
    /// Worker shutdown and request cancellation call this so descendants do not
    /// outlive the work that created them.
    pub fn cancel_all(&self) {
        let names = self
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        for name in names {
            self.force_remove(&name);
        }
    }

    fn arguments(&self, name: &str, input: &Path, output: &Path) -> Vec<OsString> {
        let source_mount = format!(
            "type=bind,src={},dst=/input/main.rs,readonly",
            input.display()
        );
        let output_mount = format!("type=bind,src={},dst=/output", output.display());
        vec![
            "run".into(),
            "--rm".into(),
            "--name".into(),
            name.into(),
            "--network".into(),
            "none".into(),
            "--read-only".into(),
            "--cap-drop".into(),
            "ALL".into(),
            "--security-opt".into(),
            "no-new-privileges".into(),
            "--user".into(),
            "65532:65532".into(),
            "--pids-limit".into(),
            self.limits.processes.to_string().into(),
            "--memory".into(),
            self.limits.memory_bytes.to_string().into(),
            "--memory-swap".into(),
            self.limits.memory_bytes.to_string().into(),
            "--cpus".into(),
            self.limits.cpus.to_string().into(),
            "--ulimit".into(),
            "nofile=64:64".into(),
            "--ulimit".into(),
            format!("cpu={0}:{0}", self.limits.wall_time.as_secs().max(1)).into(),
            "--ulimit".into(),
            format!("fsize={0}:{0}", self.limits.artifact_bytes).into(),
            "--tmpfs".into(),
            "/tmp:rw,nosuid,nodev,noexec,size=16777216,mode=1777".into(),
            "--mount".into(),
            source_mount.into(),
            "--mount".into(),
            output_mount.into(),
            "--env".into(),
            "RUST_BACKTRACE=0".into(),
            self.image.clone().into(),
            "--crate-name".into(),
            "submission".into(),
            "--crate-type".into(),
            "bin".into(),
            "--edition".into(),
            "2021".into(),
            "--target".into(),
            "wasm32-wasip1".into(),
            "-C".into(),
            "opt-level=1".into(),
            "-C".into(),
            "debuginfo=0".into(),
            "-A".into(),
            "unused".into(),
            "-o".into(),
            "/output/submission.wasm".into(),
            "/input/main.rs".into(),
        ]
    }

    fn force_remove(&self, name: &str) {
        let _ = Command::new(&self.docker)
            .args(["rm", "--force", name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

struct ContainerGuard<'a> {
    compiler: &'a ContainerRustcCompiler,
    name: String,
    armed: bool,
}

impl Drop for ContainerGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.compiler.force_remove(&self.name);
        }
        self.compiler
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.name);
    }
}

fn capture<R: Read + Send + 'static>(
    mut reader: R,
    limit: usize,
) -> std::thread::JoinHandle<(Vec<u8>, bool)> {
    std::thread::spawn(move || {
        let mut kept = Vec::with_capacity(limit.min(64 * 1024));
        let mut buffer = [0_u8; 8192];
        let mut overflow = false;
        while let Ok(count) = reader.read(&mut buffer) {
            if count == 0 {
                break;
            }
            let remaining = limit.saturating_sub(kept.len());
            kept.extend_from_slice(&buffer[..count.min(remaining)]);
            overflow |= count > remaining;
        }
        (kept, overflow)
    })
}

impl CompileBackend for ContainerRustcCompiler {
    fn id(&self) -> &'static str {
        "container-rustc-wasm32-wasip1"
    }

    fn is_qualified_for_untrusted_code(&self) -> bool {
        true
    }

    fn compile(&self, source: &[u8], environment_id: &str) -> Result<CompileOutput> {
        if environment_id != self.environment_id {
            return Err(JudgeError::MalformedPackage(format!(
                "compiler is pinned for {}, not {environment_id}",
                self.environment_id
            )));
        }
        if source.len() > self.limits.source_bytes {
            return Err(JudgeError::SecurityPolicy(format!(
                "source is {} bytes; compiler limit is {} bytes",
                source.len(),
                self.limits.source_bytes
            )));
        }
        if std::str::from_utf8(source).is_err() {
            return Ok(CompileOutput::Failed {
                diagnostics: "error: source is not valid UTF-8".into(),
            });
        }

        let scratch = tempfile::tempdir().map_err(|error| {
            JudgeError::Infrastructure(format!("create compiler scratch directory: {error}"))
        })?;
        let input = scratch.path().join("main.rs");
        let output = scratch.path().join("output");
        std::fs::create_dir(&output).map_err(|error| {
            JudgeError::Infrastructure(format!("create compiler output directory: {error}"))
        })?;
        std::fs::write(&input, source).map_err(|error| {
            JudgeError::Infrastructure(format!("write compiler input: {error}"))
        })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(scratch.path(), std::fs::Permissions::from_mode(0o755))
                .map_err(|error| {
                    JudgeError::Infrastructure(format!(
                        "make compiler scratch directory traversable: {error}"
                    ))
                })?;
            std::fs::set_permissions(&input, std::fs::Permissions::from_mode(0o444)).map_err(
                |error| JudgeError::Infrastructure(format!("protect compiler input: {error}")),
            )?;
            std::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o777)).map_err(
                |error| JudgeError::Infrastructure(format!("prepare compiler output: {error}")),
            )?;
        }

        let ordinal = NEXT_CONTAINER.fetch_add(1, Ordering::Relaxed);
        let name = format!("rustly-compile-{}-{ordinal}", std::process::id());
        self.active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(name.clone());
        let mut command = Command::new(&self.docker);
        command
            .args(self.arguments(&name, &input, &output))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut guard = ContainerGuard {
            compiler: self,
            name,
            armed: true,
        };
        let mut child = command.spawn().map_err(|error| {
            JudgeError::Infrastructure(format!("start compiler container: {error}"))
        })?;
        let stdout = capture(
            child.stdout.take().expect("stdout was piped"),
            self.limits.diagnostics_bytes,
        );
        let stderr = capture(
            child.stderr.take().expect("stderr was piped"),
            self.limits.diagnostics_bytes,
        );
        let started = Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait().map_err(|error| {
                JudgeError::Infrastructure(format!("wait for compiler container: {error}"))
            })? {
                break status;
            }
            if started.elapsed() >= self.limits.wall_time {
                self.force_remove(&guard.name);
                let _ = child.kill();
                let _ = child.wait();
                guard.armed = false;
                return Err(JudgeError::SecurityPolicy(
                    "compilation exceeded its wall-clock limit".into(),
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        guard.armed = false;
        let (stdout, stdout_overflow) = stdout
            .join()
            .map_err(|_| JudgeError::Infrastructure("compiler stdout reader panicked".into()))?;
        let (stderr, stderr_overflow) = stderr
            .join()
            .map_err(|_| JudgeError::Infrastructure("compiler stderr reader panicked".into()))?;
        if stdout_overflow || stderr_overflow {
            return Err(JudgeError::SecurityPolicy(
                "compiler diagnostics exceeded the output limit".into(),
            ));
        }
        let mut diagnostics = stderr;
        diagnostics.extend_from_slice(&stdout);
        let diagnostics = String::from_utf8_lossy(&diagnostics).into_owned();
        // rustc/LLVM can catch SIGXFSZ and exit with an ordinary non-zero
        // status. Treat evidence that the output file limit fired as a policy
        // event so it is never reported to a learner as a compile error.
        let artifact = output.join("submission.wasm");
        let hit_artifact_limit = std::fs::metadata(&artifact)
            .is_ok_and(|metadata| metadata.len() >= self.limits.artifact_bytes as u64)
            || diagnostics.to_ascii_lowercase().contains("file too large")
            || diagnostics.to_ascii_lowercase().contains("os error 27");
        if hit_artifact_limit {
            return Err(JudgeError::SecurityPolicy(format!(
                "compiled artifact reached the {} byte output limit",
                self.limits.artifact_bytes
            )));
        }
        if status.code().is_some_and(|code| code >= 125) {
            return Err(JudgeError::Infrastructure(format!(
                "compiler container failed to start: {}",
                diagnostics.trim()
            )));
        }
        if !status.success() {
            return Ok(CompileOutput::Failed { diagnostics });
        }

        let metadata = std::fs::metadata(&artifact).map_err(|error| {
            JudgeError::Infrastructure(format!("compiler produced no WASI artifact: {error}"))
        })?;
        if metadata.len() > self.limits.artifact_bytes as u64 {
            return Err(JudgeError::SecurityPolicy(format!(
                "compiled artifact is {} bytes; limit is {} bytes",
                metadata.len(),
                self.limits.artifact_bytes
            )));
        }
        let bytes = std::fs::read(&artifact).map_err(|error| {
            JudgeError::Infrastructure(format!("read compiled WASI artifact: {error}"))
        })?;
        if !bytes.starts_with(b"\0asm") {
            return Err(JudgeError::Infrastructure(
                "compiler output is not a WebAssembly module".into(),
            ));
        }
        Ok(CompileOutput::Module {
            bytes,
            diagnostics: (!diagnostics.trim().is_empty()).then_some(diagnostics),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compiler() -> ContainerRustcCompiler {
        ContainerRustcCompiler::new(
            "ghcr.io/rustly-tech/compiler@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "rust-1.88-wasm32-wasip1",
        )
        .unwrap()
    }

    #[test]
    fn image_must_be_immutable() {
        assert!(ContainerRustcCompiler::new("rust:1.88", "environment").is_err());
    }

    #[test]
    fn invocation_contains_every_host_boundary() {
        let args = compiler().arguments("job", Path::new("/in.rs"), Path::new("/out"));
        let joined = args
            .iter()
            .map(|value| value.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ");
        for required in [
            "--network none",
            "--read-only",
            "--cap-drop ALL",
            "--security-opt no-new-privileges",
            "--user 65532:65532",
            "--pids-limit 32",
            "--memory 536870912",
            "--memory-swap 536870912",
            "--cpus 1",
            "nofile=64:64",
            "cpu=20:20",
            "/tmp:rw,nosuid,nodev,noexec,size=16777216,mode=1777",
            "readonly",
            "wasm32-wasip1",
        ] {
            assert!(joined.contains(required), "missing {required}: {joined}");
        }
        assert!(!joined.contains("cargo"));
    }

    #[test]
    fn huge_and_malformed_source_fail_before_starting_a_container() {
        let tiny = compiler().with_limits(CompilerLimits {
            source_bytes: 4,
            ..CompilerLimits::default()
        });
        assert!(matches!(
            tiny.compile(b"12345", "rust-1.88-wasm32-wasip1"),
            Err(JudgeError::SecurityPolicy(_))
        ));
        assert!(matches!(
            tiny.compile(&[0xff], "rust-1.88-wasm32-wasip1"),
            Ok(CompileOutput::Failed { .. })
        ));
    }
}
