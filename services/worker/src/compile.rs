//! Compilation.
//!
//! # Why this is a separate security domain
//!
//! Compiling untrusted Rust **is running untrusted code**. Cargo executes
//! `build.rs` at build time and expands procedural macros inside the compiler
//! process, both of which are arbitrary native code written by the submitter.
//! Nothing about the execution sandbox protects the compile step, because the
//! compile step happens before there is a `.wasm` module to sandbox.
//!
//! We therefore treat the two as different domains with different maturity:
//!
//! | Backend | Status | Safe for untrusted input |
//! | --- | --- | --- |
//! | [`PrecompiledModule`] | **IMPLEMENTED** | Yes - it compiles nothing |
//! | [`CargoCompiler`] | **EXPERIMENTAL** | **No.** Not qualified |
//!
//! [`CargoCompiler`] is behind the `cargo-compiler` Cargo feature *and* refuses
//! to run unless unlocked at runtime with
//! [`CargoCompiler::unlock_for_trusted_input`]. Two locks, because a single
//! feature flag is too easy to enable by accident in a deployment script.

#[cfg(feature = "cargo-compiler")]
use rustly_judge_common::JudgeError;
use rustly_judge_common::Result;

/// What a compilation produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompileOutput {
    /// A module ready to execute.
    Module {
        /// The compiled WebAssembly.
        bytes: Vec<u8>,
        /// Warnings, verbatim. Preserved even on success: a learner should see
        /// them.
        diagnostics: Option<String>,
    },
    /// The submission did not compile.
    Failed {
        /// Raw `rustc` output, byte for byte. Never rewritten or summarised
        /// here; explaining a diagnostic is the UI's job.
        diagnostics: String,
    },
}

impl CompileOutput {
    /// The module, if compilation succeeded.
    pub fn module(&self) -> Option<&[u8]> {
        match self {
            Self::Module { bytes, .. } => Some(bytes),
            Self::Failed { .. } => None,
        }
    }
}

/// Turns submitted source into an executable module.
pub trait CompileBackend: Send + Sync {
    /// Stable identifier recorded in result manifests.
    fn id(&self) -> &'static str;

    /// Whether this backend may be given untrusted submissions.
    ///
    /// Returning `true` is a claim that compiling hostile Rust with this backend
    /// cannot compromise the host. No backend here makes that claim yet.
    fn is_qualified_for_untrusted_code(&self) -> bool;

    /// Compile `source` for `environment_id`.
    fn compile(&self, source: &[u8], environment_id: &str) -> Result<CompileOutput>;
}

/// A "compiler" that accepts an already-compiled WebAssembly module.
///
/// This is what makes the judge testable and CI-runnable without a Rust
/// toolchain in the sandbox: the pipeline is identical, and the compile step is
/// a hash-and-validate rather than an execution. It is genuinely safe for
/// untrusted input because it never executes anything - a malformed module is
/// rejected by the sandbox at instantiation.
#[derive(Debug, Clone, Copy, Default)]
pub struct PrecompiledModule;

impl PrecompiledModule {
    /// The WebAssembly magic number, `\0asm`.
    const MAGIC: &'static [u8] = b"\0asm";
}

impl CompileBackend for PrecompiledModule {
    fn id(&self) -> &'static str {
        "precompiled"
    }

    fn is_qualified_for_untrusted_code(&self) -> bool {
        true
    }

    fn compile(&self, source: &[u8], _environment_id: &str) -> Result<CompileOutput> {
        if !source.starts_with(Self::MAGIC) {
            // Not a module. This is the submitter's input, so it is a compile
            // failure rather than a judge error.
            return Ok(CompileOutput::Failed {
                diagnostics: "error: input is not a WebAssembly module (missing \\0asm header)"
                    .into(),
            });
        }
        Ok(CompileOutput::Module {
            bytes: source.to_vec(),
            diagnostics: None,
        })
    }
}

/// Compiles Rust with Cargo for `wasm32-wasip1`.
///
/// # Status: EXPERIMENTAL - not qualified for untrusted code
///
/// This backend shells out to Cargo. Cargo runs `build.rs` and expands
/// procedural macros, both arbitrary native code from the submitter, with the
/// privileges of the worker process. Until that is confined by an independently
/// reviewed sandbox, this backend must only be pointed at input you already
/// trust: your own reference solutions, content-repository validation, and
/// local development.
///
/// It fails closed. Constructing it is not enough; [`Self::unlock_for_trusted_input`]
/// must be called, and the name says what the caller is asserting.
#[cfg(feature = "cargo-compiler")]
#[derive(Debug, Clone)]
pub struct CargoCompiler {
    unlocked: bool,
    cargo: std::path::PathBuf,
}

#[cfg(feature = "cargo-compiler")]
impl Default for CargoCompiler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "cargo-compiler")]
impl CargoCompiler {
    /// A locked compiler. It will refuse to run.
    pub fn new() -> Self {
        Self {
            unlocked: false,
            cargo: "cargo".into(),
        }
    }

    /// Assert that the input to this compiler is trusted, and unlock it.
    ///
    /// The verbose name is the point: this is not a configuration knob, it is a
    /// statement about where the source came from.
    pub fn unlock_for_trusted_input(mut self) -> Self {
        self.unlocked = true;
        self
    }

    /// Use a specific `cargo` binary.
    pub fn with_cargo(mut self, cargo: impl Into<std::path::PathBuf>) -> Self {
        self.cargo = cargo.into();
        self
    }
}

#[cfg(feature = "cargo-compiler")]
impl CompileBackend for CargoCompiler {
    fn id(&self) -> &'static str {
        "cargo-wasm32-wasip1"
    }

    fn is_qualified_for_untrusted_code(&self) -> bool {
        // Deliberately unconditional. Unlocking asserts the *input* is trusted;
        // it does not make the backend safe for input that is not.
        false
    }

    fn compile(&self, source: &[u8], environment_id: &str) -> Result<CompileOutput> {
        if !self.unlocked {
            return Err(JudgeError::SecurityPolicy(
                "the Cargo compiler is EXPERIMENTAL and locked; it executes build.rs and \
                 procedural macros from the input. Call unlock_for_trusted_input() only for \
                 source you already trust."
                    .into(),
            ));
        }

        let source = std::str::from_utf8(source).map_err(|_| {
            JudgeError::MalformedPackage("submitted source is not valid UTF-8".into())
        })?;

        let workspace = tempfile::tempdir()
            .map_err(|e| JudgeError::Infrastructure(format!("cannot create a workspace: {e}")))?;
        let root = workspace.path();
        std::fs::create_dir_all(root.join("src"))
            .map_err(|e| JudgeError::Infrastructure(format!("cannot create src/: {e}")))?;
        std::fs::write(root.join("src/main.rs"), source)
            .map_err(|e| JudgeError::Infrastructure(format!("cannot write source: {e}")))?;
        std::fs::write(
            root.join("Cargo.toml"),
            // No dependencies: nothing is fetched, so the compile step needs no
            // network at all.
            "[package]\nname = \"submission\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\n\
             [dependencies]\n\n[profile.dev]\ndebug = false\n",
        )
        .map_err(|e| JudgeError::Infrastructure(format!("cannot write manifest: {e}")))?;

        let output = std::process::Command::new(&self.cargo)
            .current_dir(root)
            .args(["build", "--target", "wasm32-wasip1", "--offline", "--quiet"])
            // Cargo must not reach the network, and must not read the operator's
            // registry credentials or config.
            .env("CARGO_NET_OFFLINE", "true")
            .env("CARGO_TARGET_DIR", root.join("target"))
            .env_remove("RUSTFLAGS")
            .output()
            .map_err(|e| JudgeError::Infrastructure(format!("cannot run cargo: {e}")))?;

        let diagnostics = String::from_utf8_lossy(&output.stderr).into_owned();
        if !output.status.success() {
            return Ok(CompileOutput::Failed { diagnostics });
        }

        let artifact = root.join("target/wasm32-wasip1/debug/submission.wasm");
        let bytes = std::fs::read(&artifact).map_err(|e| {
            JudgeError::Infrastructure(format!(
                "cargo reported success for {environment_id} but {artifact:?} is missing: {e}"
            ))
        })?;
        let diagnostics = (!diagnostics.trim().is_empty()).then_some(diagnostics);
        Ok(CompileOutput::Module { bytes, diagnostics })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustly_judge_common::Verdict;

    #[test]
    fn a_precompiled_module_passes_through_unchanged() {
        let module = wat::parse_str("(module)").unwrap();
        let output = PrecompiledModule
            .compile(&module, "rust-1.88-wasm32-wasip1")
            .unwrap();
        assert_eq!(output.module(), Some(module.as_slice()));
    }

    #[test]
    fn non_wasm_input_is_a_compile_failure_not_a_judge_error() {
        let output = PrecompiledModule.compile(b"fn main() {}", "any").unwrap();
        assert!(output.module().is_none());
        match output {
            CompileOutput::Failed { diagnostics } => assert!(diagnostics.contains("WebAssembly")),
            CompileOutput::Module { .. } => panic!("should not have compiled"),
        }
    }

    #[test]
    fn the_precompiled_backend_is_safe_because_it_executes_nothing() {
        assert!(PrecompiledModule.is_qualified_for_untrusted_code());
        assert_eq!(PrecompiledModule.id(), "precompiled");
    }

    #[cfg(feature = "cargo-compiler")]
    #[test]
    fn the_cargo_compiler_refuses_to_run_until_it_is_explicitly_unlocked() {
        let error = CargoCompiler::new()
            .compile(b"fn main() {}", "any")
            .unwrap_err();
        assert_eq!(error.verdict(), Verdict::SecurityEvent);
        assert!(error.to_string().contains("build.rs"));
    }

    #[cfg(feature = "cargo-compiler")]
    #[test]
    fn unlocking_asserts_the_input_is_trusted_not_that_the_backend_is_safe() {
        let compiler = CargoCompiler::new().unlock_for_trusted_input();
        assert!(
            !compiler.is_qualified_for_untrusted_code(),
            "unlocking must never make the backend claim to be safe for untrusted code"
        );
    }
}
