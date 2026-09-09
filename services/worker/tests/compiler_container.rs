use std::process::Command;
use std::time::Duration;

use rustly_judge_common::JudgeError;
use rustly_judge_worker::{CompileBackend, CompileOutput, CompilerLimits, ContainerRustcCompiler};

fn image() -> Option<String> {
    std::env::var("RUSTLY_TEST_COMPILER_IMAGE").ok()
}

fn compiler(limits: CompilerLimits) -> Option<ContainerRustcCompiler> {
    image().map(|image| {
        ContainerRustcCompiler::new(image, "rust-1.88-wasm32-wasip1")
            .unwrap()
            .with_limits(limits)
    })
}

fn running_compiler_containers() -> String {
    let output = Command::new("docker")
        .args([
            "ps",
            "--filter",
            "name=rustly-compile-",
            "--format",
            "{{.Names}}",
        ])
        .output()
        .unwrap();
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

#[test]
#[ignore = "requires the pinned compiler container image"]
fn valid_dependency_free_rust_compiles_to_wasi() {
    let compiler = compiler(CompilerLimits::default()).unwrap();
    let output = compiler
        .compile(
            br#"fn main() { println!("hello"); }"#,
            "rust-1.88-wasm32-wasip1",
        )
        .unwrap();
    assert!(
        matches!(output, CompileOutput::Module { ref bytes, .. } if bytes.starts_with(b"\0asm"))
    );
    assert!(running_compiler_containers().is_empty());
}

#[test]
#[ignore = "requires the pinned compiler container image"]
fn compiler_fault_corpus_is_bounded_and_cleans_up() {
    let base = CompilerLimits::default();

    let oversized = compiler(CompilerLimits {
        source_bytes: 8,
        ..base
    })
    .unwrap()
    .compile(b"fn main() {}", "rust-1.88-wasm32-wasip1");
    assert!(matches!(oversized, Err(JudgeError::SecurityPolicy(_))));

    let malformed = compiler(base)
        .unwrap()
        .compile(&[0xff, 0xfe], "rust-1.88-wasm32-wasip1")
        .unwrap();
    assert!(matches!(malformed, CompileOutput::Failed { .. }));

    let output_flood = (0..1500)
        .map(|index| format!("compile_error!(\"diagnostic-{index}\");\n"))
        .collect::<String>();
    let flooded = compiler(CompilerLimits {
        diagnostics_bytes: 1024,
        ..base
    })
    .unwrap()
    .compile(output_flood.as_bytes(), "rust-1.88-wasm32-wasip1");
    assert!(matches!(flooded, Err(JudgeError::SecurityPolicy(_))));

    let host_file = tempfile::NamedTempFile::new().unwrap();
    let traversal = format!(
        "const _: &str = include_str!({:?}); fn main() {{}}",
        host_file.path().display().to_string()
    );
    let denied = compiler(base)
        .unwrap()
        .compile(traversal.as_bytes(), "rust-1.88-wasm32-wasip1")
        .unwrap();
    assert!(matches!(denied, CompileOutput::Failed { .. }));

    let tiny_artifact = compiler(CompilerLimits {
        artifact_bytes: 8,
        ..base
    })
    .unwrap()
    .compile(b"fn main() {}", "rust-1.88-wasm32-wasip1");
    assert!(matches!(tiny_artifact, Err(JudgeError::SecurityPolicy(_))));

    let timed_out = compiler(CompilerLimits {
        wall_time: Duration::from_millis(1),
        ..base
    })
    .unwrap()
    .compile(b"fn main() {}", "rust-1.88-wasm32-wasip1");
    assert!(matches!(timed_out, Err(JudgeError::SecurityPolicy(_))));
    assert!(running_compiler_containers().is_empty());
}
