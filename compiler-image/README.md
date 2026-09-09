# Rust compiler image

This image contains the pinned Rust compiler and `wasm32-wasip1` standard
library used by `ContainerRustcCompiler`. Build and publish it by digest; judge
configuration rejects mutable image tags.

The runtime invocation supplies all isolation controls. The image itself holds
no credentials, package registry, Cargo cache, source, or evaluation material.
