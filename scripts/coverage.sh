#!/usr/bin/env bash
# Combined Rust + Python coverage, written to coverage.lcov (one file for Codecov/Coveralls).
#
# The Rust code is measured while it runs under pytest (instrumented extension module) and
# under `cargo test` (pure Rust core). Python and Rust sources do not overlap, so the two lcov
# tracefiles are simply concatenated.
#
# Requires cargo-llvm-cov and the llvm-tools rustup component.
set -euo pipefail
cd "$(dirname "$0")/.."

out=target/coverage
mkdir -p "$out"

# instrumentation flags, profile output and a separate target directory
eval "$(cargo llvm-cov show-env --sh)"
cargo llvm-cov clean --workspace

# instrumented extension module, installed into the project venv
uv run --no-sync maturin develop --uv
uv run --no-sync pytest --cov-report="lcov:$out/python.lcov" "$@"
cargo test --no-default-features

cargo llvm-cov report --lcov --output-path "$out/rust.lcov"
cargo llvm-cov report --summary-only
# tracefiles may lack a final newline, which would glue two records together
{ cat "$out/rust.lcov"; echo; cat "$out/python.lcov"; } | grep -v "^$" > coverage.lcov
echo "combined report: coverage.lcov"

# restore a regular (not instrumented) build of the extension
env -u RUSTFLAGS -u LLVM_PROFILE_FILE -u CARGO_LLVM_COV -u CARGO_LLVM_COV_SHOW_ENV -u CARGO_LLVM_COV_TARGET_DIR \
  -u CARGO_TARGET_DIR -u CARGO_ENCODED_RUSTFLAGS -u RUSTDOCFLAGS -u CARGO_BUILD_RUSTFLAGS \
  uv sync --quiet --reinstall-package pysubnettree-rs
