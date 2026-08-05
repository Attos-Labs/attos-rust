#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
echo "Running Rust Enterprise Test Suite..."
cargo test --release
cargo bench
echo "✓ All tests passed."
