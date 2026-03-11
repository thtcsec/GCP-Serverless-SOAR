#!/bin/bash
# pack_function.sh — Package Cloud Functions code excluding tests and dev files
# Usage: ./scripts/pack_function.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
OUTPUT="$PROJECT_ROOT/dist/function_package.zip"

echo "📦 Packaging Cloud Function..."

rm -rf "$PROJECT_ROOT/dist"
mkdir -p "$PROJECT_ROOT/dist"

cd "$PROJECT_ROOT"

# Zip only production source code (exclude tests, __pycache__, .git)
zip -r "$OUTPUT" src/ \
  -x "src/__pycache__/*" \
  -x "src/**/__pycache__/*" \
  -x "src/**/tests/*" \
  -x "*.pyc" \
  -x "*.pyo"

echo "✅ Function package created: $OUTPUT ($(du -h "$OUTPUT" | cut -f1))"
