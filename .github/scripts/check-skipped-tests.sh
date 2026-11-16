#!/usr/bin/env bash
# Fails when a `go test -v` log contains a skipped test that is not allowlisted,
# so tests that silently stop running in CI (missing env, config, fixtures) get noticed.
set -euo pipefail

log="$1"

allowed=(
  TestParseFeedRealFile
)

mapfile -t skipped < <(grep -oE -- '--- SKIP: [^ ]+' "$log" | awk '{print $3}' | sort -u)

unexpected=()
for test in "${skipped[@]}"; do
  if [[ " ${allowed[*]} " != *" $test "* ]]; then
    unexpected+=("$test")
  fi
done

echo "Skipped tests: ${#skipped[@]}"
for test in "${skipped[@]}"; do
  echo "  $test"
done

if ((${#unexpected[@]})); then
  echo "::error::Unexpected skipped tests: ${unexpected[*]}"
  exit 1
fi
