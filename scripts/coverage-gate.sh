#!/usr/bin/env bash
# Fail when a package's statement coverage falls below its recorded floor.
#
# A floor is a ratchet, not a target: it records what the package already
# achieves, so a change cannot quietly delete the tests that made it pass.
# Raise a floor when you raise the coverage. Never lower one.
#
# The percentages come straight from `go test -cover`, which is the number a
# developer sees locally. Nothing here recomputes coverage. The script targets
# bash 3.2, so it uses no associative arrays.
set -euo pipefail

floors_file="${1:-coverage-floors.txt}"
test_output="${2:-}"

[ -f "$floors_file" ] || { echo "no floors file at $floors_file" >&2; exit 1; }

measured="$(mktemp)"
trap 'rm -f "$measured"' EXIT

if [ -n "$test_output" ]; then
  [ -f "$test_output" ] || { echo "no test output at $test_output" >&2; exit 1; }
  cat "$test_output"
else
  go test ./... -cover
fi | awk '
  /coverage: [0-9.]+% of statements/ {
    # "ok  <pkg> 0.5s coverage: 84.5% of statements" and the tests-less form
    # "<pkg>  coverage: 0.0% of statements" both appear.
    pkg = ($1 == "ok" || $1 == "FAIL" || $1 == "?") ? $2 : $1
    for (i = 1; i <= NF; i++) if ($i == "coverage:") pct = $(i + 1)
    gsub(/%/, "", pct)
    print pkg, pct
  }' > "$measured"

status=0
printf '%-52s %8s %8s\n' "package" "actual" "floor"
while read -r pkg floor; do
  case "$pkg" in ''|\#*) continue ;; esac

  got="$(awk -v p="$pkg" '$1 == p { print $2; exit }' "$measured")"
  if [ -z "$got" ]; then
    printf '%-52s %8s %7s%%  MISSING\n' "$pkg" "-" "$floor"
    echo "  $pkg is in the floors file but produced no coverage line" >&2
    status=1
    continue
  fi

  if awk -v a="$got" -v f="$floor" 'BEGIN { exit !(a + 0.001 < f) }'; then
    printf '%-52s %7s%% %7s%%  FAIL\n' "$pkg" "$got" "$floor"
    status=1
  else
    printf '%-52s %7s%% %7s%%  ok\n' "$pkg" "$got" "$floor"
  fi
done < "$floors_file"

if [ "$status" -ne 0 ]; then
  echo >&2
  echo "Coverage fell below a recorded floor. Add tests, or say in review why the floor should change." >&2
fi
exit "$status"
