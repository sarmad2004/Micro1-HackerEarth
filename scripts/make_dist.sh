#!/usr/bin/env bash
# Build the submission archive. Sources and evidence only: no build outputs,
# no binaries, nothing a clean checkout could not regenerate.
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$(pwd)"
NAME="agentgate-submission"
OUT="$ROOT/dist"

rm -rf "$OUT"
mkdir -p "$OUT/$NAME"

# Prefer the git file list, which by construction excludes build artifacts.
# Falls back to a manual copy when the tree is a git repo with nothing yet
# committed, which would otherwise silently produce an empty archive.
TRACKED=0
if git -C "$ROOT" rev-parse --git-dir >/dev/null 2>&1; then
  TRACKED=$(git -C "$ROOT" ls-files | wc -l)
fi

if [ "$TRACKED" -gt 0 ]; then
  git -C "$ROOT" ls-files -z | while IFS= read -r -d '' f; do
    mkdir -p "$OUT/$NAME/$(dirname "$f")"
    cp "$ROOT/$f" "$OUT/$NAME/$f"
  done
else
  echo "no tracked files; copying the source tree by hand" >&2
  for d in cpp rust corpus eval scripts docs; do
    [ -d "$d" ] && cp -r "$d" "$OUT/$NAME/"
  done
  cp -- *.md Makefile LICENSE .gitignore "$OUT/$NAME/" 2>/dev/null || true
  rm -rf "$OUT/$NAME/cpp/build" "$OUT/$NAME/rust/target"
fi

FILES=$(find "$OUT/$NAME" -type f | wc -l)
if [ "$FILES" -eq 0 ]; then
  echo "refusing to write an empty archive" >&2
  exit 1
fi

cd "$OUT"
zip -qr "$NAME.zip" "$NAME"
rm -rf "$NAME"

printf 'wrote %s (%s)\n' "$OUT/$NAME.zip" "$(du -h "$NAME.zip" | cut -f1)"
printf 'contents: %s files\n' "$(unzip -l "$NAME.zip" | tail -1 | awk '{print $2}')"
