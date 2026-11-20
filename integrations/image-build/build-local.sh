#!/usr/bin/env bash
# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.
# Build only from the caller's frozen, curated source archive; never push or run.
set -euo pipefail

if [[ $# -ne 4 ]]; then
  printf 'Usage: %s SOURCE_ARCHIVE EXPECTED_SHA256 OUTPUT_DIR SOURCE_COMMIT\n' "$0" >&2
  exit 2
fi
archive=$(realpath "$1")
expected=$2
output=$(realpath -m "$3")
source_commit=$4
[[ $source_commit =~ ^[a-f0-9]{40}$ ]] || { echo 'Invalid public source commit' >&2; exit 2; }
[[ $expected =~ ^[a-f0-9]{64}$ ]] || { echo 'Invalid SHA-256' >&2; exit 2; }
[[ -f $archive ]] || { echo 'Source archive not found' >&2; exit 2; }
actual=$(sha256sum "$archive" | cut -d ' ' -f 1)
[[ $actual == "$expected" ]] || { echo 'Source archive SHA-256 mismatch' >&2; exit 2; }
mkdir -p "$output"
[[ -z $(ls -A "$output") ]] || { echo 'Output directory must be empty' >&2; exit 2; }
work=$(mktemp -d /tmp/plane-image-context.XXXXXXXX)
trap 'rm -rf "$work"' EXIT
# Restrict archive traversal; the trusted source snapshot must have repository root at archive root.
python3 - "$archive" "$work" <<'PY'
import sys, tarfile
with tarfile.open(sys.argv[1], "r:*") as archive:
    archive.extractall(sys.argv[2], filter="data")
PY
[[ -f "$work/apps/web/Dockerfile.web" && -f "$work/apps/api/Dockerfile.api" ]] || {
  echo 'Archive must contain repository root at archive root' >&2; exit 2;
}
# Catch common private/local artifacts before Docker sees the source tree.
if find "$work" \( -type d \( -name .git -o -name node_modules -o -name .venv -o -name .secrets \) -o -type f \( \( -name '.env*' ! -name '.env.example' \) -o -name '*.pem' -o -name '*.key' \) \) -print -quit | grep -q .; then
  echo 'Archive contains local dependencies, repository internals or a common secret file; curate it first' >&2
  exit 2
fi
short=${actual:0:16}
printf 'source_sha256\t%s\nsource_commit\t%s\nplatform\tlinux/amd64\n' "$actual" "$source_commit" > "$output/manifest.tsv"
printf 'context_bytes\t%s\n' "$(du -sb "$work" | cut -f1)" >> "$output/manifest.tsv"
printf 'component\tresult\tduration_seconds\timage_id\timage_bytes\tarchitecture\n' > "$output/results.tsv"
status=0
for component in web admin space live backend; do
  case "$component" in
    backend) context="$work/apps/api"; dockerfile="$context/Dockerfile.api" ;;
    *) context="$work"; dockerfile="$work/apps/$component/Dockerfile.$component" ;;
  esac
  tag="plane-local-checkpoint:${short}-${component}"
  start=$(date +%s)
  printf 'Building %s from %s\n' "$component" "$actual"
  # Frontends bake in the public source commit only; no secrets or environment
  # files are passed. Browser URL settings retain the official same-origin defaults.
  build_args=()
  if [[ $component == web || $component == admin || $component == space ]]; then
    build_args+=(--build-arg "PLANE_SOURCE_COMMIT=$source_commit")
  fi
  if timeout "${PLANE_BUILD_TIMEOUT_SECONDS:-3600}" docker buildx build \
      --platform linux/amd64 --load --progress plain "${build_args[@]}" -f "$dockerfile" -t "$tag" "$context" \
      > "$output/$component.log" 2>&1; then
    duration=$(( $(date +%s) - start ))
    image_info=$(docker image inspect "$tag" --format '{{.Id}}\t{{.Size}}\t{{.Architecture}}')
    printf '%s\tOK\t%s\t%b\n' "$component" "$duration" "$image_info" >> "$output/results.tsv"
  else
    code=$?
    duration=$(( $(date +%s) - start ))
    printf '%s\tFAILED(%s)\t%s\t-\t-\t-\n' "$component" "$code" "$duration" >> "$output/results.tsv"
    status=1
  fi
done
printf 'API, worker, beat-worker and migrator use the same backend image; their entrypoints differ.\n' >> "$output/manifest.tsv"
exit "$status"
