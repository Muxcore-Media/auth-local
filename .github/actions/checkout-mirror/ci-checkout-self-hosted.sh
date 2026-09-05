#!/usr/bin/env bash
# Self-hosted GitHub Actions checkout when the runner git remote is Forgejo mirror.
# Tries Forgejo first; on missing ref, checks out from GitHub and backfills Forgejo.
#
# Required env (set by Actions or caller):
# GITHUB_WORKSPACE GITHUB_REPOSITORY GITHUB_SHA
# Optional:
# MUXCORE_CI_TOKEN / GITHUB_TOKEN — GitHub HTTPS fetch + mirror backfill
# FORGEJO_GIT — default ssh://forgejo@git.zem.systems:2222/muxcore
# MIRROR_SYNC_FIRST=1 — poll Forgejo until SHA exists (mirror push between tries)
# MIRROR_WAIT_TIMEOUT — seconds (default 300)
# CHECKOUT_DEPTH — shallow depth (default 1)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/mirror-lib.sh"

die() { echo "error: $*" >&2; exit 1; }

GITHUB_WORKSPACE="${GITHUB_WORKSPACE:-${RUNNER_WORKSPACE:-$PWD}}"
GITHUB_REPOSITORY="${GITHUB_REPOSITORY:?GITHUB_REPOSITORY required}"
GITHUB_SHA="${GITHUB_SHA:?GITHUB_SHA required}"
CHECKOUT_DEPTH="${CHECKOUT_DEPTH:-1}"
MIRROR_WAIT_TIMEOUT="${MIRROR_WAIT_TIMEOUT:-300}"
MIRROR_WAIT_INTERVAL="${MIRROR_WAIT_INTERVAL:-10}"
TOKEN="${MUXCORE_CI_TOKEN:-${GITHUB_TOKEN:-}}"

gh_name="${GITHUB_REPOSITORY#*/}"
forgejo_name="$(forgejo_repo_name "$gh_name")"
forgejo_url="${FORGEJO_GIT}/${forgejo_name}.git"
github_url="https://github.com/${GITHUB_REPOSITORY}.git"

clean_workspace() {
  find "$GITHUB_WORKSPACE" -mindepth 1 -maxdepth 1 -exec rm -rf {} + 2>/dev/null || true
}

checkout_from_forgejo() {
  echo "checkout: Forgejo muxcore/${forgejo_name} @ ${GITHUB_SHA:0:12}"
  git -C "$GITHUB_WORKSPACE" init -q
  git -C "$GITHUB_WORKSPACE" remote add origin "$forgejo_url"
  if git -C "$GITHUB_WORKSPACE" fetch --depth="$CHECKOUT_DEPTH" origin "$GITHUB_SHA"; then
    git -C "$GITHUB_WORKSPACE" checkout -q FETCH_HEAD
    return 0
  fi
  git -C "$GITHUB_WORKSPACE" remote remove origin 2>/dev/null || true
  return 1
}

checkout_from_github() {
  [[ -n "$TOKEN" ]] || die "Forgejo lacks ${GITHUB_SHA:0:12}; set MUXCORE_CI_TOKEN for GitHub fallback"
  echo "checkout: GitHub fallback ${GITHUB_REPOSITORY} @ ${GITHUB_SHA:0:12}"
  git -C "$GITHUB_WORKSPACE" init -q
  git -C "$GITHUB_WORKSPACE" remote add origin \
    "https://x-access-token:${TOKEN}@github.com/${GITHUB_REPOSITORY}.git"
  git -C "$GITHUB_WORKSPACE" fetch --depth="$CHECKOUT_DEPTH" origin "$GITHUB_SHA"
  git -C "$GITHUB_WORKSPACE" checkout -q FETCH_HEAD
}

push_mirror_to_forgejo() {
  [[ -n "$TOKEN" ]] || return 0
  local tmp work
  tmp="$(mktemp -d)"
  work="$tmp/${forgejo_name}.git"
  echo "mirror-backfill: ${GITHUB_ORG}/${gh_name} → Forgejo muxcore/${forgejo_name}"
  if git clone --mirror "https://x-access-token:${TOKEN}@${github_url#https://}" "$work" \
    && git -C "$work" push --mirror "$forgejo_url"; then
    echo "mirror-backfill: OK"
  else
    echo "warn: mirror-backfill failed (non-fatal; run mirror-github-to-forgejo.sh ${gh_name} on desk)"
  fi
  rm -rf "$tmp"
}

wait_for_forgejo_sha() {
  [[ -n "$TOKEN" ]] || die "MIRROR_SYNC_FIRST=1 requires MUXCORE_CI_TOKEN or GITHUB_TOKEN"
  local deadline=$((SECONDS + MIRROR_WAIT_TIMEOUT))
  echo "mirror-sync: waiting for ${GITHUB_SHA:0:12} on Forgejo muxcore/${forgejo_name} (${MIRROR_WAIT_TIMEOUT}s max)"
  while (( SECONDS < deadline )); do
    if forgejo_has_sha "$forgejo_name" "$GITHUB_SHA"; then
      echo "mirror-sync: OK"
      return 0
    fi
    push_mirror_to_forgejo || true
    sleep "$MIRROR_WAIT_INTERVAL"
  done
  die "mirror-sync timeout: ${GITHUB_SHA:0:12} still missing on Forgejo — configure GitHub push webhook (tls/GITHUB-FORGEJO-MIRROR.md)"
}

print_mirror_lag_help() {
  echo "warn: Forgejo muxcore/${forgejo_name} lacks ${GITHUB_SHA:0:12} (upload-pack: not our ref)"
  echo "action: run mvp/scripts/mirror-github-to-forgejo.sh ${gh_name}"
  echo " or add GitHub push webhook → mirror (see tls/GITHUB-FORGEJO-MIRROR.md)"
}

main() {
  clean_workspace
  mkdir -p "$GITHUB_WORKSPACE"

  if [[ "${MIRROR_SYNC_FIRST:-0}" == "1" ]]; then
    wait_for_forgejo_sha
    checkout_from_forgejo
    exit 0
  fi

  if forgejo_has_sha "$forgejo_name" "$GITHUB_SHA" && checkout_from_forgejo; then
    exit 0
  fi

  print_mirror_lag_help
  checkout_from_github
  push_mirror_to_forgejo &
  wait $! 2>/dev/null || true
}

main "$@"
