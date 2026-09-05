#!/usr/bin/env bash
# Shared Forgejo↔GitHub repo name mappings for mirror/audit scripts.
# shellcheck disable=SC2034
FORGEJO_ORG="${FORGEJO_ORG:-muxcore}"
GITHUB_ORG="${GITHUB_ORG:-Muxcore-Media}"
FORGEJO_API="${FORGEJO_API:-https://git.zem.systems/api/v1}"
FORGEJO_GIT="${FORGEJO_GIT:-ssh://forgejo@git.zem.systems:2222/${FORGEJO_ORG}}"
GITHUB_TOKEN="${GITHUB_TOKEN:-${GH_TOKEN:-$(gh auth token 2>/dev/null || true)}}"

# Forgejo repo name → GitHub repo name.
declare -A FORGEJO_TO_GITHUB=(
  [core-wiki]=core.wiki
  [muxcore-tvos]=media-tvos-app
)

# GitHub repo name → Forgejo repo name.
declare -A GITHUB_TO_FORGEJO=(
  [core.wiki]=core-wiki
  [media-tvos-app]=muxcore-tvos
)

SKIP_REPOS=(
  claude-working-directory
)

die() { echo "error: $*" >&2; exit 1; }

github_repo_name() {
  local forgejo="$1"
  if [[ -n "${FORGEJO_TO_GITHUB[$forgejo]+x}" ]]; then
    printf '%s\n' "${FORGEJO_TO_GITHUB[$forgejo]}"
  else
    printf '%s\n' "$forgejo"
  fi
}

forgejo_repo_name() {
  local github="$1"
  if [[ -n "${GITHUB_TO_FORGEJO[$github]+x}" ]]; then
    printf '%s\n' "${GITHUB_TO_FORGEJO[$github]}"
  else
    printf '%s\n' "$github"
  fi
}

should_skip_repo() {
  local name="$1" s
  for s in "${SKIP_REPOS[@]}"; do
    [[ "$name" == "$s" ]] && return 0
  done
  return 1
}

require_github_token() {
  [[ -n "$GITHUB_TOKEN" ]] || die "set GITHUB_TOKEN or run: gh auth login"
}

list_forgejo_repos() {
  local page=1 batch
  while :; do
    batch="$(curl -fsSL "${FORGEJO_API}/orgs/${FORGEJO_ORG}/repos?limit=50&page=${page}" | jq -r '.[].name' 2>/dev/null || true)"
    [[ -z "$batch" ]] && break
    printf '%s\n' "$batch"
    page=$((page + 1))
    [[ "$page" -gt 20 ]] && break
  done | sort -u
}

list_github_repos() {
  gh repo list "$GITHUB_ORG" --limit 200 --json name -q '.[].name' 2>/dev/null | sort -u
}

default_branch_sha() {
  local owner="$1" repo="$2" token="${3:-$GITHUB_TOKEN}"
  local branch sha
  branch="$(gh api "repos/${owner}/${repo}" --jq '.default_branch' 2>/dev/null || true)"
  [[ -n "$branch" ]] || return 1
  sha="$(gh api "repos/${owner}/${repo}/commits/${branch}" --jq .sha 2>/dev/null || true)"
  [[ -n "$sha" ]] || return 1
  printf '%s\n' "$sha"
}

forgejo_head_sha() {
  local forgejo="$1"
  git ls-remote "${FORGEJO_GIT}/${forgejo}.git" \
    refs/heads/main refs/heads/master 2>/dev/null \
    | awk 'NR==1 {print $1; exit}'
}

forgejo_has_sha() {
  local forgejo="$1" sha="$2"
  git ls-remote "${FORGEJO_GIT}/${forgejo}.git" "$sha" 2>/dev/null | grep -q .
}
