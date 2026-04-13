#!/usr/bin/env bash
# =============================================================================
# Shared functions for PAT Audit scripts
# Source this file from each step script: source "$(dirname "$0")/lib.sh"
# =============================================================================

API_BASE="https://api.github.com"
GRAPHQL_URL="https://api.github.com/graphql"
API_VERSION="${GITHUB_API_VERSION:-2026-03-10}"

REPORT_DIR="${REPORT_DIR:-./reports}"
mkdir -p "${REPORT_DIR}"

LOOKBACK_DAYS="${LOOKBACK_DAYS:-30}"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
LOOKBACK_DATE="$(date -u -d "${LOOKBACK_DAYS} days ago" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v-"${LOOKBACK_DAYS}"d +%Y-%m-%dT%H:%M:%SZ)"

# ---------------------------------------------------------------------------
# Authenticated curl for REST
# ---------------------------------------------------------------------------
gh_rest() {
  local method="${1}"
  local endpoint="${2}"
  shift 2
  curl -fsSL \
    -X "${method}" \
    -H "Accept: application/vnd.github+json" \
    -H "Authorization: Bearer ${ORG_PAT}" \
    -H "X-GitHub-Api-Version: ${API_VERSION}" \
    "$@" \
    "${API_BASE}${endpoint}"
}

# ---------------------------------------------------------------------------
# Authenticated curl for GraphQL
# ---------------------------------------------------------------------------
gh_graphql() {
  local query="${1}"
  curl -fsSL \
    -X POST \
    -H "Accept: application/vnd.github+json" \
    -H "Authorization: Bearer ${ORG_PAT}" \
    "${GRAPHQL_URL}" \
    -d "${query}"
}

# ---------------------------------------------------------------------------
# Paginated REST fetch (collects all pages into a JSON array)
# ---------------------------------------------------------------------------
gh_rest_paginated() {
  local endpoint="${1}"
  local per_page="${2:-100}"
  local results="[]"
  local page=1
  local max_pages=50

  while [[ $page -le $max_pages ]]; do
    local separator="?"
    if [[ "${endpoint}" == *"?"* ]]; then
      separator="&"
    fi
    local response
    response="$(gh_rest GET "${endpoint}${separator}per_page=${per_page}&page=${page}" 2>/dev/null || echo "[]")"

    local count
    count="$(echo "${response}" | jq 'if type == "array" then length else 0 end' 2>/dev/null || echo "0")"

    if [[ "${count}" -eq 0 ]]; then
      break
    fi

    results="$(echo "${results}" "${response}" | jq -s '.[0] + .[1]')"
    page=$((page + 1))

    if [[ "${count}" -lt "${per_page}" ]]; then
      break
    fi
  done

  echo "${results}"
}

# ---------------------------------------------------------------------------
# Validate PAT and org access
# ---------------------------------------------------------------------------
validate_auth() {
  if [[ -z "${ORG_PAT:-}" ]]; then
    echo "::error::ORG_PAT secret is not set."
    exit 1
  fi
  if [[ -z "${ORG_NAME:-}" ]]; then
    echo "::error::ORG_NAME is not set."
    exit 1
  fi

  AUTH_CHECK="$(gh_rest GET "/user" 2>/dev/null || echo "{}")"
  AUTH_USER="$(echo "${AUTH_CHECK}" | jq -r '.login // "UNKNOWN"')"
  if [[ "${AUTH_USER}" == "UNKNOWN" ]]; then
    echo "::error::Failed to authenticate with the provided PAT."
    exit 1
  fi
  echo "   Authenticated as: ${AUTH_USER}"

  ORG_INFO="$(gh_rest GET "/orgs/${ORG_NAME}" 2>/dev/null || echo "{}")"
  ORG_ID="$(echo "${ORG_INFO}" | jq -r '.id // "UNKNOWN"')"
  if [[ "${ORG_ID}" == "UNKNOWN" ]]; then
    echo "::error::Cannot access organization '${ORG_NAME}'."
    exit 1
  fi
  echo "   Organization: ${ORG_NAME} (ID: ${ORG_ID})"
}
