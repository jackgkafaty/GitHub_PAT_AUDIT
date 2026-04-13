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
# Rate limit aware REST call — checks remaining quota and waits if needed
# ---------------------------------------------------------------------------
gh_rest() {
  local method="${1}"
  local endpoint="${2}"
  shift 2

  local tmpfile
  tmpfile="$(mktemp)"

  local http_code
  http_code="$(curl -sSL -o "${tmpfile}" -w "%{http_code}" \
    -X "${method}" \
    -H "Accept: application/vnd.github+json" \
    -H "Authorization: Bearer ${ORG_PAT}" \
    -H "X-GitHub-Api-Version: ${API_VERSION}" \
    -D "${tmpfile}.hdr" \
    "$@" \
    "${API_BASE}${endpoint}" 2>/dev/null || echo "000")"

  # Check for rate limit (403 or 429)
  if [[ "${http_code}" == "403" || "${http_code}" == "429" ]]; then
    local reset_at
    reset_at="$(grep -i '^x-ratelimit-reset:' "${tmpfile}.hdr" 2>/dev/null | tr -d '\r' | awk '{print $2}')"
    if [[ -n "${reset_at}" ]]; then
      local now_epoch
      now_epoch="$(date +%s)"
      local wait_secs=$(( reset_at - now_epoch + 2 ))
      if [[ ${wait_secs} -gt 0 && ${wait_secs} -lt 900 ]]; then
        echo "::warning::Rate limited. Waiting ${wait_secs}s until reset..." >&2
        sleep "${wait_secs}"
        # Retry once
        rm -f "${tmpfile}" "${tmpfile}.hdr"
        curl -fsSL \
          -X "${method}" \
          -H "Accept: application/vnd.github+json" \
          -H "Authorization: Bearer ${ORG_PAT}" \
          -H "X-GitHub-Api-Version: ${API_VERSION}" \
          "$@" \
          "${API_BASE}${endpoint}"
        return
      fi
    fi
    echo "::error::Rate limited on ${endpoint}" >&2
    cat "${tmpfile}"
    rm -f "${tmpfile}" "${tmpfile}.hdr"
    return 1
  fi

  cat "${tmpfile}"
  rm -f "${tmpfile}" "${tmpfile}.hdr"
}

# ---------------------------------------------------------------------------
# Check remaining rate limit and wait if low
# ---------------------------------------------------------------------------
check_rate_limit() {
  local remaining
  remaining="$(curl -sSL \
    -H "Accept: application/vnd.github+json" \
    -H "Authorization: Bearer ${ORG_PAT}" \
    -H "X-GitHub-Api-Version: ${API_VERSION}" \
    "${API_BASE}/rate_limit" 2>/dev/null | jq '.rate.remaining // 999')"

  if [[ "${remaining}" -lt 50 ]]; then
    local reset_at
    reset_at="$(curl -sSL \
      -H "Accept: application/vnd.github+json" \
      -H "Authorization: Bearer ${ORG_PAT}" \
      -H "X-GitHub-Api-Version: ${API_VERSION}" \
      "${API_BASE}/rate_limit" 2>/dev/null | jq '.rate.reset // 0')"
    local now_epoch
    now_epoch="$(date +%s)"
    local wait_secs=$(( reset_at - now_epoch + 2 ))
    if [[ ${wait_secs} -gt 0 && ${wait_secs} -lt 900 ]]; then
      echo "::warning::Only ${remaining} API calls remaining. Waiting ${wait_secs}s for reset..." >&2
      sleep "${wait_secs}"
    fi
  fi
  echo "${remaining}"
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
# Paginated REST fetch with rate limit awareness
# ---------------------------------------------------------------------------
gh_rest_paginated() {
  local endpoint="${1}"
  local per_page="${2:-100}"
  local max_pages="${3:-20}"
  local results="[]"
  local page=1

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

    # Brief pause between pages to avoid rate limiting
    sleep 0.5
  done

  echo "${results}"
}

# ---------------------------------------------------------------------------
# Validate PAT and org access (cached via file to avoid repeat API calls)
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

  # Use cached auth if available (avoids burning 2 API calls per script)
  if [[ -f "${REPORT_DIR}/_auth_cache.json" ]]; then
    AUTH_USER="$(jq -r '.user' "${REPORT_DIR}/_auth_cache.json")"
    ORG_ID="$(jq -r '.org_id' "${REPORT_DIR}/_auth_cache.json")"
    echo "   Authenticated as: ${AUTH_USER} (cached)"
    echo "   Organization: ${ORG_NAME} (ID: ${ORG_ID})"
    return 0
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

  # Cache for subsequent scripts
  echo "{\"user\": \"${AUTH_USER}\", \"org_id\": \"${ORG_ID}\"}" > "${REPORT_DIR}/_auth_cache.json"
}
