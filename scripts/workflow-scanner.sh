#!/usr/bin/env bash
# =============================================================================
# Step: Scan Org Workflows for Custom Secret Usage (PAT Detection)
# Outputs: reports/workflow_secrets.json
# =============================================================================
set -euo pipefail
source "$(dirname "$0")/lib.sh"

echo "============================================"
echo "  Workflow Scanner: ${ORG_NAME}"
echo "============================================"
validate_auth

echo ""
echo ">> Scanning org workflows for custom secret references..."

# Check rate limit before starting heavy work
REMAINING="$(check_rate_limit)"
echo "   API calls remaining: ${REMAINING}"

# Use code search API to find workflows referencing secrets
SEARCH_RESULTS="[]"
SEARCH_PAGE=1
SEARCH_MAX_PAGES=5

while [[ $SEARCH_PAGE -le $SEARCH_MAX_PAGES ]]; do
  SEARCH_RESPONSE="$(gh_rest GET "/search/code?q=secrets.+org:${ORG_NAME}+path:.github/workflows+language:yaml&per_page=100&page=${SEARCH_PAGE}" 2>/dev/null || echo '{"items":[]}')"

  SEARCH_BATCH="$(echo "${SEARCH_RESPONSE}" | jq '.items // []')"
  BATCH_COUNT="$(echo "${SEARCH_BATCH}" | jq 'length')"

  if [[ "${BATCH_COUNT}" -eq 0 ]]; then
    break
  fi

  SEARCH_RESULTS="$(echo "${SEARCH_RESULTS}" "${SEARCH_BATCH}" | jq -s '.[0] + .[1]')"
  SEARCH_PAGE=$((SEARCH_PAGE + 1))
  sleep 3

  if [[ "${BATCH_COUNT}" -lt 100 ]]; then
    break
  fi
done

# Get unique repo+path combinations
UNIQUE_FILES="$(echo "${SEARCH_RESULTS}" | jq -r '[.[] | {repo: .repository.full_name, path: .path, html_url: .html_url}] | unique_by(.repo + .path)')"
UNIQUE_FILE_COUNT="$(echo "${UNIQUE_FILES}" | jq 'length')"
echo "   Found ${UNIQUE_FILE_COUNT} workflow files referencing secrets"

# Fetch each file and extract non-GITHUB_TOKEN secret names
rm -f "${REPORT_DIR}/_wf_tmp.jsonl"
PROCESSED=0

echo "${UNIQUE_FILES}" | jq -c '.[0:100] | .[]' 2>/dev/null | while IFS= read -r file_info; do
  REPO_FULL="$(echo "${file_info}" | jq -r '.repo')"
  FILE_PATH="$(echo "${file_info}" | jq -r '.path')"

  FILE_CONTENT="$(gh_rest GET "/repos/${REPO_FULL}/contents/${FILE_PATH}" 2>/dev/null || echo '{}')"
  DECODED="$(echo "${FILE_CONTENT}" | jq -r '.content // ""' | base64 -d 2>/dev/null || echo "")"

  if [[ -z "${DECODED}" ]]; then
    continue
  fi

  SECRET_NAMES="$(echo "${DECODED}" | grep -oE 'secrets\.[A-Za-z_][A-Za-z0-9_]*' | sed 's/secrets\.//' | sort -u | grep -iv '^GITHUB_TOKEN$' || true)"

  if [[ -n "${SECRET_NAMES}" ]]; then
    SECRET_JSON="$(echo "${SECRET_NAMES}" | jq -R -s 'split("\n") | map(select(length > 0))')"
    ENV_MAPPINGS="$(echo "${DECODED}" | grep -E '^\s+\w+:.*\$\{\{\s*secrets\.' | sed 's/^[[:space:]]*//' | head -20 || true)"
    ENV_JSON="$(echo "${ENV_MAPPINGS}" | jq -R -s 'split("\n") | map(select(length > 0))')"

    echo "{\"repo\": \"${REPO_FULL}\", \"workflow\": \"${FILE_PATH}\", \"secrets\": ${SECRET_JSON}, \"env_mappings\": ${ENV_JSON}}" >> "${REPORT_DIR}/_wf_tmp.jsonl"
  fi

  PROCESSED=$((PROCESSED + 1))
  if [[ $((PROCESSED % 5)) -eq 0 ]]; then
    sleep 2
  fi
done

if [[ -f "${REPORT_DIR}/_wf_tmp.jsonl" ]]; then
  WORKFLOW_SECRETS="$(cat "${REPORT_DIR}/_wf_tmp.jsonl" | jq -s '.' 2>/dev/null || echo "[]")"
  rm -f "${REPORT_DIR}/_wf_tmp.jsonl"
else
  WORKFLOW_SECRETS="[]"
fi

WORKFLOW_SECRET_COUNT="$(echo "${WORKFLOW_SECRETS}" | jq 'length')"
echo "   Found ${WORKFLOW_SECRET_COUNT} workflows using custom secrets"
echo "${WORKFLOW_SECRETS}" | jq '.' > "${REPORT_DIR}/workflow_secrets.json"

echo ""
echo ">> Done: workflow_secrets.json"
