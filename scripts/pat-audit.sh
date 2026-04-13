#!/usr/bin/env bash
# =============================================================================
# PAT Audit Script for GitHub Organizations
# =============================================================================
# Queries GitHub REST & GraphQL APIs to produce a comprehensive report of:
#   1. Fine-grained PATs with org access (SAML SSO credential authorizations)
#   2. Audit log events related to PAT usage (who accessed what, when)
#   3. Organization repositories inventory
#   4. Org member list for cross-referencing
#
# Required environment variables:
#   ORG_PAT       - A classic PAT with scopes: admin:org, read:audit_log, read:org, repo
#   ORG_NAME      - The GitHub organization slug
#   LOOKBACK_DAYS - How many days back to scan the audit log (default: 30)
#
# Required PAT scopes (classic PAT):
#   - admin:org       (for credential-authorizations / SAML SSO)
#   - read:audit_log  (for audit log queries)
#   - read:org        (for listing members, repos)
#   - repo            (for listing all repos including private)
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
API_BASE="https://api.github.com"
GRAPHQL_URL="https://api.github.com/graphql"
API_VERSION="${GITHUB_API_VERSION:-2026-03-10}"

if [[ -z "${ORG_PAT:-}" ]]; then
  echo "::error::ORG_PAT secret is not set. Please configure it in repository secrets."
  exit 1
fi

if [[ -z "${ORG_NAME:-}" ]]; then
  echo "::error::ORG_NAME is not set. Provide it via vars.GITHUB_ORG_NAME or workflow input."
  exit 1
fi

LOOKBACK_DAYS="${LOOKBACK_DAYS:-30}"
REPORT_DIR="./reports"
mkdir -p "$REPORT_DIR"

TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
LOOKBACK_DATE="$(date -u -d "${LOOKBACK_DAYS} days ago" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v-"${LOOKBACK_DAYS}"d +%Y-%m-%dT%H:%M:%SZ)"

echo "============================================"
echo "  PAT Audit Report for: ${ORG_NAME}"
echo "  Generated: ${TIMESTAMP}"
echo "  Lookback:  ${LOOKBACK_DAYS} days (since ${LOOKBACK_DATE})"
echo "============================================"

# ---------------------------------------------------------------------------
# Helper: authenticated curl for REST
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
# Helper: authenticated curl for GraphQL
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
# Helper: paginated REST fetch (collects all pages into a JSON array)
# ---------------------------------------------------------------------------
gh_rest_paginated() {
  local endpoint="${1}"
  local per_page="${2:-100}"
  local results="[]"
  local page=1
  local max_pages=50  # safety limit

  while [[ $page -le $max_pages ]]; do
    local separator="?"
    if [[ "${endpoint}" == *"?"* ]]; then
      separator="&"
    fi
    local response
    response="$(gh_rest GET "${endpoint}${separator}per_page=${per_page}&page=${page}" 2>/dev/null || echo "[]")"

    # Check if response is empty array or error
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

# =============================================================================
# SECTION 1: Validate PAT & Verify Authentication
# =============================================================================
echo ""
echo ">> Step 1: Validating PAT authentication..."

AUTH_CHECK="$(gh_rest GET "/user" 2>/dev/null || echo "{}")"
AUTH_USER="$(echo "${AUTH_CHECK}" | jq -r '.login // "UNKNOWN"')"

if [[ "${AUTH_USER}" == "UNKNOWN" ]]; then
  echo "::error::Failed to authenticate with the provided PAT."
  exit 1
fi

echo "   Authenticated as: ${AUTH_USER}"

# Verify org access
ORG_INFO="$(gh_rest GET "/orgs/${ORG_NAME}" 2>/dev/null || echo "{}")"
ORG_ID="$(echo "${ORG_INFO}" | jq -r '.id // "UNKNOWN"')"

if [[ "${ORG_ID}" == "UNKNOWN" ]]; then
  echo "::error::Cannot access organization '${ORG_NAME}'. Check PAT scopes and org membership."
  exit 1
fi

echo "   Organization: ${ORG_NAME} (ID: ${ORG_ID})"

# =============================================================================
# SECTION 2: List Organization Repositories (via GraphQL)
# =============================================================================
echo ""
echo ">> Step 2: Fetching organization repositories via GraphQL..."

REPOS_FILE="${REPORT_DIR}/repositories.json"
ALL_REPOS="[]"
HAS_NEXT="true"
CURSOR=""

while [[ "${HAS_NEXT}" == "true" ]]; do
  AFTER_CLAUSE=""
  if [[ -n "${CURSOR}" ]]; then
    AFTER_CLAUSE=", after: \\\"${CURSOR}\\\""
  fi

  GRAPHQL_QUERY="{\"query\": \"query { organization(login: \\\"${ORG_NAME}\\\") { repositories(first: 100${AFTER_CLAUSE}) { pageInfo { hasNextPage endCursor } nodes { name nameWithOwner isPrivate isArchived createdAt updatedAt pushedAt } } } }\"}"

  RESPONSE="$(gh_graphql "${GRAPHQL_QUERY}" 2>/dev/null || echo "{}")"

  REPOS_BATCH="$(echo "${RESPONSE}" | jq '.data.organization.repositories.nodes // []')"
  ALL_REPOS="$(echo "${ALL_REPOS}" "${REPOS_BATCH}" | jq -s '.[0] + .[1]')"

  HAS_NEXT="$(echo "${RESPONSE}" | jq -r '.data.organization.repositories.pageInfo.hasNextPage // false')"
  CURSOR="$(echo "${RESPONSE}" | jq -r '.data.organization.repositories.pageInfo.endCursor // empty')"
done

REPO_COUNT="$(echo "${ALL_REPOS}" | jq 'length')"
echo "   Found ${REPO_COUNT} repositories"
echo "${ALL_REPOS}" | jq '.' > "${REPOS_FILE}"

# =============================================================================
# SECTION 3: List Organization Members (via GraphQL)
# =============================================================================
echo ""
echo ">> Step 3: Fetching organization members via GraphQL..."

MEMBERS_FILE="${REPORT_DIR}/members.json"
ALL_MEMBERS="[]"
HAS_NEXT="true"
CURSOR=""

while [[ "${HAS_NEXT}" == "true" ]]; do
  AFTER_CLAUSE=""
  if [[ -n "${CURSOR}" ]]; then
    AFTER_CLAUSE=", after: \\\"${CURSOR}\\\""
  fi

  GRAPHQL_QUERY="{\"query\": \"query { organization(login: \\\"${ORG_NAME}\\\") { membersWithRole(first: 100${AFTER_CLAUSE}) { pageInfo { hasNextPage endCursor } nodes { login name email createdAt } edges { role } } } }\"}"

  RESPONSE="$(gh_graphql "${GRAPHQL_QUERY}" 2>/dev/null || echo "{}")"

  MEMBERS_BATCH="$(echo "${RESPONSE}" | jq '[.data.organization.membersWithRole as $m | range($m.nodes | length) | {login: $m.nodes[.].login, name: $m.nodes[.].name, email: $m.nodes[.].email, role: $m.edges[.].role, createdAt: $m.nodes[.].createdAt}] // []')"
  ALL_MEMBERS="$(echo "${ALL_MEMBERS}" "${MEMBERS_BATCH}" | jq -s '.[0] + .[1]')"

  HAS_NEXT="$(echo "${RESPONSE}" | jq -r '.data.organization.membersWithRole.pageInfo.hasNextPage // false')"
  CURSOR="$(echo "${RESPONSE}" | jq -r '.data.organization.membersWithRole.pageInfo.endCursor // empty')"
done

MEMBER_COUNT="$(echo "${ALL_MEMBERS}" | jq 'length')"
echo "   Found ${MEMBER_COUNT} members"
echo "${ALL_MEMBERS}" | jq '.' > "${MEMBERS_FILE}"

# =============================================================================
# SECTION 4: SAML SSO Credential Authorizations (PATs & SSH Keys)
# Endpoint: GET /orgs/{org}/credential-authorizations
# Works with classic PAT (read:org) or fine-grained PAT (Administration: read)
# Available on ALL plans — requires SAML SSO to be configured on the org
# Supports ?login= filter to narrow by specific user
# Response includes: login, credential_id, credential_type, token_last_eight,
#   credential_authorized_at, credential_accessed_at, authorized_credential_expires_at, scopes
# =============================================================================
echo ""
echo ">> Step 4: Fetching SAML SSO credential authorizations..."
echo "   (Available on all plans; requires SAML SSO enabled on org)"

CREDS_FILE="${REPORT_DIR}/credential_authorizations.json"
CREDS_DATA="$(gh_rest_paginated "/orgs/${ORG_NAME}/credential-authorizations" 100 2>/dev/null || echo "[]")"

# Filter to PATs only
PAT_CREDS="$(echo "${CREDS_DATA}" | jq '[.[] | select(.credential_type == "personal access token")]' 2>/dev/null || echo "[]")"
PAT_CRED_COUNT="$(echo "${PAT_CREDS}" | jq 'length')"

echo "   Found ${PAT_CRED_COUNT} authorized PATs via SAML SSO"

# Also count SSH keys and other credential types
SSH_CREDS="$(echo "${CREDS_DATA}" | jq '[.[] | select(.credential_type == "SSH key")]' 2>/dev/null || echo "[]")"
SSH_CRED_COUNT="$(echo "${SSH_CREDS}" | jq 'length')"
TOTAL_CRED_COUNT="$(echo "${CREDS_DATA}" | jq 'length' 2>/dev/null || echo "0")"

echo "   Found ${SSH_CRED_COUNT} authorized SSH keys via SAML SSO"
echo "   Total credentials: ${TOTAL_CRED_COUNT}"

echo "${CREDS_DATA}" | jq '.' > "${CREDS_FILE}"

# =============================================================================
# SECTION 5: Audit Log - PAT-related Events
# =============================================================================
echo ""
echo ">> Step 5: Querying audit log for PAT-related events..."

AUDIT_PAT_FILE="${REPORT_DIR}/audit_pat_events.json"

# Search for personal access token events in audit log
# Key audit actions for PATs:
#   - personal_access_token.access_granted
#   - personal_access_token.access_denied
#   - personal_access_token.request_created
#   - personal_access_token.request_cancelled
#   - personal_access_token.access_revoked
#   - personal_access_token.credential_regenerated

PAT_AUDIT_EVENTS="[]"
AUDIT_PHRASES=(
  "action:personal_access_token created:>=${LOOKBACK_DATE}"
  "action:personal_access_token. created:>=${LOOKBACK_DATE}"
)

for phrase in "${AUDIT_PHRASES[@]}"; do
  ENCODED_PHRASE="$(python3 -c "import urllib.parse; print(urllib.parse.quote('${phrase}'))" 2>/dev/null || echo "${phrase}")"
  EVENTS="$(gh_rest_paginated "/orgs/${ORG_NAME}/audit-log?phrase=${ENCODED_PHRASE}&include=all" 100 2>/dev/null || echo "[]")"
  EVENT_COUNT="$(echo "${EVENTS}" | jq 'length' 2>/dev/null || echo "0")"
  if [[ "${EVENT_COUNT}" -gt 0 ]]; then
    PAT_AUDIT_EVENTS="$(echo "${PAT_AUDIT_EVENTS}" "${EVENTS}" | jq -s '.[0] + .[1] | unique_by(._document_id // .["@timestamp"])')"
    break  # Found events with this phrase pattern
  fi
done

PAT_AUDIT_COUNT="$(echo "${PAT_AUDIT_EVENTS}" | jq 'length')"
echo "   Found ${PAT_AUDIT_COUNT} PAT-related audit log events"
echo "${PAT_AUDIT_EVENTS}" | jq '.' > "${AUDIT_PAT_FILE}"

# =============================================================================
# SECTION 6: Audit Log - Token Authentication Events
# =============================================================================
echo ""
echo ">> Step 6: Querying audit log for token-based authentication events..."

AUDIT_AUTH_FILE="${REPORT_DIR}/audit_token_access.json"

# Search for programmatic (token-based) access patterns
# These include: API calls made with PATs showing actor + action + repo
TOKEN_ACCESS_EVENTS="$(gh_rest_paginated "/orgs/${ORG_NAME}/audit-log?phrase=created:>=${LOOKBACK_DATE}&include=all" 100 2>/dev/null || echo "[]")"

# Filter for events that have programmatic_access_type or token-related fields
TOKEN_AUTH_EVENTS="$(echo "${TOKEN_ACCESS_EVENTS}" | jq '[.[] | select(
  .programmatic_access_type != null or
  .token_id != null or
  .hashed_token != null or
  .credential_authorized_at != null or
  (.actor_is_bot == true)
)]' 2>/dev/null || echo "[]")"

TOKEN_AUTH_COUNT="$(echo "${TOKEN_AUTH_EVENTS}" | jq 'length')"
echo "   Found ${TOKEN_AUTH_COUNT} token-authenticated audit events"
echo "${TOKEN_AUTH_EVENTS}" | jq '.' > "${AUDIT_AUTH_FILE}"

# =============================================================================
# SECTION 7: Audit Log - Actor Summary (users/bots using PATs)
# =============================================================================
echo ""
echo ">> Step 7: Building actor access summary from audit log..."

ACTOR_SUMMARY_FILE="${REPORT_DIR}/actor_summary.json"

# Summarize all audit events by actor to identify who is making API calls
ACTOR_SUMMARY="$(echo "${TOKEN_ACCESS_EVENTS}" | jq '
  group_by(.actor) |
  map({
    actor: .[0].actor,
    total_events: length,
    actions: ([.[].action] | unique),
    first_seen: ([.[]."@timestamp"] | min | . / 1000 | todate),
    last_seen: ([.[]."@timestamp"] | max | . / 1000 | todate),
    repos_accessed: ([.[].repo // empty] | unique),
    has_programmatic_access: (any(.programmatic_access_type != null)),
    is_bot: (any(.actor_is_bot == true))
  }) |
  sort_by(-.total_events)
' 2>/dev/null || echo "[]")"

ACTOR_COUNT="$(echo "${ACTOR_SUMMARY}" | jq 'length')"
echo "   Identified ${ACTOR_COUNT} unique actors in audit log"
echo "${ACTOR_SUMMARY}" | jq '.' > "${ACTOR_SUMMARY_FILE}"

# =============================================================================
# SECTION 8: Generate Consolidated Report
# =============================================================================
echo ""
echo ">> Step 8: Generating consolidated report..."

REPORT_FILE="${REPORT_DIR}/pat-audit-report.md"

cat > "${REPORT_FILE}" << REPORT_HEADER
# PAT Audit Report: ${ORG_NAME}

**Generated:** ${TIMESTAMP}
**Authenticated As:** ${AUTH_USER}
**Lookback Period:** ${LOOKBACK_DAYS} days (since ${LOOKBACK_DATE})
**Organization ID:** ${ORG_ID}

---

## Summary

| Metric | Count |
|--------|-------|
| Total Repositories | ${REPO_COUNT} |
| Total Members | ${MEMBER_COUNT} |
| SAML SSO Authorized PATs | ${PAT_CRED_COUNT} |
| SAML SSO Authorized SSH Keys | ${SSH_CRED_COUNT} |
| PAT-Related Audit Events | ${PAT_AUDIT_COUNT} |
| Token Auth Audit Events | ${TOKEN_AUTH_COUNT} |
| Unique Actors in Audit Log | ${ACTOR_COUNT} |

---

## 1. SAML SSO Authorized Personal Access Tokens

These are PATs that have been authorized for SAML SSO access to the organization.
This section is only populated if your organization uses SAML SSO.

REPORT_HEADER

if [[ "${PAT_CRED_COUNT}" -gt 0 ]]; then
  echo "| User | Credential ID | Token (last 8) | Authorized At | Last Accessed | Expires At | Scopes |" >> "${REPORT_FILE}"
  echo "|------|--------------|-----------------|---------------|---------------|------------|--------|" >> "${REPORT_FILE}"

  echo "${PAT_CREDS}" | jq -r '.[] | "| \(.login) | \(.credential_id) | `\(.token_last_eight)` | \(.credential_authorized_at) | \(.credential_accessed_at // "Never") | \(.authorized_credential_expires_at // "Never") | \(.scopes | join(", ")) |"' >> "${REPORT_FILE}"
else
  echo "_No SAML SSO authorized PATs found. This is expected if the organization does not use SAML SSO._" >> "${REPORT_FILE}"
  echo "" >> "${REPORT_FILE}"
  echo "> **Note:** If your org does not use SAML SSO, PATs (classic) cannot be enumerated" >> "${REPORT_FILE}"
  echo "> via API. Use the audit log sections below for visibility into PAT usage." >> "${REPORT_FILE}"
fi

cat >> "${REPORT_FILE}" << 'SECTION2'

---

## 2. PAT-Related Audit Log Events

Events from the organization audit log related to personal access token lifecycle
(creation, approval, denial, revocation).

SECTION2

if [[ "${PAT_AUDIT_COUNT}" -gt 0 ]]; then
  echo "| Timestamp | Action | Actor | User | Details |" >> "${REPORT_FILE}"
  echo "|-----------|--------|-------|------|---------|" >> "${REPORT_FILE}"

  echo "${PAT_AUDIT_EVENTS}" | jq -r '.[] | "| \(."@timestamp" // .created_at | if type == "number" then . / 1000 | todate else . end) | \(.action) | \(.actor // "N/A") | \(.user // "N/A") | \(.repo // .org // "—") |"' >> "${REPORT_FILE}" 2>/dev/null || true
else
  echo "_No PAT-related audit events found in the last ${LOOKBACK_DAYS} days._" >> "${REPORT_FILE}"
fi

cat >> "${REPORT_FILE}" << 'SECTION3'

---

## 3. Token-Authenticated Access Events

Audit log entries identified as token-based (programmatic) access, indicating
a PAT or bot was used.

SECTION3

if [[ "${TOKEN_AUTH_COUNT}" -gt 0 ]]; then
  echo "| Timestamp | Action | Actor | Repository | Access Type |" >> "${REPORT_FILE}"
  echo "|-----------|--------|-------|------------|-------------|" >> "${REPORT_FILE}"

  echo "${TOKEN_AUTH_EVENTS}" | jq -r '.[0:200] | .[] | "| \(."@timestamp" // .created_at | if type == "number" then . / 1000 | todate else . end) | \(.action) | \(.actor // "N/A") | \(.repo // "N/A") | \(.programmatic_access_type // "token") |"' >> "${REPORT_FILE}" 2>/dev/null || true

  if [[ "${TOKEN_AUTH_COUNT}" -gt 200 ]]; then
    echo "" >> "${REPORT_FILE}"
    echo "_Showing first 200 of ${TOKEN_AUTH_COUNT} events. See \`audit_token_access.json\` for full data._" >> "${REPORT_FILE}"
  fi
else
  echo "_No token-authenticated audit events found in the last ${LOOKBACK_DAYS} days._" >> "${REPORT_FILE}"
fi

cat >> "${REPORT_FILE}" << 'SECTION4'

---

## 4. Actor Summary (Users & Bots Accessing via API)

Unique actors observed in the audit log, sorted by activity volume.
Actors flagged as bots or with programmatic access are highlighted.

SECTION4

if [[ "${ACTOR_COUNT}" -gt 0 ]]; then
  echo "| Actor | Events | Bot? | Programmatic? | First Seen | Last Seen | Repos Accessed | Actions |" >> "${REPORT_FILE}"
  echo "|-------|--------|------|---------------|------------|-----------|----------------|---------|" >> "${REPORT_FILE}"

  echo "${ACTOR_SUMMARY}" | jq -r '.[] | "| \(.actor) | \(.total_events) | \(if .is_bot then "Yes" else "No" end) | \(if .has_programmatic_access then "Yes" else "No" end) | \(.first_seen) | \(.last_seen) | \(.repos_accessed | length) | \(.actions | length) unique |"' >> "${REPORT_FILE}" 2>/dev/null || true
else
  echo "_No actors found in audit log for the specified period._" >> "${REPORT_FILE}"
fi

cat >> "${REPORT_FILE}" << 'SECTION5'

---

## 5. Organization Members

| Login | Name | Role | Account Created |
|-------|------|------|----------------|
SECTION5

echo "${ALL_MEMBERS}" | jq -r '.[] | "| \(.login) | \(.name // "—") | \(.role // "—") | \(.createdAt // "—") |"' >> "${REPORT_FILE}" 2>/dev/null || true

cat >> "${REPORT_FILE}" << 'SECTION6'

---

## 6. Repository Inventory

| Repository | Private | Archived | Last Push |
|-----------|---------|----------|-----------|
SECTION6

echo "${ALL_REPOS}" | jq -r '.[] | "| \(.nameWithOwner) | \(.isPrivate) | \(.isArchived) | \(.pushedAt // "Never") |"' >> "${REPORT_FILE}" 2>/dev/null || true

cat >> "${REPORT_FILE}" << 'FOOTER'

---

## Data Files

The following JSON data files are included in this artifact:

| File | Description |
|------|-------------|
| `repositories.json` | All org repositories with metadata |
| `members.json` | All org members with roles |
| `credential_authorizations.json` | SAML SSO authorized credentials (PATs + SSH keys) |
| `audit_pat_events.json` | Audit log events related to PAT lifecycle |
| `audit_token_access.json` | Audit log events with token-based authentication |
| `actor_summary.json` | Aggregated actor activity summary |

---

*Report generated by [PAT Audit GitHub Action](../.github/workflows/pat-audit.yml)*
FOOTER

echo ""
echo "============================================"
echo "  Report generated: ${REPORT_FILE}"
echo "  Data files in: ${REPORT_DIR}/"
echo "============================================"
echo ""
echo ">> Files produced:"
ls -la "${REPORT_DIR}/"
