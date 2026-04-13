#!/usr/bin/env bash
# =============================================================================
# Step: Generate Consolidated Report & GitHub Actions Job Summary
# Reads all JSON data from reports/ and produces:
#   - reports/user_pat_matrix.json
#   - reports/pat-audit-report.md
#   - GitHub Actions Job Summary (GITHUB_STEP_SUMMARY)
#
# Only displays users who have PAT activity (SAML creds, audit log, workflow secrets).
# =============================================================================
set -euo pipefail
source "$(dirname "$0")/lib.sh"

echo "============================================"
echo "  Generate Report: ${ORG_NAME}"
echo "============================================"

# ---------------------------------------------------------------------------
# Load data files (gracefully handle missing files)
# ---------------------------------------------------------------------------
load_json() {
  local file="${1}"
  if [[ -f "${file}" ]]; then
    cat "${file}"
  else
    echo "[]"
  fi
}

ALL_REPOS="$(load_json "${REPORT_DIR}/repositories.json")"
ALL_MEMBERS="$(load_json "${REPORT_DIR}/members.json")"
CREDS_DATA="$(load_json "${REPORT_DIR}/credential_authorizations.json")"
PAT_AUDIT_EVENTS="$(load_json "${REPORT_DIR}/audit_pat_events.json")"
TOKEN_AUTH_EVENTS="$(load_json "${REPORT_DIR}/audit_token_access.json")"
ACTOR_SUMMARY="$(load_json "${REPORT_DIR}/actor_summary.json")"
WORKFLOW_SECRETS="$(load_json "${REPORT_DIR}/workflow_secrets.json")"

# Derived data
PAT_CREDS="$(echo "${CREDS_DATA}" | jq '[.[] | select(.credential_type == "personal access token")]' 2>/dev/null || echo "[]")"
SSH_CREDS="$(echo "${CREDS_DATA}" | jq '[.[] | select(.credential_type == "SSH key")]' 2>/dev/null || echo "[]")"

# Counts
REPO_COUNT="$(echo "${ALL_REPOS}" | jq 'length')"
MEMBER_COUNT="$(echo "${ALL_MEMBERS}" | jq 'length')"
PAT_CRED_COUNT="$(echo "${PAT_CREDS}" | jq 'length')"
SSH_CRED_COUNT="$(echo "${SSH_CREDS}" | jq 'length')"
PAT_AUDIT_COUNT="$(echo "${PAT_AUDIT_EVENTS}" | jq 'length')"
TOKEN_AUTH_COUNT="$(echo "${TOKEN_AUTH_EVENTS}" | jq 'length')"
ACTOR_COUNT="$(echo "${ACTOR_SUMMARY}" | jq 'length')"
WORKFLOW_SECRET_COUNT="$(echo "${WORKFLOW_SECRETS}" | jq 'length')"

# Auth info (read from org info, or use env)
AUTH_USER="${AUTH_USER:-$(gh_rest GET "/user" 2>/dev/null | jq -r '.login // "unknown"')}"
ORG_ID="${ORG_ID:-$(gh_rest GET "/orgs/${ORG_NAME}" 2>/dev/null | jq -r '.id // "unknown"')}"

echo "   Repos: ${REPO_COUNT} | Members: ${MEMBER_COUNT}"
echo "   SAML PATs: ${PAT_CRED_COUNT} | Audit PAT events: ${PAT_AUDIT_COUNT}"
echo "   Token auth events: ${TOKEN_AUTH_COUNT} | Workflows with secrets: ${WORKFLOW_SECRET_COUNT}"

# ---------------------------------------------------------------------------
# Build Per-User PAT Activity Matrix
# Only users who appear in ANY PAT-related data source
# ---------------------------------------------------------------------------
echo ""
echo ">> Building per-user PAT activity matrix..."

# Collect all PAT-active usernames from every data source
PAT_ACTIVE_USERS="$(jq -n \
  --argjson creds "${PAT_CREDS}" \
  --argjson pat_events "${PAT_AUDIT_EVENTS}" \
  --argjson token_events "${TOKEN_AUTH_EVENTS}" \
  --argjson actors "${ACTOR_SUMMARY}" \
  '
  # Users from SAML SSO credentials
  ([$creds[].login] // []) +
  # Actors from PAT lifecycle events
  ([$pat_events[].actor // empty] | map(select(. != null))) +
  # Target users from PAT lifecycle events
  ([$pat_events[].user // empty] | map(select(. != null))) +
  # Actors from token auth events (non-bot only)
  ([$token_events[] | select(.actor_is_bot != true) | .actor // empty] | map(select(. != null))) +
  # Actors from actor summary with programmatic access
  ([$actors[] | select(.has_programmatic_access == true) | .actor // empty] | map(select(. != null)))
  | unique | map(select(. != null and . != ""))
' 2>/dev/null || echo "[]")"

PAT_ACTIVE_COUNT="$(echo "${PAT_ACTIVE_USERS}" | jq 'length')"
echo "   Found ${PAT_ACTIVE_COUNT} users with PAT activity"

# Build detailed matrix for each PAT-active user
USER_PAT_MATRIX="$(jq -n \
  --argjson users "${PAT_ACTIVE_USERS}" \
  --argjson creds "${PAT_CREDS}" \
  --argjson token_events "${TOKEN_AUTH_EVENTS}" \
  --argjson pat_events "${PAT_AUDIT_EVENTS}" \
  --argjson actors "${ACTOR_SUMMARY}" \
  --argjson members "${ALL_MEMBERS}" \
  --argjson wf "${WORKFLOW_SECRETS}" \
  '
  ($members | map({key: .login, value: .}) | from_entries) as $member_map |
  [$users[] | . as $user |
  {
    user: $user,
    name: ($member_map[$user].name // null),
    role: ($member_map[$user].role // null),
    saml_pats: [
      $creds[] | select(.login == $user) | {
        token_last_eight: .token_last_eight,
        scopes: (.scopes | join(", ")),
        authorized_at: .credential_authorized_at,
        last_accessed: (.credential_accessed_at // "Never"),
        expires: (.authorized_credential_expires_at // "Never")
      }
    ],
    repos_accessed_with_pat: (
      [$token_events[] | select(.actor == $user and .actor_is_bot != true) | .repo // empty] | unique | map(select(. != ""))
    ),
    token_types_used: (
      [$token_events[] | select(.actor == $user) | .programmatic_access_type // empty] | unique | map(select(. != ""))
    ),
    pat_lifecycle_events: (
      [$pat_events[] | select(.actor == $user or .user == $user) | {
        action: .action,
        timestamp: (."@timestamp" // .created_at | if type == "number" then . / 1000 | todate else . end)
      }]
    ),
    audit_event_count: (
      [$token_events[] | select(.actor == $user and .actor_is_bot != true)] | length
    ),
    first_activity: (
      [$token_events[] | select(.actor == $user) | ."@timestamp" // 0] | min | if . > 0 then . / 1000 | todate else null end
    ),
    last_activity: (
      [$token_events[] | select(.actor == $user) | ."@timestamp" // 0] | max | if . > 0 then . / 1000 | todate else null end
    ),
    is_bot: (
      [$actors[] | select(.actor == $user and .is_bot == true)] | length > 0
    )
  }] | sort_by(-.audit_event_count)
' 2>/dev/null || echo "[]")"

USER_MATRIX_COUNT="$(echo "${USER_PAT_MATRIX}" | jq 'length' 2>/dev/null || echo "0")"
echo "   Built matrix for ${USER_MATRIX_COUNT} PAT-active users"
echo "${USER_PAT_MATRIX}" | jq '.' > "${REPORT_DIR}/user_pat_matrix.json"

# =============================================================================
# Generate Markdown Report
# =============================================================================
echo ""
echo ">> Generating Markdown report..."

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
|--------|------:|
| Total Repositories | ${REPO_COUNT} |
| Total Members | ${MEMBER_COUNT} |
| **Users with PAT Activity** | **${PAT_ACTIVE_COUNT}** |
| SAML SSO Authorized PATs | ${PAT_CRED_COUNT} |
| SAML SSO Authorized SSH Keys | ${SSH_CRED_COUNT} |
| PAT Lifecycle Audit Events | ${PAT_AUDIT_COUNT} |
| Token Auth Audit Events | ${TOKEN_AUTH_COUNT} |
| Unique Actors in Audit Log | ${ACTOR_COUNT} |
| Workflows Using Custom Secrets | ${WORKFLOW_SECRET_COUNT} |

---

## 1. Users with PAT Activity

Users who have created, used, or been associated with a Personal Access Token
across any data source (SAML SSO, audit log, token auth events).

REPORT_HEADER

if [[ "${USER_MATRIX_COUNT}" -gt 0 ]]; then
  echo "| User | Name | Role | Repos Accessed via PAT | Token Types | SAML PATs | Events | Last Active |" >> "${REPORT_FILE}"
  echo "|------|------|------|----------------------|-------------|-----------|-------:|-------------|" >> "${REPORT_FILE}"

  echo "${USER_PAT_MATRIX}" | jq -r '.[] |
    "| \(.user) | \(.name // "—") | \(.role // "—") | \(
      .repos_accessed_with_pat | if length == 0 then "—"
      elif length > 3 then (.[0:3] | join(", ")) + " +\(length - 3) more"
      else join(", ") end
    ) | \(.token_types_used | if length > 0 then join(", ") else "—" end) | \(.saml_pats | length) | \(.audit_event_count) | \(.last_activity // "—") |"
  ' >> "${REPORT_FILE}" 2>/dev/null || true
else
  echo "_No users with PAT activity detected._" >> "${REPORT_FILE}"
fi

cat >> "${REPORT_FILE}" << 'SECTION2'

---

## 2. SAML SSO Authorized Tokens

PATs authorized for SAML SSO access to the organization.
Only populated if the organization uses SAML SSO.

SECTION2

if [[ "${PAT_CRED_COUNT}" -gt 0 ]]; then
  echo "| User | Token (last 8) | Scopes | Authorized At | Last Accessed | Expires |" >> "${REPORT_FILE}"
  echo "|------|:--------------:|--------|---------------|---------------|---------|" >> "${REPORT_FILE}"

  echo "${PAT_CREDS}" | jq -r '.[] | "| \(.login) | `\(.token_last_eight)` | \(.scopes | join(", ")) | \(.credential_authorized_at) | \(.credential_accessed_at // "Never") | \(.authorized_credential_expires_at // "Never") |"' >> "${REPORT_FILE}"
else
  echo "> _No SAML SSO authorized PATs found. Expected if SAML SSO is not enabled._" >> "${REPORT_FILE}"
fi

cat >> "${REPORT_FILE}" << 'SECTION3'

---

## 3. PAT Lifecycle Events

Token creation, approval, denial, and revocation events from the audit log.

SECTION3

if [[ "${PAT_AUDIT_COUNT}" -gt 0 ]]; then
  echo "| Timestamp | Action | Actor | Target User | Repository |" >> "${REPORT_FILE}"
  echo "|-----------|--------|-------|-------------|-----------|" >> "${REPORT_FILE}"

  echo "${PAT_AUDIT_EVENTS}" | jq -r '.[] | "| \(."@timestamp" // .created_at | if type == "number" then . / 1000 | todate else . end) | \(.action) | \(.actor // "N/A") | \(.user // "N/A") | \(.repo // .org // "—") |"' >> "${REPORT_FILE}" 2>/dev/null || true
else
  echo "> _No PAT lifecycle events found in the last ${LOOKBACK_DAYS} days._" >> "${REPORT_FILE}"
fi

cat >> "${REPORT_FILE}" << 'SECTION4'

---

## 4. Token-Authenticated Access Events

API calls made using a PAT or by a bot/app.

SECTION4

if [[ "${TOKEN_AUTH_COUNT}" -gt 0 ]]; then
  echo "| Timestamp | Action | Actor | Repository | Access Type |" >> "${REPORT_FILE}"
  echo "|-----------|--------|-------|------------|-------------|" >> "${REPORT_FILE}"

  echo "${TOKEN_AUTH_EVENTS}" | jq -r '.[0:200] | .[] | "| \(."@timestamp" // .created_at | if type == "number" then . / 1000 | todate else . end) | \(.action) | \(.actor // "N/A") | \(.repo // "N/A") | \(.programmatic_access_type // "token") |"' >> "${REPORT_FILE}" 2>/dev/null || true

  if [[ "${TOKEN_AUTH_COUNT}" -gt 200 ]]; then
    echo "" >> "${REPORT_FILE}"
    echo "_Showing first 200 of ${TOKEN_AUTH_COUNT} events. See \`audit_token_access.json\` for full data._" >> "${REPORT_FILE}"
  fi
else
  echo "> _No token-authenticated access events found._" >> "${REPORT_FILE}"
fi

cat >> "${REPORT_FILE}" << 'SECTION5'

---

## 5. Workflows Using Custom Secrets

Workflow files referencing secrets other than `GITHUB_TOKEN` — likely using a user-created PAT.

SECTION5

if [[ "${WORKFLOW_SECRET_COUNT}" -gt 0 ]]; then
  echo "| Repository | Workflow File | Secrets Referenced |" >> "${REPORT_FILE}"
  echo "|-----------|--------------|-------------------|" >> "${REPORT_FILE}"

  echo "${WORKFLOW_SECRETS}" | jq -r '.[] | "| \(.repo) | `\(.workflow)` | \(.secrets | map("`\(.)`") | join(", ")) |"' >> "${REPORT_FILE}" 2>/dev/null || true
else
  echo "> _No workflows found using custom secrets._" >> "${REPORT_FILE}"
fi

cat >> "${REPORT_FILE}" << 'SECTION6'

---

## 6. Repository Inventory

SECTION6

echo "| Repository | Private | Archived | Last Push |" >> "${REPORT_FILE}"
echo "|-----------|---------|----------|-----------|" >> "${REPORT_FILE}"
echo "${ALL_REPOS}" | jq -r '.[] | "| \(.nameWithOwner) | \(.isPrivate) | \(.isArchived) | \(.pushedAt // "Never") |"' >> "${REPORT_FILE}" 2>/dev/null || true

cat >> "${REPORT_FILE}" << 'FOOTER'

---

## Data Files

| File | Description |
|------|-------------|
| `user_pat_matrix.json` | Per-user PAT activity matrix (PAT-active users only) |
| `repositories.json` | All org repositories with metadata |
| `members.json` | All org members (for cross-reference) |
| `credential_authorizations.json` | SAML SSO authorized credentials |
| `audit_pat_events.json` | Audit log PAT lifecycle events |
| `audit_token_access.json` | Audit log token-authenticated events |
| `actor_summary.json` | Aggregated actor activity summary |
| `workflow_secrets.json` | Workflows using custom secrets |

---

*Report generated by [PAT Audit GitHub Action](../.github/workflows/pat-audit.yml)*
FOOTER

echo "   Report: ${REPORT_FILE}"

# =============================================================================
# GitHub Actions Job Summary
# =============================================================================
if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  echo ""
  echo ">> Writing GitHub Actions Job Summary..."

  SUMMARY="${GITHUB_STEP_SUMMARY}"

  cat >> "${SUMMARY}" << SUMMARY_HEADER
# 🔐 PAT Audit Report — \`${ORG_NAME}\`

| | |
|---|---|
| **Organization** | \`${ORG_NAME}\` |
| **Run Date** | ${TIMESTAMP} |
| **Authenticated As** | \`${AUTH_USER}\` |
| **Lookback Period** | ${LOOKBACK_DAYS} days (since ${LOOKBACK_DATE}) |

---

## 📊 Overview

| Metric | Count |
|:-------|------:|
| Total Repositories | **${REPO_COUNT}** |
| Total Members | **${MEMBER_COUNT}** |
| **Users with PAT Activity** | **${PAT_ACTIVE_COUNT}** |
| SAML SSO Authorized PATs | **${PAT_CRED_COUNT}** |
| PAT Lifecycle Audit Events | **${PAT_AUDIT_COUNT}** |
| Token Auth Audit Events | **${TOKEN_AUTH_COUNT}** |
| Workflows Using Custom Secrets | **${WORKFLOW_SECRET_COUNT}** |

---

## 🧑‍💻 Users with PAT Activity

Users who have created, used, or been associated with a PAT — across SAML SSO, audit log, and token auth events.

SUMMARY_HEADER

  if [[ "${USER_MATRIX_COUNT}" -gt 0 ]]; then
    echo "| User | Name | Role | Repos Accessed via PAT | Token Type | SAML PATs | Events | Last Active |" >> "${SUMMARY}"
    echo "|:-----|:-----|:-----|:----------------------|:-----------|:---------:|-------:|:------------|" >> "${SUMMARY}"
    echo "${USER_PAT_MATRIX}" | jq -r '.[] |
      "| `\(.user)` | \(.name // "—") | \(.role // "—") | \(
        .repos_accessed_with_pat | if length == 0 then "—"
        elif length > 3 then (.[0:3] | join(", ")) + " +\(length - 3) more"
        else join(", ") end
      ) | \(.token_types_used | if length > 0 then join(", ") else "—" end) | \(.saml_pats | length) | \(.audit_event_count) | \(.last_activity // "—") |"
    ' >> "${SUMMARY}" 2>/dev/null || true
  else
    echo "> _No users with PAT activity detected._" >> "${SUMMARY}"
  fi

  cat >> "${SUMMARY}" << 'SAML_HEADER'

---

## 🔑 SAML SSO Authorized Tokens

SAML_HEADER

  if [[ "${PAT_CRED_COUNT}" -gt 0 ]]; then
    echo "| User | Token (last 8) | Scopes | Authorized | Last Accessed | Expires |" >> "${SUMMARY}"
    echo "|:-----|:--------------:|:-------|:-----------|:--------------|:--------|" >> "${SUMMARY}"
    echo "${PAT_CREDS}" | jq -r '.[] | "| `\(.login)` | `\(.token_last_eight)` | \(.scopes | join(", ")) | \(.credential_authorized_at // "—") | \(.credential_accessed_at // "Never") | \(.authorized_credential_expires_at // "Never") |"' >> "${SUMMARY}" 2>/dev/null || true
  else
    echo "> _No SAML SSO authorized PATs found. Expected if SAML SSO is not enabled._" >> "${SUMMARY}"
  fi

  cat >> "${SUMMARY}" << 'PAT_EVENTS_HEADER'

---

## 📋 PAT Lifecycle Events

PAT_EVENTS_HEADER

  if [[ "${PAT_AUDIT_COUNT}" -gt 0 ]]; then
    echo "| Date | Event | Actor | Target User | Repository |" >> "${SUMMARY}"
    echo "|:-----|:------|:------|:------------|:-----------|" >> "${SUMMARY}"
    echo "${PAT_AUDIT_EVENTS}" | jq -r '.[0:50] | .[] |
      "| \(."@timestamp" // .created_at | if type == "number" then . / 1000 | todate else . end) | `\(.action | split(".") | last)` | `\(.actor // "N/A")` | `\(.user // "—")` | \(.repo // "—") |"
    ' >> "${SUMMARY}" 2>/dev/null || true
    if [[ "${PAT_AUDIT_COUNT}" -gt 50 ]]; then
      echo "" >> "${SUMMARY}"
      echo "_Showing 50 of ${PAT_AUDIT_COUNT} events. Download the artifact for full data._" >> "${SUMMARY}"
    fi
  else
    echo "> _No PAT lifecycle events found in the last ${LOOKBACK_DAYS} days._" >> "${SUMMARY}"
  fi

  cat >> "${SUMMARY}" << 'TOKEN_AUTH_HEADER'

---

## 🤖 Token-Authenticated Access

TOKEN_AUTH_HEADER

  if [[ "${TOKEN_AUTH_COUNT}" -gt 0 ]]; then
    echo "| Date | Action | User | Repository | Token Type |" >> "${SUMMARY}"
    echo "|:-----|:-------|:-----|:-----------|:-----------|" >> "${SUMMARY}"
    echo "${TOKEN_AUTH_EVENTS}" | jq -r '.[0:50] | .[] |
      "| \(."@timestamp" // .created_at | if type == "number" then . / 1000 | todate else . end) | `\(.action)` | `\(.actor // "N/A")` | \(.repo // "—") | \(.programmatic_access_type // "classic PAT") |"
    ' >> "${SUMMARY}" 2>/dev/null || true
    if [[ "${TOKEN_AUTH_COUNT}" -gt 50 ]]; then
      echo "" >> "${SUMMARY}"
      echo "_Showing 50 of ${TOKEN_AUTH_COUNT} events. Download the artifact for full data._" >> "${SUMMARY}"
    fi
  else
    echo "> _No token-authenticated access events found._" >> "${SUMMARY}"
  fi

  cat >> "${SUMMARY}" << 'WF_HEADER'

---

## 🔍 Workflows Using Custom Secrets

Workflow files referencing secrets other than `GITHUB_TOKEN` — likely using a user-created PAT.

WF_HEADER

  if [[ "${WORKFLOW_SECRET_COUNT}" -gt 0 ]]; then
    echo "| Repository | Workflow | Secrets Used |" >> "${SUMMARY}"
    echo "|:-----------|:---------|:-------------|" >> "${SUMMARY}"
    echo "${WORKFLOW_SECRETS}" | jq -r '.[0:50] | .[] |
      "| `\(.repo)` | `\(.workflow | split("/") | last)` | \(.secrets | map("`\(.)`") | join(", ")) |"
    ' >> "${SUMMARY}" 2>/dev/null || true
    if [[ "${WORKFLOW_SECRET_COUNT}" -gt 50 ]]; then
      echo "" >> "${SUMMARY}"
      echo "_Showing 50 of ${WORKFLOW_SECRET_COUNT} workflows. Download the artifact for full data._" >> "${SUMMARY}"
    fi
  else
    echo "> _No workflows found using custom secrets._" >> "${SUMMARY}"
  fi

  cat >> "${SUMMARY}" << 'REPOS_HEADER'

---

## 📦 Repository Inventory

REPOS_HEADER

  echo "| Repository | Visibility | Archived | Last Push |" >> "${SUMMARY}"
  echo "|:-----------|:-----------|:--------:|:----------|" >> "${SUMMARY}"
  echo "${ALL_REPOS}" | jq -r '.[0:100] | .[] |
    "| `\(.nameWithOwner)` | \(if .isPrivate then "🔒 Private" else "🌐 Public" end) | \(if .isArchived then "📁 Yes" else "—" end) | \(.pushedAt // "Never") |"
  ' >> "${SUMMARY}" 2>/dev/null || true

  if [[ "${REPO_COUNT}" -gt 100 ]]; then
    echo "" >> "${SUMMARY}"
    echo "_Showing 100 of ${REPO_COUNT} repositories. Download the artifact for full data._" >> "${SUMMARY}"
  fi

  cat >> "${SUMMARY}" << 'SUMMARY_FOOTER'

---

> 📎 **Full data available in the workflow artifact** — download the `pat-audit-report` artifact for complete JSON data files and the detailed Markdown report.
SUMMARY_FOOTER

  echo "   Job summary written to GITHUB_STEP_SUMMARY"
fi

echo ""
echo "============================================"
echo "  Report complete: ${REPORT_FILE}"
echo "  Data files in: ${REPORT_DIR}/"
echo "============================================"
ls -la "${REPORT_DIR}/"
