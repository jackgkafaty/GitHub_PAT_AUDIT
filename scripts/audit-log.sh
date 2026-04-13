#!/usr/bin/env bash
# =============================================================================
# Step: Query Audit Log for PAT Events & Token Access
# Outputs: reports/audit_pat_events.json, reports/audit_token_access.json,
#          reports/actor_summary.json
# =============================================================================
set -euo pipefail
source "$(dirname "$0")/lib.sh"

echo "============================================"
echo "  Audit Log: ${ORG_NAME}"
echo "  Lookback: ${LOOKBACK_DAYS} days"
echo "============================================"
validate_auth

# --- PAT Lifecycle Events ---
echo ""
echo ">> Querying audit log for PAT lifecycle events..."

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
    break
  fi
done

PAT_AUDIT_COUNT="$(echo "${PAT_AUDIT_EVENTS}" | jq 'length')"
echo "   Found ${PAT_AUDIT_COUNT} PAT lifecycle events"
echo "${PAT_AUDIT_EVENTS}" | jq '.' > "${REPORT_DIR}/audit_pat_events.json"

# --- Token Authentication Events ---
echo ""
echo ">> Querying audit log for token-based access events..."

TOKEN_ACCESS_EVENTS="$(gh_rest_paginated "/orgs/${ORG_NAME}/audit-log?phrase=created:>=${LOOKBACK_DATE}&include=all" 100 2>/dev/null || echo "[]")"

TOKEN_AUTH_EVENTS="$(echo "${TOKEN_ACCESS_EVENTS}" | jq '[.[] | select(
  .programmatic_access_type != null or
  .token_id != null or
  .hashed_token != null or
  .credential_authorized_at != null or
  (.actor_is_bot == true)
)]' 2>/dev/null || echo "[]")"

TOKEN_AUTH_COUNT="$(echo "${TOKEN_AUTH_EVENTS}" | jq 'length')"
echo "   Found ${TOKEN_AUTH_COUNT} token-authenticated events"
echo "${TOKEN_AUTH_EVENTS}" | jq '.' > "${REPORT_DIR}/audit_token_access.json"

# --- Actor Summary ---
echo ""
echo ">> Building actor summary..."

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
echo "   Identified ${ACTOR_COUNT} unique actors"
echo "${ACTOR_SUMMARY}" | jq '.' > "${REPORT_DIR}/actor_summary.json"

echo ""
echo ">> Done: audit_pat_events.json, audit_token_access.json, actor_summary.json"
