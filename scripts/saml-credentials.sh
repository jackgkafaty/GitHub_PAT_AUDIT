#!/usr/bin/env bash
# =============================================================================
# Step: Fetch SAML SSO Credential Authorizations
# Outputs: reports/credential_authorizations.json
# =============================================================================
set -euo pipefail
source "$(dirname "$0")/lib.sh"

echo "============================================"
echo "  SAML SSO Credentials: ${ORG_NAME}"
echo "============================================"
validate_auth

echo ""
echo ">> Fetching SAML SSO credential authorizations..."

CREDS_DATA="$(gh_rest_paginated "/orgs/${ORG_NAME}/credential-authorizations" 100 2>/dev/null || echo "[]")"

PAT_CREDS="$(echo "${CREDS_DATA}" | jq '[.[] | select(.credential_type == "personal access token")]' 2>/dev/null || echo "[]")"
PAT_CRED_COUNT="$(echo "${PAT_CREDS}" | jq 'length')"

SSH_CREDS="$(echo "${CREDS_DATA}" | jq '[.[] | select(.credential_type == "SSH key")]' 2>/dev/null || echo "[]")"
SSH_CRED_COUNT="$(echo "${SSH_CREDS}" | jq 'length')"
TOTAL_CRED_COUNT="$(echo "${CREDS_DATA}" | jq 'length' 2>/dev/null || echo "0")"

echo "   Found ${PAT_CRED_COUNT} authorized PATs"
echo "   Found ${SSH_CRED_COUNT} authorized SSH keys"
echo "   Total credentials: ${TOTAL_CRED_COUNT}"

echo "${CREDS_DATA}" | jq '.' > "${REPORT_DIR}/credential_authorizations.json"

echo ""
echo ">> Done: credential_authorizations.json"
