#!/usr/bin/env bash
# =============================================================================
# Step: Fetch Organization Repositories & Members
# Outputs: reports/repositories.json, reports/members.json
# =============================================================================
set -euo pipefail
source "$(dirname "$0")/lib.sh"

echo "============================================"
echo "  Fetch Org Data: ${ORG_NAME}"
echo "============================================"
validate_auth

# --- Repositories (GraphQL) ---
echo ""
echo ">> Fetching organization repositories..."

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
echo "${ALL_REPOS}" | jq '.' > "${REPORT_DIR}/repositories.json"

# --- Members (GraphQL) ---
echo ""
echo ">> Fetching organization members..."

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
echo "${ALL_MEMBERS}" | jq '.' > "${REPORT_DIR}/members.json"

echo ""
echo ">> Done: repositories.json, members.json"
