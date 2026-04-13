#!/usr/bin/env bash
# =============================================================================
# PAT Audit — Local Runner
# Runs all audit steps sequentially. For CI, use the parallel workflow instead.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "============================================"
echo "  PAT Audit: ${ORG_NAME:-<ORG_NAME not set>}"
echo "  $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "============================================"

bash "${SCRIPT_DIR}/fetch-org-data.sh"
bash "${SCRIPT_DIR}/saml-credentials.sh"
bash "${SCRIPT_DIR}/audit-log.sh"
bash "${SCRIPT_DIR}/workflow-scanner.sh"
bash "${SCRIPT_DIR}/generate-report.sh"
