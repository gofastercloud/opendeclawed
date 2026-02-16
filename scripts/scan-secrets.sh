#!/usr/bin/env bash
###############################################################################
# scan-secrets.sh — Run TruffleHog against the repo
#
# Usage:
#   ./scripts/scan-secrets.sh              # scan uncommitted changes
#   ./scripts/scan-secrets.sh --full       # scan entire git history
#   ./scripts/scan-secrets.sh --staged     # scan staged files only (pre-commit)
###############################################################################
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "${SCRIPT_DIR}")"

# Check for trufflehog
if ! command -v trufflehog >/dev/null 2>&1; then
    echo -e "${RED}[x] trufflehog not found.${NC}"
    echo ""
    echo "  Install:"
    echo "    macOS:  brew install trufflehog"
    echo "    Linux:  curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin"
    echo "    Docker: docker run --rm -v \"\$(pwd):/repo\" trufflesecurity/trufflehog:latest git file:///repo"
    echo ""
    exit 1
fi

MODE="${1:-}"
CONFIG="${REPO_DIR}/.trufflehog-config.yaml"
EXCLUDE_ARG=""
if [ -f "${CONFIG}" ]; then
    EXCLUDE_ARG="--exclude-paths=${CONFIG}"
fi

echo -e "${GREEN}[+]${NC} TruffleHog secrets scan"
echo ""

case "${MODE}" in
    --full)
        echo -e "  Scanning ${YELLOW}entire git history${NC}..."
        trufflehog git "file://${REPO_DIR}" \
            --fail \
            --no-update \
            ${EXCLUDE_ARG} \
            2>&1
        ;;
    --staged)
        echo -e "  Scanning ${YELLOW}staged changes only${NC}..."
        trufflehog git "file://${REPO_DIR}" \
            --since-branch HEAD \
            --fail \
            --no-update \
            ${EXCLUDE_ARG} \
            2>&1
        ;;
    *)
        echo -e "  Scanning ${YELLOW}current working tree${NC}..."
        trufflehog filesystem "${REPO_DIR}" \
            --fail \
            --no-update \
            ${EXCLUDE_ARG} \
            2>&1
        ;;
esac

EXIT_CODE=$?
echo ""
if [ ${EXIT_CODE} -eq 0 ]; then
    echo -e "${GREEN}[+] No secrets detected.${NC}"
else
    echo -e "${RED}[x] SECRETS FOUND — review output above and remove them before committing.${NC}"
    echo -e "${RED}    If these are false positives, add the path to .trufflehog-config.yaml${NC}"
fi
exit ${EXIT_CODE}
