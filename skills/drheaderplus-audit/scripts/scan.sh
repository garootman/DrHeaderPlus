#!/usr/bin/env bash
# Quick scan wrapper — usage: ./scan.sh <url> [--preset owasp-asvs-v14] [--cross-origin-isolated]
set -euo pipefail

if [ $# -lt 1 ]; then
    echo "Usage: scan.sh <url> [drheader options...]"
    exit 1
fi

URL="$1"
shift

# Ensure drheaderplus is available
if ! command -v drheader &>/dev/null; then
    echo "drheaderplus not found, installing..."
    pip install -q drheaderplus 2>/dev/null || uv pip install -q drheaderplus
fi

drheader scan single "$URL" --output json "$@"
