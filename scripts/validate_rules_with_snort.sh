#!/usr/bin/env bash

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RULES_FILE="$PROJECT_ROOT/data/processed/person1_rules.rules"
SNORT_CONFIG="${SNORT_CONFIG:-/usr/local/etc/snort/snort.lua}"

if ! command -v snort >/dev/null 2>&1; then
  echo "Snort is not installed. Skipping runtime rule validation."
  echo "Install Snort and re-run this script to validate $RULES_FILE."
  exit 1
fi

if [[ ! -f "$SNORT_CONFIG" ]]; then
  echo "Snort config not found: $SNORT_CONFIG"
  echo "Set SNORT_CONFIG to a valid snort.lua path and re-run."
  exit 1
fi

exec snort -c "$SNORT_CONFIG" -R "$RULES_FILE" --warn-all --pedantic
