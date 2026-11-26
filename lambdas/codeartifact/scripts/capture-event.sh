#!/usr/bin/env bash
# Saves the most recent event the Lambda received into
# testdata/<name>.json for use in unit tests.
set -euo pipefail

name=${1:?usage: capture-event.sh <name>}
root="$(cd "$(dirname "$0")/.." && pwd)"
log_group=$(terraform -chdir="$root/terraform" output -raw log_group_name)

# JSON output merges all result pages (--query with text output runs per page).
aws logs filter-log-events --log-group-name "$log_group" \
  --filter-pattern '{ $.msg = "received event" }' --output json \
  | jq -r '.events[-1].message' \
  | jq '.event' > "$root/testdata/$name.json"

echo "saved testdata/$name.json"
