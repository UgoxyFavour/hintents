#!/usr/bin/env bash
set -euo pipefail

protocol="${ERST_PROTOCOL_NAME:-erst}"
cli_path="${1:-${ERST_CLI_PATH:-}}"
plist_path="${HOME}/Library/LaunchAgents/com.erst.protocol.plist"

if [[ ! -f "$plist_path" ]]; then
  echo "[FAIL] LaunchAgent plist does not exist at $plist_path" >&2
  exit 1
fi

echo "[OK] LaunchAgent plist exists at $plist_path"

if grep -q "<string>${protocol}</string>" "$plist_path"; then
  echo "[OK] Plist contains the ${protocol} scheme"
else
  echo "[FAIL] Plist does not contain the ${protocol} scheme" >&2
  exit 1
fi

if grep -q "<string>protocol-handler</string>" "$plist_path"; then
  echo "[OK] Plist launches the protocol-handler command"
else
  echo "[FAIL] Plist does not launch the protocol-handler command" >&2
  exit 1
fi

if [[ -n "$cli_path" ]]; then
  if grep -q "<string>${cli_path}</string>" "$plist_path"; then
    echo "[OK] Plist points to CLI executable ${cli_path}"
  else
    echo "[FAIL] Plist does not point to CLI executable ${cli_path}" >&2
    exit 1
  fi
fi

echo "[OK] macOS protocol registration verification succeeded"
