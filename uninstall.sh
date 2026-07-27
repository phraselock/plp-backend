#!/bin/bash
# plp-backend uninstaller
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/phraselock/plp-backend/main/uninstall.sh -o uninstall.sh
#   sudo bash uninstall.sh
#
set -euo pipefail

INSTALL_DIR="/opt/phraselock/backend"
SERVICE_NAME="plp-backend"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

# ---------------------------------------------------------------------------
# Root check
# ---------------------------------------------------------------------------
if [[ "$(id -u)" -ne 0 ]]; then
  echo "Error: this uninstaller must run as root (sudo)." >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Dialog tool
# ---------------------------------------------------------------------------
DIALOG=$(command -v whiptail 2>/dev/null || command -v dialog 2>/dev/null || true)
if [[ -z "$DIALOG" ]]; then
  echo "Error: whiptail or dialog is required." >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Confirmation
# ---------------------------------------------------------------------------
if ! "$DIALOG" --title "plp-backend Uninstall" --yesno \
    "This will stop and remove the plp-backend service and all its files in:\n\n  ${INSTALL_DIR}\n\nThis includes application.properties, mqtt.properties,\nkeepass.properties, and all databases.\n\nContinue?" \
    14 65; then
  echo "Aborted." >&2
  exit 0
fi

# ---------------------------------------------------------------------------
# Stop and disable service
# ---------------------------------------------------------------------------
echo "Stopping plp-backend..."
systemctl stop    "$SERVICE_NAME" 2>/dev/null || true
systemctl disable "$SERVICE_NAME" 2>/dev/null || true

# ---------------------------------------------------------------------------
# Remove service file and install directory
# ---------------------------------------------------------------------------
rm -f "$SERVICE_FILE"
systemctl daemon-reload
rm -rf "$INSTALL_DIR"

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
"$DIALOG" --title "plp-backend Uninstall — Done" --msgbox \
"plp-backend has been removed.

Removed:
  - systemd service (${SERVICE_NAME})
  - ${INSTALL_DIR}

The 'phraselock' system user was kept in case other
PhraseLock services are still running on this host.
Remove it manually if no longer needed:
  userdel phraselock" 18 65
