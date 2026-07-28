#!/bin/bash
# plp-backend installer
# Downloads the latest release from GitHub and installs it as a systemd service.
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/phraselock/plp-backend/main/install.sh | sudo bash
#
set -euo pipefail

GITHUB_REPO="phraselock/plp-backend"
SERVICE_NAME="plp-backend"
INSTALL_DIR="/opt/phraselock/backend"
SERVICE_USER="phraselock"
SUMMARY_FILE="/opt/phraselock/backend/backend-setup.txt"

# ---------------------------------------------------------------------------
# Root check
# ---------------------------------------------------------------------------
if [[ "$(id -u)" -ne 0 ]]; then
  echo "Error: this installer must run as root (sudo)." >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Dialog tool
# ---------------------------------------------------------------------------
DIALOG=$(command -v whiptail 2>/dev/null || command -v dialog 2>/dev/null || true)
if [[ -z "$DIALOG" ]]; then
  echo "Installing whiptail..." >&2
  DEBIAN_FRONTEND=noninteractive apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq whiptail
  DIALOG=$(command -v whiptail)
fi

# ---------------------------------------------------------------------------
# curl
# ---------------------------------------------------------------------------
if ! command -v curl >/dev/null 2>&1; then
  DEBIAN_FRONTEND=noninteractive apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl
fi

# ---------------------------------------------------------------------------
# Fetch latest release from GitHub
# ---------------------------------------------------------------------------
echo "Fetching latest release from GitHub (${GITHUB_REPO})..."
RELEASE_JSON=$(curl -fsSL "https://api.github.com/repos/${GITHUB_REPO}/releases/latest")
VERSION=$(echo "$RELEASE_JSON" \
  | grep '"tag_name"' \
  | sed -E 's/.*"tag_name"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/')
JAR_URL=$(echo "$RELEASE_JSON" \
  | grep '"browser_download_url"' \
  | grep '\.jar"' \
  | sed -E 's/.*"browser_download_url"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/')

if [[ -z "$VERSION" || -z "$JAR_URL" ]]; then
  echo "Error: could not parse GitHub release info. Check your internet connection." >&2
  exit 1
fi

JAR_NAME=$(basename "$JAR_URL")
DEMO_KDBX_URL="https://raw.githubusercontent.com/${GITHUB_REPO}/main/keepass-phraselock.kdbx"

# ---------------------------------------------------------------------------
# Helper: read a key from a properties file
# ---------------------------------------------------------------------------
_get() {
  local key="$1" file="$2" default="${3:-}"
  grep "^${key}=" "$file" 2>/dev/null | cut -d= -f2- || echo "$default"
}

# ---------------------------------------------------------------------------
# Read existing config (upgrade-friendly)
# ---------------------------------------------------------------------------
APP_PROPS="$INSTALL_DIR/application.properties"
MQTT_PROPS="$INSTALL_DIR/mqtt.properties"
KEEPASS_PROPS="$INSTALL_DIR/keepass.properties"

E_PORT="8080"
E_IPS="127.0.0.1,::1,[0:0:0:0:0:0:0:1]"
E_MAX_THREADS="10"
E_ADMIN_TOKEN=""
E_KEEPASS_ENABLED="true"
E_PEER_STORE="sqlite"

E_MQTT_URL="ssl://localhost:8883"
E_MQTT_USER="plpbackend"
E_MQTT_PASS=""
E_MQTT_KEY="/opt/phraselock/certs/mqtt_8883.pkcs8.key"
E_MQTT_CERT="/opt/phraselock/certs/mqtt_8883.crt"

E_KP_FILE="/opt/phraselock/backend/keepass-phraselock.kdbx"
E_KP_PASS=""
E_KP_UUID="$(cat /proc/sys/kernel/random/uuid 2>/dev/null || echo "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx")"

if [[ -f "$APP_PROPS" ]]; then
  E_PORT=$(_get server.port "$APP_PROPS" "$E_PORT")
  E_IPS=$(_get allowed.ips "$APP_PROPS" "$E_IPS")
  E_MAX_THREADS=$(_get jetty.maxThreads "$APP_PROPS" "$E_MAX_THREADS")
  E_ADMIN_TOKEN=$(_get admin.token "$APP_PROPS" "")
  E_KEEPASS_ENABLED=$(_get bes.keepass.enabled "$APP_PROPS" "true")
  E_PEER_STORE=$(_get peer.config.store "$APP_PROPS" "sqlite")
fi

if [[ -f "$MQTT_PROPS" ]]; then
  E_MQTT_URL=$(_get broker.url "$MQTT_PROPS" "$E_MQTT_URL")
  E_MQTT_USER=$(_get auth.username "$MQTT_PROPS" "$E_MQTT_USER")
  E_MQTT_PASS=$(_get auth.password "$MQTT_PROPS" "")
  E_MQTT_KEY=$(_get tls.client.key "$MQTT_PROPS" "$E_MQTT_KEY")
  E_MQTT_CERT=$(_get tls.client.cert "$MQTT_PROPS" "$E_MQTT_CERT")
fi

if [[ -f "$KEEPASS_PROPS" ]]; then
  E_KP_FILE=$(_get keepass.file "$KEEPASS_PROPS" "$E_KP_FILE")
  E_KP_PASS=$(_get keepass.password "$KEEPASS_PROPS" "")
  E_KP_UUID=$(_get service.uuid "$KEEPASS_PROPS" "$E_KP_UUID")
fi

TITLE="plp-backend ${VERSION} Setup"

# ---------------------------------------------------------------------------
# Dialog: General settings
# ---------------------------------------------------------------------------
if ! PORT=$("$DIALOG" --title "$TITLE" \
    --inputbox "HTTP port for plp-backend:" 10 55 "$E_PORT" \
    3>&1 1>&2 2>&3); then echo "Aborted." >&2; exit 1; fi

if ! ALLOWED_IPS=$("$DIALOG" --title "$TITLE" \
    --inputbox "Allowed IPs (comma-separated):" 10 70 "$E_IPS" \
    3>&1 1>&2 2>&3); then echo "Aborted." >&2; exit 1; fi

if ! MAX_THREADS=$("$DIALOG" --title "$TITLE" \
    --inputbox "Jetty max threads:" 10 55 "$E_MAX_THREADS" \
    3>&1 1>&2 2>&3); then echo "Aborted." >&2; exit 1; fi

# Admin token — generate once, never overwrite
if [[ -z "$E_ADMIN_TOKEN" ]]; then
  ADMIN_TOKEN=$(openssl rand -hex 32)
  TOKEN_STATUS="Admin token newly generated."
  TOKEN_IS_NEW=true
else
  ADMIN_TOKEN="$E_ADMIN_TOKEN"
  TOKEN_STATUS="Admin token preserved from existing installation."
  TOKEN_IS_NEW=false
fi

# KeePass enabled?
if "$DIALOG" --title "$TITLE" --yesno "Enable KeePass integration?" 8 50; then
  KEEPASS_ENABLED=true
else
  KEEPASS_ENABLED=false
fi

# Peer config store
if "$DIALOG" --title "$TITLE" --yesno \
    "Use Redis as peer config store?\n(No = SQLite, recommended for single-host setups)" 9 60; then
  PEER_STORE=redis
else
  PEER_STORE=sqlite
fi

# ---------------------------------------------------------------------------
# Dialog: MQTT settings
# ---------------------------------------------------------------------------
if ! MQTT_URL=$("$DIALOG" --title "$TITLE (MQTT)" \
    --inputbox "MQTT broker URL (e.g. ssl://your.host:8883):" 10 65 "$E_MQTT_URL" \
    3>&1 1>&2 2>&3); then echo "Aborted." >&2; exit 1; fi

if ! MQTT_USER=$("$DIALOG" --title "$TITLE (MQTT)" \
    --inputbox "MQTT username:" 10 55 "$E_MQTT_USER" \
    3>&1 1>&2 2>&3); then echo "Aborted." >&2; exit 1; fi

if ! MQTT_PASS=$("$DIALOG" --title "$TITLE (MQTT)" \
    --passwordbox "MQTT password:" 10 55 \
    3>&1 1>&2 2>&3); then echo "Aborted." >&2; exit 1; fi

if ! MQTT_KEY=$("$DIALOG" --title "$TITLE (MQTT)" \
    --inputbox "Path to mTLS client private key (.pkcs8.key):" 10 70 "$E_MQTT_KEY" \
    3>&1 1>&2 2>&3); then echo "Aborted." >&2; exit 1; fi

if ! MQTT_CERT=$("$DIALOG" --title "$TITLE (MQTT)" \
    --inputbox "Path to mTLS client certificate (.crt):" 10 70 "$E_MQTT_CERT" \
    3>&1 1>&2 2>&3); then echo "Aborted." >&2; exit 1; fi

# ---------------------------------------------------------------------------
# Dialog: KeePass settings (only when enabled)
# ---------------------------------------------------------------------------
KP_FILE="$E_KP_FILE"
KP_PASS="$E_KP_PASS"
KP_UUID="$E_KP_UUID"

if [[ "$KEEPASS_ENABLED" == true ]]; then
  if ! KP_FILE=$("$DIALOG" --title "$TITLE (KeePass)" \
      --inputbox "Path to .kdbx file:" 10 70 "$E_KP_FILE" \
      3>&1 1>&2 2>&3); then echo "Aborted." >&2; exit 1; fi

  # Pre-fill demo password on fresh install and warn the user
  KP_PASS_DEFAULT="$E_KP_PASS"
  if [[ -z "$KP_PASS_DEFAULT" ]]; then
    KP_PASS_DEFAULT='my$ecretPa$$w0rd'
    "$DIALOG" --title "$TITLE (KeePass)" --msgbox \
'The demo KeePass database uses the default password:

  my$ecretPa$$w0rd

CHANGE IT immediately after installation!
Use KeePassXC: Database → Change Master Password,
then update keepass.properties.' 14 60
  fi

  if ! KP_PASS=$("$DIALOG" --title "$TITLE (KeePass)" \
      --passwordbox "KeePass master password:" 10 55 "$KP_PASS_DEFAULT" \
      3>&1 1>&2 2>&3); then echo "Aborted." >&2; exit 1; fi

  if ! KP_UUID=$("$DIALOG" --title "$TITLE (KeePass)" \
      --inputbox "Service UUID (shown in QR codes on mobile app):" 10 70 "$E_KP_UUID" \
      3>&1 1>&2 2>&3); then echo "Aborted." >&2; exit 1; fi
fi

# ---------------------------------------------------------------------------
# Java 21
# ---------------------------------------------------------------------------
JAVA_MAJOR=0
if command -v java >/dev/null 2>&1; then
  JAVA_MAJOR=$(java -version 2>&1 | head -1 | grep -oE '"[0-9]+' | tr -d '"')
fi

if [[ "$JAVA_MAJOR" -lt 21 ]]; then
  echo "Installing OpenJDK 21..."
  DEBIAN_FRONTEND=noninteractive apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y openjdk-21-jre-headless
  JAVA_STATUS="OpenJDK 21 (headless JRE) installed."
else
  JAVA_STATUS="Java ${JAVA_MAJOR} already present — meets the minimum of 21."
fi

# ---------------------------------------------------------------------------
# System user
# ---------------------------------------------------------------------------
id -u "$SERVICE_USER" >/dev/null 2>&1 \
  || useradd -r -m -s /usr/sbin/nologin "$SERVICE_USER"

# ---------------------------------------------------------------------------
# Download and install JAR
# ---------------------------------------------------------------------------
mkdir -p "$INSTALL_DIR"
echo "Downloading ${JAR_NAME} (${VERSION})..."
curl -fsSL "$JAR_URL" -o "$INSTALL_DIR/$JAR_NAME"
ln -sf "$JAR_NAME" "$INSTALL_DIR/plp-backend.jar"

# Demo KeePass database — only downloaded on fresh install, never overwritten
if [[ ! -f "$INSTALL_DIR/keepass-phraselock.kdbx" ]]; then
  echo "Downloading demo KeePass database..."
  curl -fsSL "$DEMO_KDBX_URL" -o "$INSTALL_DIR/keepass-phraselock.kdbx"
fi

# ---------------------------------------------------------------------------
# application.properties
# ---------------------------------------------------------------------------
cat > "$APP_PROPS" << EOF
# HTTP port.
server.port=${PORT}

# IP addresses allowed to call this service. Comma-separated.
allowed.ips=${ALLOWED_IPS}

# Jetty thread pool.
jetty.minThreads=2
jetty.maxThreads=${MAX_THREADS}

# Credential sources.
bes.keepass.enabled=${KEEPASS_ENABLED}
bes.psono.enabled=false

# Peer config store backend: redis | sqlite
peer.config.store=${PEER_STORE}

# Shared secret for /admin/* routes.
admin.token=${ADMIN_TOKEN}
EOF

# ---------------------------------------------------------------------------
# mqtt.properties
# Generate ECC key pair on first install; preserve on upgrade.
# ---------------------------------------------------------------------------
EXISTING_DPRIV=$(_get bes.id.dpriv "$MQTT_PROPS" "")
EXISTING_XPUBL=$(_get bes.id.xpubl "$MQTT_PROPS" "")
EXISTING_YPUBL=$(_get bes.id.ypubl "$MQTT_PROPS" "")

if [[ -z "$EXISTING_DPRIV" || "$EXISTING_DPRIV" == "changeme" ]]; then
  echo "Generating ECC key pair for message signing..."
  TMP_KEY=$(mktemp)
  openssl ecparam -name prime256v1 -genkey -noout -out "$TMP_KEY"
  RAW=$(openssl ec -in "$TMP_KEY" -text -noout 2>/dev/null)
  EXISTING_DPRIV=$(echo "$RAW" | awk '/^priv:/{found=1; next} found && /^pub:/{found=0} found{print}' | tr -d ' :\n')
  PUB=$(echo "$RAW"           | awk '/^pub:/{found=1; next}  found && /^ASN1/{found=0}  found{print}' | tr -d ' :\n')
  PUB_CLEAN="${PUB:2}"
  LEN=${#PUB_CLEAN}; HALF=$((LEN / 2))
  EXISTING_XPUBL="${PUB_CLEAN:0:$HALF}"
  EXISTING_YPUBL="${PUB_CLEAN:$HALF}"
  rm -f "$TMP_KEY"
  ECC_STATUS="ECC key pair generated automatically."
else
  ECC_STATUS="ECC key pair preserved from existing installation."
fi

cat > "$MQTT_PROPS" << EOF
# MQTT Broker Configuration
broker.url=${MQTT_URL}
client.id=plp-backend-client

# Connection params
keepalive.seconds=45
connect.retry.seconds=5

# Broker authentication
auth.username=${MQTT_USER}
auth.password=${MQTT_PASS}

# ECC key pair for message signing.
# Generate via PhraseLock-Bridge's generateECCKeyPair.sh,
# or set these values through the admin UI at /admin/mqttconfig.
bes.id.dpriv=${EXISTING_DPRIV}
bes.id.xpubl=${EXISTING_XPUBL}
bes.id.ypubl=${EXISTING_YPUBL}

# mTLS client certificate (issued by PhraseLock-Bridge PKI).
tls.client.key=${MQTT_KEY}
tls.client.cert=${MQTT_CERT}
EOF

# ---------------------------------------------------------------------------
# keepass.properties
# ---------------------------------------------------------------------------
cat > "$KEEPASS_PROPS" << EOF
# KeePass Configuration

# Service UUID shown in QR codes on the mobile app.
service.uuid=${KP_UUID}

# Path to the .kdbx file.
keepass.file=${KP_FILE}

# Master password.
keepass.password=${KP_PASS}
EOF

# Secure all config files — they contain credentials
chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
chmod 600 "$APP_PROPS" "$MQTT_PROPS" "$KEEPASS_PROPS"

# ---------------------------------------------------------------------------
# systemd service
# ---------------------------------------------------------------------------
cat > /etc/systemd/system/plp-backend.service << EOF
[Unit]
Description=Phrase-Lock Backend Service
After=network.target

[Service]
User=${SERVICE_USER}
WorkingDirectory=${INSTALL_DIR}
ExecStart=/usr/bin/java -jar ${INSTALL_DIR}/plp-backend.jar
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable plp-backend >/dev/null 2>&1 || true
systemctl restart plp-backend

sleep 2
if systemctl is-active --quiet plp-backend; then
  SERVICE_STATUS="plp-backend is running."
else
  SERVICE_STATUS="WARNING: plp-backend did not start — check: journalctl -u plp-backend"
fi

# ---------------------------------------------------------------------------
# Summary text file
# ---------------------------------------------------------------------------
TOKEN_DISPLAY="(preserved — see ${INSTALL_DIR}/application.properties)"
if [[ "$TOKEN_IS_NEW" == true ]]; then
  TOKEN_DISPLAY="${ADMIN_TOKEN}"
fi

cat > "$SUMMARY_FILE" << EOF
plp-backend ${VERSION} — Installation Summary
$(date)
============================================================

${JAVA_STATUS}
${SERVICE_STATUS}
${TOKEN_STATUS}
${ECC_STATUS}

Admin token:
  ${TOKEN_DISPLAY}

Admin UI:
  http://localhost:${PORT}/admin/config?token=${ADMIN_TOKEN}

KeePass integration: ${KEEPASS_ENABLED}
Peer config store:   ${PEER_STORE}
MQTT broker:         ${MQTT_URL}

Config files (chmod 600):
  ${INSTALL_DIR}/application.properties
  ${INSTALL_DIR}/mqtt.properties
  ${INSTALL_DIR}/keepass.properties

============================================================
nginx — add to your server{} section:

location /admin/ {
    #if (\$ssl_client_verify != SUCCESS) { return 403; } Not required
    proxy_pass          http://localhost:${PORT}/admin/;
    proxy_set_header    Host              \$host;
    proxy_set_header    X-Real-IP         \$remote_addr;
    proxy_set_header    X-Forwarded-For   \$proxy_add_x_forwarded_for;
    proxy_set_header    X-Forwarded-Proto \$scheme;
    proxy_set_header    X-Client-Verify   \$ssl_client_verify;
    proxy_set_header    X-Client-DN       \$ssl_client_s_dn;
}
============================================================

To update: sudo bash install.sh
To remove:  sudo bash uninstall.sh
EOF

chmod 600 "$SUMMARY_FILE"

# ---------------------------------------------------------------------------
# Summary dialog
# ---------------------------------------------------------------------------
TOKEN_LINE=""
if [[ "$TOKEN_IS_NEW" == true ]]; then
  TOKEN_LINE="
Admin token (save this!):
  ${ADMIN_TOKEN}"
fi

"$DIALOG" --title "plp-backend ${VERSION} Setup — Done" --msgbox \
"${JAVA_STATUS}

plp-backend ${VERSION} installed to:
  ${INSTALL_DIR}

${SERVICE_STATUS}
${TOKEN_STATUS}${TOKEN_LINE}
${ECC_STATUS}
KeePass: ${KEEPASS_ENABLED}
Peer store: ${PEER_STORE}
MQTT broker: ${MQTT_URL}

Admin UI:
  http://localhost:${PORT}/admin/config?token=<token>

Config files (chmod 600):
  ${INSTALL_DIR}/application.properties
  ${INSTALL_DIR}/mqtt.properties
  ${INSTALL_DIR}/keepass.properties

Full summary saved to:
  ${SUMMARY_FILE}

To update: sudo bash install.sh
To remove:  sudo bash uninstall.sh" 36 78
