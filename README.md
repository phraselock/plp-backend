# plp-backend

Backend service for the **PhraseLock** ecosystem.

plp-backend is a lightweight Java service that acts as the central hub between
FIDO2/WebAuthn clients, a KeePass credential store, and an MQTT broker. It is
distributed as a self-contained fat JAR and is designed to run on a Raspberry Pi
or any Linux host sitting inside a local network, behind an nginx reverse proxy.

---

## What it does

### WebAuthn / FIDO2
Handles the full WebAuthn registration and authentication ceremony
(`/phraselock-idp/webauthn/...`). Registered credential metadata is persisted in
a SQLite database (or Redis, configurable).

### KeePass integration
Reads credentials from a local KeePass KDBX v4 file and makes them available to
authenticated clients. A built-in QR-code generator (`/admin/keepass-user`) lets
administrators create per-user provisioning codes that embed the server's ECC
signature key and service UUID — ready to scan with a compatible mobile app.

### MQTT connectivity
Connects to an MQTT broker (plain or mTLS) and exchanges signed messages with
PhraseLock client devices. ECC key pairs for message signing are configured in
`mqtt.properties`.

### Admin web interface
A browser-based configuration UI is available under `/admin/`:

| Path | Purpose |
|---|---|
| `/admin/config` | Hub — links to all editors |
| `/admin/appconfig` | Edit `application.properties` live |
| `/admin/mqttconfig` | Edit `mqtt.properties` live |
| `/admin/keepass` | Edit `keepass.properties` live |
| `/admin/keepass-user` | Manage KeePass users, generate QR codes |

All admin routes are protected by a shared-secret token (`admin.token` in
`application.properties`) that is checked on every request. Access is intended
to be restricted to a single admin via a bookmarked URL containing the token.

---

## Installation

### One-line install (Debian / Ubuntu / Raspberry Pi OS)

```bash
curl -sSL https://raw.githubusercontent.com/phraselock/plp-backend/main/install.sh | sudo bash
```

The installer downloads the latest release from GitHub, installs Java 21 if needed, walks you through all configuration (port, MQTT broker, KeePass, admin token) with a dialog UI, and registers a `plp-backend` systemd service. Re-running the same command upgrades to the latest version while preserving your existing configuration.

A demo KeePass database (`keepass-phraselock.kdbx`) with sample entries is installed automatically. Open it with KeePassXC using the default password, change it to your own, and update `keepass.properties` accordingly.

---

## Requirements

- Java 21 or later
- nginx (recommended) for TLS termination and mTLS client-certificate enforcement
- A KeePass KDBX v4 file (optional — can be disabled)
- An MQTT broker reachable over the network (optional)

---

## Configuration

All configuration is done via `.properties` files placed next to the JAR.
Template files with documented placeholders are bundled inside the JAR and
serve as defaults. An external file overrides individual keys without replacing
the entire template.

| File | Purpose |
|---|---|
| `application.properties` | Port, IP allowlist, thread pool, admin token |
| `mqtt.properties` | Broker URL, credentials, ECC keys, TLS certs |
| `keepass.properties` | KDBX file path, master password, service UUID |

---

## Running

```bash
java -jar plp-backend-<version>.jar
```

Logs are written to stdout. For production use, wrap in a systemd unit.

---

## nginx reverse proxy

The admin interface is designed to sit behind an `nginx` `location /admin/`
block with optional mTLS enforcement:

```nginx
location /admin/ {
    if ($ssl_client_verify != SUCCESS) { return 403; }
    proxy_pass http://localhost:8080/admin/;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Client-Verify $ssl_client_verify;
    proxy_set_header X-Client-DN $ssl_client_s_dn;
}
```

---

## Related projects

- [PhraseLock-Bridge](https://github.com/phraselock/PhraseLock-Bridge) — native Linux installer that bundles this service with nginx, systemd, and certificate tooling.

---

© 2026 iPoxo IT GmbH — All rights reserved
