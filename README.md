# Wazuh Agent Installer

A desktop GUI application that provides a guided interface for installing and configuring a full Wazuh security agent stack on Linux, macOS, and Windows.

---

## Features

- **Sidebar UI:** Intuitive layout with Setup, Enrollment, and Components tabs.
- **Cross-platform support:** Native installation on Linux, macOS, and Windows.
- **Modular branding:** Customize logo, color palette, preconfigured manager addresses, and endpoints using a single configuration file.
- **Secure Privileges:** Validates `sudo` authentication upfront and securely pipes it via `stdin` across installation sub-processes (no plaintext password caching to disk).
- **Component Auditing:** Detects and verifies the presence of security binaries and active-response scripts across root-owned directories.
- **Real-time log streaming:** Terminal-style view during installation and enrollment.
- **OAuth2 enrollment:** Guided certificate-based authentication flow from within the app using PKCE.

---

## What it installs

**Core (always installed)**

- [Wazuh Agent](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/index.html) — security monitoring agent
- [wazuh-cert-oauth2-client](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2) — certificate-based OAuth2 authentication
- [wazuh-agent-status](https://github.com/ADORSYS-GIS/wazuh-agent-status) — agent health monitoring daemon
- [YARA](https://virustotal.github.io/yara/) — malware detection via YARA rules
- USB DLP active response scripts — blocks/alerts on unauthorized USB storage and HID devices

**Configurable (user choice)**

- **Suricata** (IDS or IPS mode) — network intrusion detection/prevention
- **Trivy** _(optional, Linux/macOS only)_ — vulnerability and misconfiguration scanner

---

## Quick start

To develop locally or test the application, you'll need Node.js 18+ and Rust installed.

```bash
# Install frontend dependencies
npm install

# Run the local CI check to ensure the project compiles and passes lints
./run-ci.sh

# Run in development mode (hot-reload)
npm run tauri dev
```

---

## Branding & Customization

All branding elements and preconfigured values are controlled from `src/config.ts`. This is the **single source of truth** for:
- Company logo
- Application title and version
- Color themes (primary, secondary, backgrounds, borders, status highlights)
- List of default Wazuh Managers
- OAuth2 Issuers and Certificate Endpoint options
- Default agent version

To update the branding, simply edit `src/config.ts` and build the application.

---

## Building a release

```bash
npm run tauri build
```

Output is written to `src-tauri/target/release/bundle/`.

| Platform | Package                                    |
| -------- | ------------------------------------------ |
| Linux    | `.deb`, `.AppImage`                        |
| macOS    | `.dmg` (universal — Intel + Apple Silicon) |
| Windows  | `.msi`, `.exe`                             |
