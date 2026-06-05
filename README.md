# Wazuh Agent Installer

[![CI](https://github.com/ADORSYS-GIS/wazuh-agent-installer/actions/workflows/ci.yml/badge.svg)](https://github.com/ADORSYS-GIS/wazuh-agent-installer/actions/workflows/ci.yml)

A desktop GUI application that provides a guided, wizard-style interface for installing and configuring a full Wazuh security agent stack on Linux, macOS, and Windows.

Instead of running installation commands manually in the terminal, this app walks the user through configuration, previews the installation plan, and then executes the setup scripts (Bash on Linux/macOS, PowerShell on Windows) with elevated privileges — streaming real-time logs directly into the UI.

---

## Features

- **5-step wizard:** Configure → Components → Review → Install → Enroll
- **Cross-platform support:** Native installation on Linux, macOS, and Windows
- **Modular branding:** Customize logo, color palette, preconfigured manager addresses, and endpoints using a single configuration file
- **Real-time log streaming:** Terminal-style view during installation and enrollment
- **Privilege escalation:** Runs natively with elevated system permissions
- **System tray integration:** Minimize to tray, left-click to toggle, right-click for menu
- **OAuth2 enrollment:** Guided certificate-based authentication flow from within the app

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

## Branding & Customization

All branding elements and preconfigured values are controlled from [src/config.ts](file:///home/adorsys/adorsys/wazuh/wazuh-agent-installer/src/config.ts). This is the **single source of truth** for:
- Company logo
- Application title and version
- Color themes (primary, secondary, backgrounds, borders, status highlights)
- List of default Wazuh Managers
- OAuth2 Issuers and Certificate Endpoint options
- Default agent version

To update the branding, simply edit `src/config.ts` and build the application.

---

## Prerequisites

### System dependencies

**Linux (Debian/Ubuntu)**

```bash
sudo apt update
sudo apt install -y \
  libwebkit2gtk-4.1-dev \
  libgtk-3-dev \
  libsoup-3.0-dev \
  libayatana-appindicator3-dev \
  librsvg2-dev \
  policykit-1
```

**macOS**

```bash
xcode-select --install
```

### Rust

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

### Node.js

Any recent LTS version (18+).

---

## Quick start

```bash
# Install frontend dependencies
npm install

# Run in development mode (hot-reload)
npm run tauri dev
```

---

## Local CI Validation

To verify code quality, formatting, compilation, and lints (both frontend and backend) before pushing to Git, run the unified developer CI script:

```bash
./run-ci.sh
```

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

---

## Project structure

```
.
├── setup-agent.sh              # Bundled install script for Linux & macOS
├── setup-agent.ps1             # Bundled install script for Windows
├── run-ci.sh                   # Unified local CI runner check script
├── src/
│   ├── index.html              # App UI — 5-step wizard
│   ├── config.ts               # Branding and manager configuration source of truth
│   ├── main.ts                 # Frontend logic (Tauri IPC, event handling)
│   ├── styles.css              # Design system using brand CSS custom properties
│   └── assets/                 # Static assets (logo, icons)
└── src-tauri/
    ├── src/
    │   ├── lib.rs              # Rust backend — tray, install commands, log streaming
    │   └── main.rs             # Entry point
    ├── capabilities/
    │   └── default.json        # Tauri permission scopes
    ├── icons/                  # App icons (all required sizes)
    ├── Cargo.toml              # Rust dependencies
    └── tauri.conf.json         # Tauri configuration
```

---

## Tech stack

| Layer                | Technology                      |
| -------------------- | ------------------------------- |
| Desktop framework    | [Tauri v2](https://tauri.app)   |
| Frontend             | HTML / CSS / TypeScript + Vite  |
| Backend              | Rust (Tokio async runtime)      |
| Privilege escalation | `pkexec` (Linux), User-elevation prompt (Windows) |
| Install script       | Bash (`setup-agent.sh`) & PowerShell (`setup-agent.ps1`) |
