# Wazuh Agent Installer

[![CI](https://github.com/ADORSYS-GIS/wazuh-agent-installer/actions/workflows/ci.yml/badge.svg)](https://github.com/ADORSYS-GIS/wazuh-agent-installer/actions/workflows/ci.yml)

A desktop GUI application that provides a guided, wizard-style interface for installing and configuring a full Wazuh security agent stack on Linux, macOS and Windows.

Instead of running a shell script manually from the terminal, this app walks the user through configuration, previews the installation plan, then executes the setup script with elevated privileges — streaming real-time logs directly into the UI.

---

## Features

- **4-step wizard:** Configure → Components → Review → Install
- **Real-time log streaming** — terminal-style view during installation
- **Privilege escalation** via `pkexec` (no terminal sudo required)
- **System tray integration** — minimize to tray, left-click to toggle, right-click for menu
- **OAuth2 enrollment** — guided certificate-based authentication flow from within the app, no browser switching required

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
- **Snort** — classic open-source network IDS
- **Trivy** _(optional)_ — vulnerability and misconfiguration scanner

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

Any recent LTS version (18+). Install via [nvm](https://github.com/nvm-sh/nvm) or your package manager.

---

## Quick start

```bash
# Install frontend dependencies
npm install

# Run in development mode (hot-reload)
npm run tauri dev
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
├── setup-agent.sh              # The bundled install script
├── src/
│   ├── index.html              # App UI — 4-step wizard
│   ├── main.js                 # Frontend logic (Tauri IPC, event handling)
│   ├── styles.css              # Design system
│   └── assets/                 # Static assets (icons, images)
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

## How it works

1. The user fills in the **Configure** step — Wazuh Manager address, agent name, version, and log level.
2. On the **Components** step, they choose an IDS engine (Suricata or Snort) and optionally enable Trivy.
3. The **Review** step shows a summary of all selected options before execution.
4. On **Install**, the frontend invokes the Rust backend via Tauri's IPC bridge. Rust spawns the setup agent wrapper script (which downloads and runs the OS-specific installer) with elevated privileges and streams stdout/stderr back to the UI in real time.
5. On completion, a success or failure screen is shown. The app minimizes to the system tray and remains accessible.

---

## Tech stack

| Layer                | Technology                      |
| -------------------- | ------------------------------- |
| Desktop framework    | [Tauri v2](https://tauri.app)   |
| Frontend             | Vanilla HTML / CSS / JavaScript |
| Backend              | Rust (Tokio async runtime)      |
| Privilege escalation | `pkexec` (Linux)                |
| Install script       | Bash (`setup-agent.sh`)         |
