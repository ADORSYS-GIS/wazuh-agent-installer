# Architecture Overview

This document describes the high-level architecture, design decisions, and security model of the Wazuh Agent Installer.

## System Overview

The Wazuh Agent Installer is a cross-platform desktop application built using [Tauri v2](https://v2.tauri.app/) and TypeScript. It provides a guided graphical interface for deploying and configuring a complete Wazuh security stack on end-user machines across Linux, macOS, and Windows.

```text
+-----------------------------------------------------------------------+
|                             Frontend (UI)                             |
|  TypeScript + Vite + HTML5 + Vanilla DOM (No bulky framework)        |
|  Tabs: Setup | Enrollment | Components | Help & Support               |
+-----------------------------------------------------------------------+
                                  |
                                  | Tauri IPC (invoke / events)
                                  v
+-----------------------------------------------------------------------+
|                          Backend Core (Rust)                          |
|  - Process execution & sudo stdin streaming                           |
|  - Single-instance file lock (flock + O_CLOEXEC)                      |
|  - Safe external URL dispatch (http/https/slack protocols)            |
|  - Asynchronous background process spawning                           |
|  - Updater integration with auto-restart                              |
+-----------------------------------------------------------------------+
         |                        |                        |
         v                        v                        v
+------------------+     +------------------+     +--------------------+
|  OS Services     |     | Security Gateway |     | External Apps      |
|  - systemd / svc |     | - OAuth2 PKCE    |     | - Default Browser  |
|  - Wazuh Agent   |     | - Cert Exchange  |     | - Slack Desktop    |
|  - Suricata/YARA |     | - Conflict check |     +--------------------+
+------------------+     +------------------+
```

## Layered Architecture

### 1. Frontend Layer (`src/`)

- **Rendering Engine**: Native Webview managed by Tauri (WebKitGTK on Linux, WKWebView on macOS, WebView2 on Windows).
- **Application Logic**: Written in TypeScript using standard DOM APIs without large frontend frameworks (React/Vue/Angular), keeping bundle size minimal and memory usage low.
- **Branding & Config**: Centralized in `src/config.ts`. Modifying `config.ts` dynamically configures the visual identity, colors, default endpoints, and supported features.
- **Event Listeners**: Listens to backend log streaming events (`log_stdout`, `log_stderr`, `process_finished`) to display real-time terminal output during installation and enrollment.

### 2. Backend Bridge Layer (`src-tauri/src/`)

- **IPC Dispatcher**: Exposes safe, strongly-typed Rust functions to the webview using Tauri's `#[tauri::command]` attribute.
- **Command Routing**:
  - `start_installation`: Runs the platform-specific installer script, securely streaming sudo credentials through stdin.
  - `start_enrollment`: Performs agent enrollment against the Wazuh Gateway or Manager.
  - `open_external_url`: Validates and dispatches external URLs to system handlers.
  - `check_component_status`: Probes filesystem paths for installed binaries and services.
  - `restart_application`: Triggers an in-place relaunch after software updates.

## Security and Privilege Model

Installing security monitoring software requires root/administrator privileges. The installer implements a strict security posture:

### 1. Sudo Authentication via Standard Input
- The application prompts for administrator credentials upfront through a secure password input field.
- Passwords are **never cached to disk** or written to temporary configuration files.
- Credentials are piped directly through standard input (`stdin`) to privileged processes (such as `sudo -S`).
- Process stdin pipes are immediately closed after authentication to minimize exposure window.

### 2. Single-Instance Execution Lock
- To prevent conflicting concurrent installations or database locks, the installer enforces single-instance execution.
- On Unix-like systems, the lock file (`/tmp/wazuh-agent-installer.lock`) is acquired using `flock`.
- The lock file descriptor is opened with `O_CLOEXEC` to guarantee that file handles are not leaked to spawned child processes or external commands.

### 3. Safe External URL Dispatch
- External links opened from within the application (documentation links, support channels) are strictly validated by `is_safe_url`.
- Allowed protocols are restricted to `http://`, `https://`, and `slack://`.
- Arbitrary command injection or protocol handler abuse (such as `file://` or shell execution protocols) is rejected.

### 4. Non-Blocking Process Spawning
- External helper commands on Linux (such as `xdg-open`) are spawned asynchronously with disconnected standard input, output, and error streams (`Stdio::null()`).
- This prevents child processes from blocking the Tauri event loop or holding stdout/stderr pipes open, which previously caused UI and log stream freezes.

## Component Stack Overview

The installer automates the installation and configuration of six security components:

| Component | Function | Upstream Reference |
| :--- | :--- | :--- |
| **Wazuh Agent** | Endpoint security monitoring, file integrity monitoring (FIM), vulnerability detection, and active response. | [Wazuh Documentation](https://documentation.wazuh.com/) |
| **wazuh-cert-oauth2-client** | Manages certificate-based authentication using OAuth2 PKCE flow for mutual TLS with the Wazuh cluster. | [ADORSYS-GIS/wazuh-cert-oauth2](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2) |
| **wazuh-agent-status** | Background daemon reporting agent health, enrollment status, and telemetry. | [ADORSYS-GIS/wazuh-agent-status](https://github.com/ADORSYS-GIS/wazuh-agent-status) |
| **YARA** | Pattern matching engine evaluating files against custom security rules for malware detection. | [VirusTotal YARA](https://virustotal.github.io/yara/) |
| **USB DLP Active Response** | Custom active-response scripts that detect, block, and report unauthorized USB storage and HID devices. | Internal Wazuh Ruleset |
| **Suricata** (Optional) | Network intrusion detection and prevention system (IDS/IPS) analyzing packet flows. | [Suricata IDS](https://suricata.io/) |

## Enrollment and Conflict Handling

1. **Authentication Flow**:
   - The user enters their corporate email address and clicks "Enroll Agent".
   - The installer initiates an OAuth2 PKCE exchange with the identity provider (IdP).
   - Upon successful identity verification, the client requests a client certificate from the Wazuh Gateway.

2. **Active Certificate Conflict Handling**:
   - If the Gateway reports that the user already has an active, valid certificate in the cluster, an HTTP 409 Conflict is returned.
   - Per **ADR-0003**, self-service certificate overwrite is disabled in the UI to prevent accidental invalidation of active endpoint certificates.
   - The UI surfaces clear, actionable instructions directing the user to contact the Security Team on Slack (`#Wazuh-Support` at `https://adorsys.slack.com/archives/C08M6LK5FCM`).
