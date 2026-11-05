# Configuration Reference

This document provides a comprehensive reference of configuration settings, data structures, network endpoints, and file locations for the Wazuh Agent Installer.

## Visual Brand Configuration (`src/config.ts`)

### `BRAND_CONFIG`

| Setting | Type | Description |
| :--- | :--- | :--- |
| `companyName` | `string` | Organization name displayed in window subtitles. |
| `appTitle` | `string` | Display title shown in header and window frame. |
| `logo` | `string` | Imported image asset bundled into webview. |
| `colors.primary` | `string` | Main brand accent color. |
| `colors.primaryHover` | `string` | Hover state for primary buttons. |
| `colors.primaryGhost` | `string` | Semi-transparent highlight for active navigation tabs. |
| `colors.bgRoot` | `string` | Main window background color. |
| `colors.bgCard` | `string` | Card container background. |
| `colors.bgInput` | `string` | Form input field background. |
| `colors.bgTerminal` | `string` | Terminal console log output background. |
| `colors.textPrimary` | `string` | Primary body text color. |
| `colors.textSecondary` | `string` | Subtitle and secondary text color. |
| `colors.statusSuccess` | `string` | Color for success checkmarks and badges. |
| `colors.statusError` | `string` | Color for error banners and warnings. |
| `colors.statusWarn` | `string` | Color for warning highlights. |

### `COMPONENT_DESCRIPTIONS`

Key-value dictionary in `src/config.ts` mapping component names to descriptions rendered in the **Overview** tab:
- `"Wazuh Agent"`
- `"OAuth2 Client"`
- `"Agent Status Monitor"`
- `"YARA"`
- `"Suricata"`
- `"NetBird"`

## Backend Endpoints (`AppConfig` in `src-tauri/src/lib.rs`)

Configured in Rust and exposed via the `get_app_config` IPC command:

| Field | Example Placeholder | Description |
| :--- | :--- | :--- |
| `wazuh_manager_url` | `"manager.wazuh.example.com"` | Default Wazuh Manager hostname for agent communication. |
| `wazuh_oauth_issuer` | `"https://login.wazuh.example.com/realms/<realm>"` | Identity Provider (IdP) OIDC / OAuth2 token issuer. |
| `wazuh_cert_endpoint` | `"https://cert.wazuh.example.com/api/register-agent"` | Certificate Server (`cert-server`) API endpoint for certificate exchange. |
| `netbird_management_url` | `"https://netbird.example.com"` | Central management server URL for optional NetBird overlay network. |

## Installer Parameter Model (`InstallConfig` in `src-tauri/src/lib.rs`)

Parameters passed from the frontend to `run_install`:

| Field | Type | Description |
| :--- | :--- | :--- |
| `wazuh_manager` | `String` | Hostname or IP of the Wazuh Manager. |
| `wazuh_agent_name` | `String` | Unique hostname or identifier for the registering agent. |
| `log_level` | `String` | Desired logging verbosity (e.g. `"info"`). |
| `ids_engine` | `String` | Network intrusion engine selection (`"suricata"`). |
| `suricata_mode` | `String` | Suricata operating mode (`"ids"` or `"ips"`). |
| `install_netbird` | `bool` | User toggle controlling whether NetBird VPN client is installed (`-b` flag). |
| `oauth_issuer` | `String` | OIDC / OAuth2 identity provider issuer URL. |
| `cert_endpoint` | `String` | Certificate Server (`cert-server`) registration endpoint. |

## Support & Channel Links (`src/main.ts`)

| Setting | Value Pattern | Description |
| :--- | :--- | :--- |
| `WAZUH_SUPPORT_SLACK_URL` | `"https://<workspace>.slack.com/archives/<channel-id>"` | Direct channel link to `#Wazuh-Support` in organization Slack workspace. |

## Network Ports and Endpoints

| Service | Port / Protocol | Direction | Purpose |
| :--- | :--- | :--- | :--- |
| **Wazuh Agent Events** | `1514 / TCP` | Outbound | Secure agent-to-manager event ingestion and log streaming. |
| **Wazuh Agent Auth** | `1515 / TCP` | Outbound | Direct agent registration daemon. |
| **Wazuh Cluster API** | `55000 / TCP` | Outbound | Administrative API querying agent health. |
| **Certificate Server (`cert-server`)** | `443 / TCP` | Outbound | HTTPS endpoint for OAuth2 token validation and certificate issuance. |
| **Identity Provider (IdP)**| `443 / TCP` | Outbound | HTTPS endpoint for user OAuth2 PKCE login. |
| **NetBird Management** | `443 / TCP` | Outbound | NetBird control plane coordination. |
| **NetBird WireGuard** | `51820 / UDP` | Inbound / Outbound | WireGuard peer-to-peer encrypted mesh tunnel. |
| **GitHub Releases** | `443 / TCP` | Outbound | In-app update check and release artifact downloads. |

## Key File Locations

| Platform | Component | Path |
| :--- | :--- | :--- |
| **Linux** | Installer Lock File | `$HOME/.config/wazuh-agent-installer/.lock` |
| | Wazuh Agent Home | `/var/ossec/` |
| | Wazuh Agent Binary | `/var/ossec/bin/wazuh-agentd` |
| | Wazuh Agent Config | `/var/ossec/etc/ossec.conf` |
| | Wazuh Agent Keys | `/var/ossec/etc/client.keys` |
| | Wazuh Agent Logs | `/var/ossec/logs/ossec.log` |
| | Suricata Binary | `/opt/wazuh/suricata/bin/suricata` |
| | YARA Binary | `/opt/wazuh/yara/bin/yara` |
| | Status Daemon | `/usr/local/bin/wazuh-agent-status` |
| | NetBird Binary | `/usr/bin/netbird` or `/usr/local/bin/netbird` |
| **macOS** | Installer Lock File | `$HOME/.config/wazuh-agent-installer/.lock` |
| | Wazuh Agent Home | `/Library/Ossec/` |
| | Wazuh Agent Binary | `/Library/Ossec/bin/wazuh-agentd` |
| | Wazuh Agent Config | `/Library/Ossec/etc/ossec.conf` |
| | Wazuh Agent Keys | `/Library/Ossec/etc/client.keys` |
| | Wazuh Agent Logs | `/Library/Ossec/logs/ossec.log` |
| | Suricata Binary | `/opt/wazuh/suricata/bin/suricata` |
| | YARA Binary | `/opt/wazuh/yara/bin/yara` |
| | Status Daemon | `/usr/local/bin/wazuh-agent-status` |
| | NetBird Binary | `/usr/local/bin/netbird` |
| **Windows** | Wazuh Agent Home | `C:\Program Files (x86)\ossec-agent\` |
| | Wazuh Agent Binary | `C:\Program Files (x86)\ossec-agent\wazuh-agent.exe` |
| | Wazuh Agent Config | `C:\Program Files (x86)\ossec-agent\ossec.conf` |
| | Wazuh Agent Keys | `C:\Program Files (x86)\ossec-agent\client.keys` |
| | Wazuh Agent Logs | `C:\Program Files (x86)\ossec-agent\ossec.log` |
| | Suricata Binary | `suricata.exe` |
| | YARA Binary | `yara64.exe` |
| | Status Daemon | `C:\Program Files\wazuh-agent-status\wazuh-agent-status.exe` |
| | NetBird Binary | `C:\Program Files\Netbird\netbird.exe` |
