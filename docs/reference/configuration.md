# Configuration Reference

This document provides a comprehensive reference of configuration settings, environment variables, network endpoints, and file locations for the Wazuh Agent Installer.

## Branding Configuration (`src/config.ts`)

| Setting | Type | Description |
| :--- | :--- | :--- |
| `branding.appName` | `string` | Display title shown in header and window frame. |
| `branding.companyName` | `string` | Organization name displayed in subheadings and notifications. |
| `branding.logoPath` | `string` | Relative path to logo asset (e.g. `/assets/logo.svg`). |
| `branding.supportEmail` | `string` | Security or IT help desk contact email. |
| `branding.supportSlackChannel` | `string` | Direct channel permalink (`https://adorsys.slack.com/archives/C08M6LK5FCM`). |
| `branding.documentationUrl` | `string` | Documentation link referenced in Help tab. |
| `theme.primaryColor` | `string` | Hex color code for primary action buttons and active highlights. |
| `theme.backgroundColor` | `string` | Main window background color. |
| `theme.surfaceColor` | `string` | Sidebar and card background color. |
| `theme.borderColor` | `string` | Border color for dividers, tables, and input elements. |
| `theme.textColor` | `string` | Main body text color. |
| `theme.textMuted` | `string` | Subtitle and placeholder text color. |
| `wazuh.defaultManager` | `string` | Default Wazuh Manager hostname or IP address populated in Setup tab. |
| `wazuh.defaultVersion` | `string` | Default agent version installed if not overridden by release scripts. |
| `wazuh.defaultAgentGroup` | `string` | Agent registration group assigned in manager. |
| `oauth2.issuer` | `string` | OIDC / OAuth2 identity provider issuer URL. |
| `oauth2.clientId` | `string` | OAuth2 client identifier for PKCE desktop authentication. |
| `oauth2.gatewayEndpoint` | `string` | Base URL of Wazuh Gateway for certificate issuance. |

## Network Ports and Endpoints

The installer and installed services require outbound connectivity to the following network ports:

| Service | Port / Protocol | Direction | Purpose |
| :--- | :--- | :--- | :--- |
| **Wazuh Agent Events** | `1514 / TCP` | Outbound | Secure agent-to-manager event ingestion and log streaming. |
| **Wazuh Agent Auth** | `1515 / TCP` | Outbound | Agent registration daemon (if enrollment key is issued directly). |
| **Wazuh Cluster API** | `55000 / TCP` | Outbound | Administrative API querying agent status and verification. |
| **Wazuh Gateway** | `443 / TCP` | Outbound | HTTPS endpoint for OAuth2 token validation and certificate issuance. |
| **Identity Provider (IdP)**| `443 / TCP` | Outbound | HTTPS endpoint for user OAuth2 PKCE login. |
| **GitHub Releases** | `443 / TCP` | Outbound | In-app update check and release artifact downloads. |

## Key File Locations

| Platform | Component | Path |
| :--- | :--- | :--- |
| **Linux** | Installer Lock File | `/tmp/wazuh-agent-installer.lock` |
| | Wazuh Agent Home | `/var/ossec/` |
| | Wazuh Agent Config | `/var/ossec/etc/ossec.conf` |
| | Wazuh Agent Keys | `/var/ossec/etc/client.keys` |
| | Wazuh Agent Logs | `/var/ossec/logs/ossec.log` |
| | Status Daemon Config | `/etc/wazuh-agent-status/config.yaml` |
| **macOS** | Installer Lock File | `/tmp/wazuh-agent-installer.lock` |
| | Wazuh Agent Home | `/Library/Ossec/` |
| | Wazuh Agent Config | `/Library/Ossec/etc/ossec.conf` |
| | Wazuh Agent Keys | `/Library/Ossec/etc/client.keys` |
| | Wazuh Agent Logs | `/Library/Ossec/logs/ossec.log` |
| **Windows** | Wazuh Agent Home | `C:\Program Files (x86)\ossec-agent\` |
| | Wazuh Agent Config | `C:\Program Files (x86)\ossec-agent\ossec.conf` |
| | Wazuh Agent Keys | `C:\Program Files (x86)\ossec-agent\client.keys` |
| | Wazuh Agent Logs | `C:\Program Files (x86)\ossec-agent\ossec.log` |
