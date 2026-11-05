# Branding & Customization Guide

The Wazuh Agent Installer separates brand identity and UI presentation from core application logic. This guide explains how to customize the visual theme, component descriptions, and preconfigured endpoints.

## Brand Identity: `src/config.ts`

The primary configuration file for visual presentation is `src/config.ts`. It exports `BRAND_CONFIG` and `COMPONENT_DESCRIPTIONS`.

### 1. `BRAND_CONFIG`

Defines application titles, corporate logos, and color tokens:

```typescript
import logoUrl from "./assets/adorsys-logo.png";

export const BRAND_CONFIG = {
  // Brand Metadata
  companyName: "Adorsys",
  appTitle: "Wazuh Agent Installer",
  logo: logoUrl,

  // Brand Theme Palette (dynamically injected into :root CSS variables)
  colors: {
    primary: "#1a73e8",
    primaryHover: "#4d9af5",
    primaryGhost: "rgba(26, 115, 232, 0.15)",
    teal: "#00c4b4",
    tealDim: "rgba(0, 196, 180, 0.12)",

    // Dark theme surface backgrounds
    bgRoot: "#0b0e14",
    bgCard: "#12161f",
    bgCardHover: "#181d28",
    bgInput: "#161b26",
    bgInputFocus: "#1a2030",
    bgTerminal: "#090c10",

    // Text colors
    textPrimary: "#e8ecf1",
    textSecondary: "#8b95a5",
    textMuted: "#5a6476",
    textAccent: "#4d9af5",

    // Status indicator colors
    statusSuccess: "#34d399",
    statusSuccessDim: "rgba(52, 211, 153, 0.12)",
    statusError: "#f87171",
    statusErrorDim: "rgba(248, 113, 113, 0.12)",
    statusWarn: "#fbbf24",
    statusWarnDim: "rgba(251, 191, 36, 0.12)",
  },
};
```

During startup, `applyBrandTheme()` in `src/main.ts` automatically injects these palette tokens into the DOM root (`:root`), mapping them to CSS variables such as `--brand-primary`, `--brand-bg-root`, `--brand-text-primary`, and status colors.

### 2. `COMPONENT_DESCRIPTIONS`

Defines human-readable descriptions displayed in the **Overview** (Components) tab:

```typescript
export const COMPONENT_DESCRIPTIONS: Record<string, string> = {
  "Wazuh Agent": "Core security agent responsible for system monitoring, log collection, and threat detection.",
  "OAuth2 Client": "Custom client that automatically negotiates certificates and authenticates the agent with the central cluster.",
  "Agent Status Monitor": "Background service ensuring the Wazuh agent remains healthy and restarts automatically if it crashes.",
  YARA: "Malware identification engine used to perform file content pattern matching for advanced threats.",
  Suricata: "High performance Network IDS, IPS and Network Security Monitoring engine.",
  NetBird: "WireGuard-based overlay VPN client providing secure mesh networking between agents.",
};
```

## Backend Endpoints: `src-tauri/src/lib.rs`

Default network infrastructure URLs are managed via `AppConfig` in the Rust backend (`src-tauri/src/lib.rs`):

```rust
pub struct AppConfig {
    pub wazuh_manager_url: String,       // Default: "manager.wazuh.adorsys.team"
    pub wazuh_oauth_issuer: String,      // Default: "https://login.wazuh.adorsys.team/realms/adorsys"
    pub wazuh_cert_endpoint: String,     // Default: "https://cert.wazuh.adorsys.team/api/register-agent"
    pub netbird_management_url: String,  // Default: "https://netbird.guard.adorsys.com"
}
```

The frontend fetches these defaults on startup via the `get_app_config` Tauri command to populate input fields and manage authentication targets.

## Support & Help URL: `src/main.ts`

The Slack support channel URL routed to by the **Help & Support** tab and the certificate conflict resolution dialog is defined as:
```typescript
const WAZUH_SUPPORT_SLACK_URL = "https://adorsys.slack.com/archives/C08M6LK5FCM";
```
To route support inquiries to a different internal Slack channel or IT help desk, update this constant in `src/main.ts`.
