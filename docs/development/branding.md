# Branding & Customization Guide

The Wazuh Agent Installer is designed to be easily rebranded and adapted for different enterprise environments without modifying the core logic or UI components.

## Single Source of Truth: `src/config.ts`

All branding tokens, color palettes, preconfigured server endpoints, and default application parameters are centralized in `src/config.ts`.

### Configuration Structure

The configuration exports a single `APP_CONFIG` object:

```typescript
export const APP_CONFIG = {
  branding: {
    appName: "Wazuh Agent Installer",
    companyName: "ADORSYS GIS",
    logoPath: "/assets/logo.svg",
    supportEmail: "security@example.com",
    supportSlackChannel: "https://adorsys.slack.com/archives/C08M6LK5FCM",
    documentationUrl: "https://github.com/ADORSYS-GIS/wazuh-agent-installer",
  },
  theme: {
    primaryColor: "#0284c7",
    primaryHover: "#0369a1",
    backgroundColor: "#0f172a",
    surfaceColor: "#1e293b",
    borderColor: "#334155",
    textColor: "#f8fafc",
    textMuted: "#94a3b8",
    successColor: "#10b981",
    warningColor: "#f59e0b",
    errorColor: "#ef4444",
  },
  wazuh: {
    defaultManager: "wazuh-manager.internal",
    defaultVersion: "4.8.0",
    defaultAgentName: "",
    defaultAgentGroup: "default",
  },
  oauth2: {
    issuer: "https://auth.example.com/realms/security",
    clientId: "wazuh-installer",
    gatewayEndpoint: "https://wazuh-gateway.internal",
    scopes: ["openid", "profile", "email"],
  },
};
```

## Customization Workflows

### 1. Updating Company Logo
1. Place your SVG or high-resolution PNG logo into `public/assets/` (e.g., `public/assets/company-logo.svg`).
2. Update `APP_CONFIG.branding.logoPath` in `src/config.ts` to reference the new file:
   ```typescript
   logoPath: "/assets/company-logo.svg",
   ```

### 2. Customizing Color Themes
Colors defined in `APP_CONFIG.theme` are automatically mapped to CSS custom variables in the root DOM element during initialization.
To update the look and feel:
- Change `primaryColor` and `primaryHover` to your brand's accent colors.
- Adjust `backgroundColor` and `surfaceColor` to match dark mode or corporate UI requirements.

### 3. Setting Preconfigured Endpoints
To distribute a pre-configured installer where users do not need to manually enter server addresses:
- Set `wazuh.defaultManager` to your Wazuh Manager DNS hostname or IP address.
- Set `oauth2.gatewayEndpoint` to your internal Wazuh Gateway URL.
- Set `oauth2.issuer` to your OAuth2 Identity Provider (IdP) URL.

### 4. Updating Support Links
If your organization uses a different Slack channel or help desk:
- Update `APP_CONFIG.branding.supportSlackChannel` to your support URL.
- Update `APP_CONFIG.branding.supportEmail` to your team inbox.
