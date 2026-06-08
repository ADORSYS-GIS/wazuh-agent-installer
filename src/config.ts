// ============================================================
// Wazuh Agent Installer — Brand & Dynamic Configuration
// ============================================================

export const BRAND_CONFIG = {
  // Brand Metadata
  companyName: "Sky EngPro",
  appTitle: "Wazuh Agent Installer",
  appVersion: "v1.0.0",
  logo: "assets/sky-engpro-logo.png", // Path relative to public/build folder

  // Brand Theme Palette (dynamically injected into :root variables)
  colors: {
    // Primary brand color and hover/ghost variants
    primary: "#FF991C",
    primaryHover: "#e6891a",
    primaryGhost: "rgba(255, 153, 28, 0.12)",
    teal: "#FF991C",
    tealDim: "rgba(255, 153, 28, 0.10)",

    // Light theme surface backgrounds
    bgRoot: "#f8f6f3",
    bgCard: "#ffffff",
    bgCardHover: "#f3f0ec",
    bgInput: "#f3f0ec",
    bgInputFocus: "#ede9e4",
    bgTerminal: "#1a1a2e",

    // Text colors
    textPrimary: "#1a1a2e",
    textSecondary: "#78716c",
    textMuted: "#a8a29e",
    textAccent: "#FF991C",

    // Status colors
    statusSuccess: "#16a34a",
    statusSuccessDim: "rgba(22, 163, 74, 0.10)",
    statusError: "#dc2626",
    statusErrorDim: "rgba(220, 38, 38, 0.10)",
    statusWarn: "#d97706",
    statusWarnDim: "rgba(217, 119, 6, 0.10)",
  },

  // Wazuh Agent default configuration
  wazuhAgentVersion: "4.14.1-1",

  // Dropdown option selections
  managers: [
    { value: "wazuh.adorsys.com", label: "wazuh.adorsys.com" },
    { value: "wazuh.adorsys.de", label: "wazuh.adorsys.de" },
  ],

  oauthIssuers: [
    { value: "https://login.wazuh.adorsys.team/realms/adorsys", label: "login.wazuh.adorsys.team / adorsys" },
    {
      value: "https://login.dev.wazuh.adorsys.team/realms/test-adorsys",
      label: "login.dev.wazuh.adorsys.team / test-adorsys (dev)",
    },
  ],

  certEndpoints: [
    { value: "https://cert.wazuh.adorsys.team/api/register-agent", label: "cert.wazuh.adorsys.team (production)" },
    { value: "https://cert.dev.wazuh.adorsys.team/api/register-agent", label: "cert.dev.wazuh.adorsys.team (dev)" },
  ],
};
