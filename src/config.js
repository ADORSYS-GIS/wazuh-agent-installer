// ============================================================
// Wazuh Agent Installer — Brand & Dynamic Configuration
// ============================================================
export const BRAND_CONFIG = {
    // Brand Metadata
    companyName: "Adorsys",
    appTitle: "Wazuh Agent Installer",
    appVersion: "v1.0.0",
    logo: "assets/adorsys-logo.png", // Path relative to public/build folder
    // Brand Theme Palette (dynamically injected into :root variables)
    colors: {
        // Primary brand color and hover/ghost variants
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
        // Status colors
        statusSuccess: "#34d399",
        statusSuccessDim: "rgba(52, 211, 153, 0.12)",
        statusError: "#f87171",
        statusErrorDim: "rgba(248, 113, 113, 0.12)",
        statusWarn: "#fbbf24",
        statusWarnDim: "rgba(251, 191, 36, 0.12)",
    },
    // Wazuh Agent default configuration
    managers: [
        { value: "manager.wazuh.adorsys.team", label: "manager.wazuh.adorsys.team (prod)" },
        { value: "single-cluster.dev.wazuh.adorsys.team", label: "single-cluster.dev.wazuh.adorsys.team (dev)" },
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
