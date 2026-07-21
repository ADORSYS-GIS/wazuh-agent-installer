// ============================================================
// Wazuh Agent Installer — Brand & Dynamic Configuration
// ============================================================
import logoUrl from "./assets/adorsys-logo.png";

export const BRAND_CONFIG = {
  // Brand Metadata
  companyName: "Adorsys",
  appTitle: "Wazuh Agent Installer",
  logo: logoUrl,

  // Brand Theme Palette (dynamically injected into :root variables)
  colors: {
    // Primary brand color and hover/ghost variants
    primary: "#1a73e8",
    primaryHover: "#4d9af5",
    primaryGhost: "rgba(26, 115, 232, 0.15)",

    // Dark theme surface backgrounds
    bgRoot: "#0b0e14",
    bgCard: "#12161f",
    bgInput: "#161b26",
    bgInputFocus: "#1a2030",
    bgTerminal: "#090c10",

    // Text colors
    textPrimary: "#e8ecf1",
    textSecondary: "#8b95a5",
    textMuted: "#5a6476",

    // Status colors
    statusSuccess: "#34d399",
    statusError: "#f87171",
    statusWarn: "#fbbf24",
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
  netbirdManagementUrls: [
    { value: "https://api.netbird.io:443", label: "NetBird Cloud (api.netbird.io)" },
    { value: "https://netbird.guard.adorsys.com", label: "netbird.guard.adorsys.com" },
  ],
};

// Human-readable descriptions for each component, shown in the Overview tab.
export const COMPONENT_DESCRIPTIONS: Record<string, string> = {
  "Wazuh Agent": "Core security agent responsible for system monitoring, log collection, and threat detection.",
  "OAuth2 Client":
    "Custom daemon that automatically negotiates certificates and authenticates the agent with the central cluster.",
  "Agent Status Monitor":
    "Background service ensuring the Wazuh agent remains healthy and restarts automatically if it crashes.",
  YARA: "Malware identification engine used to perform file content pattern matching for advanced threats.",
  Suricata: "High performance Network IDS, IPS and Network Security Monitoring engine.",
  Trivy: "Comprehensive vulnerability scanner for OS packages, container images, and file system misconfigurations.",
  "USB DLP Scripts": "Active response scripts to monitor, block, and manage unauthorized USB storage devices.",
  NetBird: "WireGuard-based overlay VPN client providing secure mesh networking between agents.",
  Velociraptor: "Advanced endpoint visibility and incident response platform for hunting and monitoring.",
};
