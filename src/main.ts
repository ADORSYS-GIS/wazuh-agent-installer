import { BRAND_CONFIG } from "./config";
import "@fontsource-variable/plus-jakarta-sans";

// ---- Tauri Typings ----
interface LogLine {
  line: string;
  level: string; // "info" | "error" | "success"
}

interface InstallResult {
  success: boolean;
  exit_code: number;
  message: string;
}

interface ComponentStatus {
  name: string;
  installed: boolean;
  version: string | null;
  path: string;
}

interface EnrollmentState {
  enrolled: boolean;
  agent_name?: string;
  manager?: string;
}

interface NetbirdState {
  daemon_status?: string;
  netbird_ip?: string;
  management_connected: boolean;
}

interface AppConfig {
  wazuh_manager_url: string;
  wazuh_oauth_issuer: string;
  wazuh_cert_endpoint: string;
  netbird_management_url: string;
}

declare global {
  interface Window {
    __TAURI__?: {
      core: {
        invoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T>;
      };
      event: {
        listen<T>(event: string, handler: (event: { payload: T }) => void): Promise<() => void>;
      };
      window: {
        getCurrentWindow(): {
          hide(): Promise<void>;
        };
      };
    };
  }
}

// ---- Tauri Core Bindings ----
const hasTauri = typeof window !== "undefined" && typeof window.__TAURI__ !== "undefined";

const invoke = hasTauri
  ? window.__TAURI__!.core.invoke
  : async <T>(cmd: string, args?: Record<string, unknown>): Promise<T> => {
      console.log(`[Mock Invoke] ${cmd}`, args);
      if (cmd === "get_platform") return "linux" as unknown as T;
      if (cmd === "is_root") return false as unknown as T;
      if (cmd === "run_install") {
        return { success: true, exit_code: 0, message: "Mock install successful" } as unknown as T;
      }
      if (cmd === "run_enroll") {
        return { success: true, exit_code: 0, message: "Mock enroll successful" } as unknown as T;
      }
      if (cmd === "check_components") {
        return [
          { name: "Wazuh Agent", installed: true, version: "4.14.1", path: "/var/ossec/bin/wazuh-agent" },
          { name: "OAuth2 Client", installed: false, version: null, path: "/var/ossec/bin/wazuh-cert-oauth2-client" },
        ] as unknown as T;
      }
      if (cmd === "check_enrollment") {
        return { enrolled: false } as unknown as T;
      }
      return {} as T;
    };

const listen = hasTauri
  ? window.__TAURI__!.event.listen
  : async <T>(event: string, _handler: (event: { payload: T }) => void): Promise<() => void> => {
      console.log(`[Mock Listen] Registered handler for: ${event}`);
      return () => {};
    };

let isInstalling = false;
let isEnrolling = false;
let isReEnrolling = false; // true when the user is already enrolled — passes --overwrite to the client
let isNetbirding = false;

// ---- DOM refs ----
// App container
const appContainer = document.getElementById("app");

// Nav
const navItems = document.querySelectorAll<HTMLElement>(".nav-item");
const tabPanels = document.querySelectorAll<HTMLElement>(".tab-panel");

// Config inputs
const elTrivy = document.getElementById("install-trivy") as HTMLInputElement | null;
const elNetbirdInstall = document.getElementById("install-netbird") as HTMLInputElement | null;

// IDS mode pills
const suricataModePills = document.querySelectorAll<HTMLElement>("#suricata-mode-group .pill");

// Install / Enroll Action Buttons
const btnStartInstall = document.getElementById("btn-start-install") as HTMLButtonElement;
const btnStartEnroll = document.getElementById("btn-start-enroll") as HTMLButtonElement;
const btnRetryEnroll = document.getElementById("btn-retry-enroll") as HTMLButtonElement;

const btnRefreshComponents = document.getElementById("btn-refresh-components") as HTMLButtonElement;

// Terminals
const terminalInstall = document.getElementById("terminal");
const installLogCard = document.getElementById("install-log-card");
const installStatusBanner = document.getElementById("status-banner");
const resultScreen = document.getElementById("result-screen");

const terminalEnrollArea = document.getElementById("enroll-terminal-area");
const terminalEnroll = document.getElementById("enroll-terminal");
const enrollStatusBanner = document.getElementById("enroll-status-banner");

// NetBird
const elNetbirdSetupKey = document.getElementById("netbird-setup-key") as HTMLInputElement | null;
const btnStartNetbird = document.getElementById("btn-start-netbird") as HTMLButtonElement;
const btnRetryNetbird = document.getElementById("btn-retry-netbird") as HTMLButtonElement;
const terminalNetbirdArea = document.getElementById("netbird-terminal-area");
const terminalNetbird = document.getElementById("netbird-terminal");
const netbirdStatusBanner = document.getElementById("netbird-status-banner");

// ---- Initialization ----

let appConfig: AppConfig | null = null;

async function boot() {
  try {
    appConfig = await invoke<AppConfig>("get_app_config");
  } catch (err) {
    console.error("Failed to load app config:", err);
  }

  applyBrandTheme();
  initializeAppHeaderAndOptions();
  setupRadioCards();

  // Tab handling
  navItems.forEach((item) => {
    item.addEventListener("click", () => {
      if (item.classList.contains("nav-accordion-toggle")) {
        const accordion = item.closest(".nav-group-accordion");
        if (accordion) accordion.classList.toggle("expanded");
        return;
      }
      if (item.dataset.target) {
        switchTab(item.dataset.target);
      }
    });
  });

  // Action listeners
  btnStartInstall?.addEventListener("click", startInstall);
  btnStartEnroll?.addEventListener("click", startEnrollment);
  btnRetryEnroll?.addEventListener("click", startEnrollment);

  btnStartNetbird?.addEventListener("click", startNetbirdConnection);
  btnRetryNetbird?.addEventListener("click", startNetbirdConnection);
  btnRefreshComponents?.addEventListener("click", refreshComponents);

  finishBoot();
}

function finishBoot() {
  if (appContainer) appContainer.style.display = "block";
  updateInstallButtonState();
  updateEnrollButtonState();
  updateNetbirdButtonState();
  refreshComponents(); // Initial load
  checkEnrollmentState(); // Check if already enrolled on startup
  checkNetbirdState(); // Check if already connected to Netbird on startup

  // Keep the enrolled card in sync while the app is open
  setInterval(() => checkEnrollmentState(), 15_000);
  setInterval(() => checkNetbirdState(), 15_000);
}

function switchTab(targetId: string) {
  navItems.forEach((item) => {
    item.classList.toggle("active", item.dataset.target === targetId);
  });
  tabPanels.forEach((panel) => {
    panel.classList.toggle("active", panel.id === targetId);
  });

  if (targetId === "tab-components") {
    refreshComponents();
  }
}

// ---- UI Helpers ----

function applyBrandTheme(): void {
  const root = document.documentElement;
  root.style.setProperty("--brand-primary", BRAND_CONFIG.colors.primary);
  root.style.setProperty("--brand-primary-hover", BRAND_CONFIG.colors.primaryHover);
  root.style.setProperty("--brand-primary-ghost", BRAND_CONFIG.colors.primaryGhost);
  root.style.setProperty("--brand-bg-root", BRAND_CONFIG.colors.bgRoot);
  root.style.setProperty("--brand-bg-card", BRAND_CONFIG.colors.bgCard);
  root.style.setProperty("--brand-bg-input", BRAND_CONFIG.colors.bgInput);
  root.style.setProperty("--brand-bg-input-focus", BRAND_CONFIG.colors.bgInputFocus);
  root.style.setProperty("--brand-bg-terminal", BRAND_CONFIG.colors.bgTerminal);
  root.style.setProperty("--brand-text-primary", BRAND_CONFIG.colors.textPrimary);
  root.style.setProperty("--brand-text-secondary", BRAND_CONFIG.colors.textSecondary);
  root.style.setProperty("--brand-status-success", BRAND_CONFIG.colors.statusSuccess);
  root.style.setProperty("--brand-status-error", BRAND_CONFIG.colors.statusError);
  root.style.setProperty("--brand-status-warn", BRAND_CONFIG.colors.statusWarn);
  // --brand-status-info is used by .log-line.info in styles.css
  root.style.setProperty("--brand-status-info", "#60a5fa");
}

function initializeAppHeaderAndOptions(): void {
  const appLogo = document.getElementById("app-logo") as HTMLImageElement | null;
  const appTitle = document.getElementById("app-title");
  const appVersion = document.getElementById("app-version");

  if (appLogo) appLogo.src = BRAND_CONFIG.logo;
  if (appTitle) appTitle.textContent = BRAND_CONFIG.appTitle;
  if (appVersion) appVersion.textContent = BRAND_CONFIG.appVersion;
  document.title = BRAND_CONFIG.appTitle;
}

function setupRadioCards(): void {
  suricataModePills.forEach((pill) => {
    pill.addEventListener("click", () => {
      suricataModePills.forEach((p) => p.classList.remove("selected"));
      pill.classList.add("selected");
    });
  });
}

// ---- Data Retrieval ----

function getManagerValue(): string {
  return appConfig?.wazuh_manager_url ?? "";
}

function getIssuerValue(): string {
  return appConfig?.wazuh_oauth_issuer ?? "";
}

function getEndpointValue(): string {
  return appConfig?.wazuh_cert_endpoint ?? "";
}

function getNetbirdUrlValue(): string {
  return appConfig?.netbird_management_url ?? "";
}

function getNetbirdSetupKey(): string {
  return elNetbirdSetupKey?.value.trim() ?? "";
}

function getConfig() {
  const selectedModePill = document.querySelector("#suricata-mode-group .pill.selected") as HTMLElement | null;
  return {
    wazuh_manager: getManagerValue(),
    wazuh_agent_name: "wazuh-agent",
    log_level: "INFO",
    ids_engine: "suricata",
    suricata_mode: selectedModePill ? (selectedModePill.dataset.mode ?? "ids") : "ids",
    install_trivy: elTrivy ? elTrivy.checked : false,
    install_netbird: elNetbirdInstall ? elNetbirdInstall.checked : false,
    oauth_issuer: getIssuerValue(),
    cert_endpoint: getEndpointValue(),
    netbird_url: getNetbirdUrlValue(),
    netbird_key: getNetbirdSetupKey(),
  };
}

function updateInstallButtonState() {
  if (btnStartInstall) {
    btnStartInstall.disabled = !getManagerValue() || isInstalling;
  }
}

function updateEnrollButtonState() {
  if (btnStartEnroll) {
    btnStartEnroll.disabled = !getIssuerValue() || !getEndpointValue() || isEnrolling;
  }
}

// ---- Installation Flow ----

function stripAnsi(str: string): string {
  // eslint-disable-next-line no-control-regex
  return str.replace(/\x1b\[[0-9;]*m/g, "");
}

function appendLog(term: HTMLElement | null, line: string, level: string): void {
  if (!term) return;
  const placeholder = term.querySelector(".terminal-placeholder");
  if (placeholder) placeholder.remove();

  const div = document.createElement("div");
  div.className = `log-line ${level}`;
  div.textContent = stripAnsi(line);
  term.appendChild(div);
  term.scrollTop = term.scrollHeight;
}

function showStatusBanner(banner: HTMLElement | null, type: "running" | "success" | "error", message: string) {
  if (!banner) return;
  banner.className = `status-banner visible ${type}`;
  const icon = type === "running" ? '<span class="spinner"></span>' : type === "success" ? "✓" : "✕";
  banner.innerHTML = `${icon} ${message}`;
}

async function startInstall() {
  if (isInstalling) return;
  isInstalling = true;
  updateInstallButtonState();

  if (installLogCard) installLogCard.style.display = "block";
  if (resultScreen) resultScreen.style.display = "none";
  if (terminalInstall) {
    terminalInstall.innerHTML =
      '<div class="terminal-placeholder"><span class="spinner"></span> Waiting to start…</div>';
  }

  showStatusBanner(installStatusBanner, "running", "Installation in progress…");
  appendLog(terminalInstall, "Starting Wazuh Agent installation…", "info");

  const unlistenLog = await listen<LogLine>("install-log", (e) => {
    appendLog(terminalInstall, e.payload.line, e.payload.level);
  });

  try {
    const result = await invoke<InstallResult>("run_install", {
      config: getConfig(),
    });

    if (result.success) {
      showStatusBanner(installStatusBanner, "success", result.message);
      showInstallResult(true, "The Wazuh Agent stack was installed successfully.");
    } else {
      showStatusBanner(installStatusBanner, "error", `Installation failed: exit code ${result.exit_code}`);
      showInstallResult(false, result.message);
    }
  } catch (err: unknown) {
    appendLog(terminalInstall, `ERROR: ${err}`, "error");
    showStatusBanner(installStatusBanner, "error", `Installation failed: ${err}`);
    showInstallResult(false, String(err));
  } finally {
    unlistenLog();
    isInstalling = false;
    updateInstallButtonState();
    enableSaveLogs("btn-save-install-logs", "terminal", "install");
  }
}

function showInstallResult(success: boolean, desc: string) {
  if (!resultScreen) return;
  resultScreen.style.display = "block";

  const icon = document.getElementById("result-icon");
  const title = document.getElementById("result-title");
  const descEl = document.getElementById("result-desc");
  if (icon) {
    icon.className = `result-icon ${success ? "success" : "error"}`;
    icon.textContent = success ? "✓" : "✕";
  }
  if (title) title.textContent = success ? "Installation Complete" : "Installation Failed";
  if (descEl) descEl.textContent = desc;
}

// ---- Enrollment Flow ----

async function startEnrollment() {
  if (isEnrolling) return;

  const issuer = getIssuerValue();
  const endpoint = getEndpointValue();
  if (!issuer || !endpoint) return;

  isEnrolling = true;
  updateEnrollButtonState();

  if (terminalEnrollArea) terminalEnrollArea.style.display = "block";
  if (btnRetryEnroll) btnRetryEnroll.style.display = "none";
  if (terminalEnroll) {
    terminalEnroll.innerHTML =
      '<div class="terminal-placeholder"><span class="spinner"></span> Running enrollment…</div>';
  }

  showStatusBanner(enrollStatusBanner, "running", "Enrollment in progress — check your browser…");

  const unlistenLog = await listen<LogLine>("enroll-log", (e) => {
    appendLog(terminalEnroll, e.payload.line, e.payload.level);
  });

  try {
    const result = await invoke<InstallResult>("run_enroll", {
      issuer,
      endpoint,
      overwrite: isReEnrolling,
    });

    if (result.success) {
      showStatusBanner(enrollStatusBanner, "success", "✓ Agent enrolled successfully!");
      // Wait 1.5s for client.keys to be fully written before checking state
      setTimeout(() => checkEnrollmentState(), 1500);
    } else {
      showStatusBanner(enrollStatusBanner, "error", `Enrollment failed: exit code ${result.exit_code}`);
      if (btnRetryEnroll) btnRetryEnroll.style.display = "flex";
    }
  } catch (err: unknown) {
    showStatusBanner(enrollStatusBanner, "error", `Enrollment error: ${err}`);
    if (btnRetryEnroll) btnRetryEnroll.style.display = "flex";
  } finally {
    unlistenLog();
    isEnrolling = false;
    updateEnrollButtonState();
    refreshComponents();
    enableSaveLogs("btn-save-enroll-logs", "enroll-terminal", "enroll");
  }
}

async function startNetbirdConnection() {
  const managementUrl = getNetbirdUrlValue();
  const setupKey = getNetbirdSetupKey();

  if (isNetbirding) return;
  isNetbirding = true;
  updateNetbirdButtonState();

  if (terminalNetbirdArea) terminalNetbirdArea.style.display = "block";
  if (btnRetryNetbird) btnRetryNetbird.style.display = "none";
  if (terminalNetbird) {
    terminalNetbird.innerHTML =
      '<div class="terminal-placeholder"><span class="spinner"></span> Running netbird up…</div>';
  }

  showStatusBanner(netbirdStatusBanner, "running", "Connecting to NetBird…");

  const unlistenLog = await listen<LogLine>("netbird-log", (e) => {
    appendLog(terminalNetbird, e.payload.line, e.payload.level);
  });

  try {
    const result = await invoke<InstallResult>("run_netbird_up", {
      setupKey,
      managementUrl,
    });

    if (result.success) {
      showStatusBanner(netbirdStatusBanner, "success", "NetBird connected successfully!");
      setTimeout(() => checkNetbirdState(), 1500);
    } else {
      showStatusBanner(netbirdStatusBanner, "error", `NetBird connection failed: exit code ${result.exit_code}`);
      if (btnRetryNetbird) btnRetryNetbird.style.display = "flex";
    }
  } catch (err: unknown) {
    showStatusBanner(netbirdStatusBanner, "error", `NetBird connection error: ${err}`);
    if (btnRetryNetbird) btnRetryNetbird.style.display = "flex";
  } finally {
    unlistenLog();
    isNetbirding = false;
    updateNetbirdButtonState();
    refreshComponents();
    enableSaveLogs("btn-save-netbird-logs", "netbird-terminal", "netbird");
  }
}

// ---- Enrollment State ----

async function checkEnrollmentState(): Promise<void> {
  try {
    const state = await invoke<EnrollmentState>("check_enrollment");

    const activeCard = document.getElementById("enroll-active-card");
    const formSection = document.getElementById("enroll-form-section");
    const dangerBody = document.getElementById("enroll-danger-body");
    const navBadge = document.getElementById("enroll-nav-badge");
    const agentNameEl = document.getElementById("enroll-info-agent-name");

    if (state.enrolled) {
      // Show the status card
      if (activeCard) activeCard.style.display = "block";

      // Move the form into the Advanced / danger section
      if (dangerBody && formSection && formSection.parentElement !== dangerBody) {
        dangerBody.appendChild(formSection);
        formSection.style.display = "block";
        isReEnrolling = true; // from here on, any enrollment is a re-enrollment
        if (btnStartEnroll) {
          btnStartEnroll.textContent = "⚠️ Re-enroll Device";
          btnStartEnroll.classList.remove("btn-primary");
          btnStartEnroll.classList.add("btn-danger");
          btnStartEnroll.disabled = !getIssuerValue() || !getEndpointValue() || isEnrolling;
        }
      }

      // Populate info rows
      if (agentNameEl) agentNameEl.textContent = state.agent_name ?? "Unknown";

      // Show the sidebar green badge
      if (navBadge) {
        navBadge.style.display = "flex";
        navBadge.className = "enroll-nav-badge enroll-nav-badge--active";
        navBadge.textContent = "✓";
      }
    } else {
      // Not enrolled — hide the card, show the form normally
      if (activeCard) activeCard.style.display = "none";
      isReEnrolling = false; // fresh machine — no overwrite needed

      // Move form back to its original position in the tab panel
      const tabPanel = document.getElementById("tab-enrollment");
      if (tabPanel && formSection && formSection.parentElement !== tabPanel) {
        const terminalArea = document.getElementById("enroll-terminal-area");
        tabPanel.insertBefore(formSection, terminalArea);
        formSection.style.display = "block";
      }

      // Reset button to primary enroll style
      if (btnStartEnroll) {
        btnStartEnroll.textContent = "🔐 Run Enrollment";
        btnStartEnroll.classList.add("btn-primary");
        btnStartEnroll.classList.remove("btn-danger");
      }

      // Show sidebar red badge
      if (navBadge) {
        navBadge.style.display = "flex";
        navBadge.className = "enroll-nav-badge enroll-nav-badge--missing";
        navBadge.textContent = "✗";
      }
    }
  } catch (err) {
    console.warn("[checkEnrollmentState] Could not determine enrollment state:", err);
  }
}

// ---- Netbird State ----

async function checkNetbirdState(): Promise<void> {
  try {
    const state = await invoke<NetbirdState>("check_netbird");

    const activeCard = document.getElementById("netbird-active-card");
    const formSection = document.getElementById("netbird-form-section");
    const dangerBody = document.getElementById("netbird-danger-body");
    const ipEl = document.getElementById("netbird-info-ip");
    const mgmtEl = document.getElementById("netbird-info-mgmt");
    const navBadge = document.getElementById("netbird-nav-badge");

    if (state.daemon_status === "Connected") {
      if (activeCard) activeCard.style.display = "block";

      if (dangerBody && formSection && formSection.parentElement !== dangerBody) {
        dangerBody.appendChild(formSection);
        formSection.style.display = "block";
        if (btnStartNetbird) {
          btnStartNetbird.textContent = "⚠️ Reconnect NetBird";
          btnStartNetbird.classList.remove("btn-primary");
          btnStartNetbird.classList.add("btn-danger");
        }
      }

      if (ipEl) ipEl.textContent = state.netbird_ip ?? "Unknown";
      if (mgmtEl) {
        mgmtEl.textContent = state.management_connected ? "Connected" : "Disconnected";
        mgmtEl.className = state.management_connected ? "enrolled-info-value enrolled-info-ok" : "enrolled-info-value";
        if (!state.management_connected) mgmtEl.style.color = "var(--color-danger)";
      }

      if (navBadge) {
        navBadge.style.display = "flex";
        navBadge.className = "enroll-nav-badge enroll-nav-badge--active";
        navBadge.textContent = "✓";
      }
    } else {
      if (activeCard) activeCard.style.display = "none";

      const tabPanel = document.getElementById("tab-netbird");
      if (tabPanel && formSection && formSection.parentElement !== tabPanel) {
        const terminalArea = document.getElementById("netbird-terminal-area");
        tabPanel.insertBefore(formSection, terminalArea);
        formSection.style.display = "block";
      }

      if (btnStartNetbird) {
        btnStartNetbird.textContent = "🐦 Connect NetBird";
        btnStartNetbird.classList.add("btn-primary");
        btnStartNetbird.classList.remove("btn-danger");
      }

      if (navBadge) {
        navBadge.style.display = "flex";
        navBadge.className = "enroll-nav-badge enroll-nav-badge--missing";
        navBadge.textContent = "✗";
      }
    }
  } catch (err) {
    console.warn("[checkNetbirdState] Could not determine netbird state:", err);
  }
}

// ---- Components Tab ----

async function refreshComponents() {
  const grid = document.getElementById("components-grid");
  if (!grid) return;

  const btn = document.getElementById("btn-refresh-components") as HTMLButtonElement;
  if (btn) btn.innerHTML = `<span class="spinner" style="margin-right: 6px"></span> Refreshing...`;

  try {
    const components = await invoke<ComponentStatus[]>("check_components");
    grid.innerHTML = "";

    components.forEach((comp) => {
      const card = document.createElement("div");
      card.className = "comp-card";

      const isOk = comp.installed;
      const badgeClass = isOk ? "installed" : "missing";
      const badgeText = isOk ? "Installed" : "Missing";

      card.innerHTML = `
        <div class="comp-header">
          <div class="comp-name">${comp.name}</div>
          <div class="comp-badge ${badgeClass}">${badgeText}</div>
        </div>
        <div class="comp-desc">${getComponentDescription(comp.name)}</div>
        ${comp.version ? `<div class="comp-version">📦 ${comp.version}</div>` : ""}
        <div class="comp-path">${comp.path}</div>
      `;
      grid.appendChild(card);
    });
  } catch (err) {
    console.error("Failed to check components", err);
  } finally {
    if (btn) btn.textContent = "↺ Refresh";
  }
}

// ---- Start ----
boot();
// ---- Helpers ----

function updateNetbirdButtonState() {
  if (btnStartNetbird) {
    btnStartNetbird.disabled = !getNetbirdUrlValue() || isNetbirding;
  }
}

function enableSaveLogs(buttonId: string, terminalId: string, prefix: string) {
  const btn = document.getElementById(buttonId);
  const term = document.getElementById(terminalId);
  if (!btn || !term) return;
  btn.style.display = "inline-flex";
  btn.onclick = async () => {
    const clone = term.cloneNode(true) as HTMLElement;
    const placeholder = clone.querySelector(".terminal-placeholder");
    if (placeholder) placeholder.remove();

    const logs = clone.innerText.trim();
    if (!logs) return;

    try {
      const path = await invoke<string>("save_logs", { logs, prefix });
      alert(`Logs successfully saved to:\n${path}`);
    } catch (e) {
      alert(`Failed to save logs: ${e}`);
    }
  };
}

function getComponentDescription(name: string): string {
  switch (name) {
    case "Wazuh Agent":
      return "Core security agent responsible for system monitoring, log collection, and threat detection.";
    case "OAuth2 Client":
      return "Custom daemon that automatically negotiates certificates and authenticates the agent with the central cluster.";
    case "Agent Status Monitor":
      return "Background service ensuring the Wazuh agent remains healthy and restarts automatically if it crashes.";
    case "YARA":
      return "Malware identification engine used to perform file content pattern matching for advanced threats.";
    case "Suricata":
      return "High performance Network IDS, IPS and Network Security Monitoring engine.";
    case "Trivy":
      return "Comprehensive vulnerability scanner for OS packages, container images, and file system misconfigurations.";
    case "USB DLP Scripts":
      return "Active response scripts to monitor, block, and manage unauthorized USB storage devices.";
    default:
      return "Security component managed by the Wazuh Installer.";
  }
}
