import { BRAND_CONFIG, COMPONENT_DESCRIPTIONS } from "./config";

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

declare global {
  interface Window {
    __TAURI__?: {
      core: {
        invoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T>;
      };
      event: {
        listen<T>(event: string, handler: (event: { payload: T }) => void): Promise<() => void>;
      };
      app: {
        getVersion(): Promise<string>;
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
      if (cmd === "verify_sudo") return (args?.password === "root") as unknown as T;
      if (cmd === "run_install") {
        return { success: true, exit_code: 0, message: "Mock install successful" } as unknown as T;
      }
      if (cmd === "run_enroll") {
        return { success: true, exit_code: 0, message: "Mock enroll successful" } as unknown as T;
      }
      if (cmd === "run_netbird_up") {
        return { success: true, exit_code: 0, message: "Mock netbird up successful" } as unknown as T;
      }
      if (cmd === "check_components") {
        return [
          { name: "Wazuh Agent", installed: true, version: "4.14.1", path: "/var/ossec/bin/wazuh-agent" },
          { name: "OAuth2 Client", installed: false, version: null, path: "/var/ossec/bin/wazuh-cert-oauth2-client" },
        ] as unknown as T;
      }
      return {} as T;
    };

const listen = hasTauri
  ? window.__TAURI__!.event.listen
  : async <T>(event: string, _handler: (event: { payload: T }) => void): Promise<() => void> => {
      console.log(`[Mock Listen] Registered handler for: ${event}`);
      return () => {};
    };

// ---- State ----
let sudoPassword = "";
const installState = { running: false };
const enrollState = { running: false };
const netbirdState = { running: false };

// ---- DOM refs ----
// Overlays
const sudoOverlay = document.getElementById("sudo-overlay");
const appContainer = document.getElementById("app");
const sudoPasswordInput = document.getElementById("sudo-password") as HTMLInputElement;
const btnSudoSubmit = document.getElementById("btn-sudo-submit") as HTMLButtonElement;
const sudoError = document.getElementById("sudo-error");

// Nav
const navItems = document.querySelectorAll<HTMLElement>(".nav-item");
const tabPanels = document.querySelectorAll<HTMLElement>(".tab-panel");

// Config inputs
const elManagerSelect = document.getElementById("wazuh-manager") as HTMLSelectElement | null;
const elManagerCustom = document.getElementById("wazuh-manager-custom") as HTMLInputElement | null;
const elIssuerSelect = document.getElementById("oauth-issuer") as HTMLSelectElement | null;
const elIssuerCustom = document.getElementById("oauth-issuer-custom") as HTMLInputElement | null;
const elEndpointSelect = document.getElementById("cert-endpoint") as HTMLSelectElement | null;
const elEndpointCustom = document.getElementById("cert-endpoint-custom") as HTMLInputElement | null;
const elTrivy = document.getElementById("install-trivy") as HTMLInputElement | null;
const elNetbirdInstall = document.getElementById("install-netbird") as HTMLInputElement | null;

// IDS mode pills
const suricataModePills = document.querySelectorAll<HTMLElement>("#suricata-mode-group .pill");

// Install / Enroll Action Buttons
const btnStartInstall = document.getElementById("btn-start-install") as HTMLButtonElement;
const btnStartEnroll = document.getElementById("btn-start-enroll") as HTMLButtonElement;
const btnRetryEnroll = document.getElementById("btn-retry-enroll") as HTMLButtonElement;
const btnGoEnroll = document.getElementById("btn-go-enroll") as HTMLButtonElement;
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
const elNetbirdUrlSelect = document.getElementById("netbird-management-url") as HTMLSelectElement | null;
const elNetbirdUrlCustom = document.getElementById("netbird-management-url-custom") as HTMLInputElement | null;
const elNetbirdSetupKey = document.getElementById("netbird-setup-key") as HTMLInputElement | null;
const btnStartNetbird = document.getElementById("btn-start-netbird") as HTMLButtonElement;
const btnRetryNetbird = document.getElementById("btn-retry-netbird") as HTMLButtonElement;
const terminalNetbirdArea = document.getElementById("netbird-terminal-area");
const terminalNetbird = document.getElementById("netbird-terminal");
const netbirdStatusBanner = document.getElementById("netbird-status-banner");

// ---- Initialization ----

async function boot() {
  applyBrandTheme();
  initializeAppHeaderAndOptions();
  setupCustomInputListeners();
  setupRadioCards();

  // Tab handling
  navItems.forEach((item) => {
    item.addEventListener("click", () => switchTab(item.dataset.target!));
  });

  // Action listeners
  btnStartInstall?.addEventListener("click", startInstall);
  btnStartEnroll?.addEventListener("click", startEnrollment);
  btnRetryEnroll?.addEventListener("click", startEnrollment);
  btnGoEnroll?.addEventListener("click", () => switchTab("tab-enrollment"));
  btnStartNetbird?.addEventListener("click", startNetbirdConnection);
  btnRetryNetbird?.addEventListener("click", startNetbirdConnection);
  btnRefreshComponents?.addEventListener("click", refreshComponents);

  const isRoot = await invoke<boolean>("is_root");
  const platform = await invoke<string>("get_platform");

  if (!isRoot && (platform === "linux" || platform === "macos")) {
    // Show Sudo prompt
    if (sudoOverlay) sudoOverlay.style.display = "flex";

    sudoPasswordInput?.addEventListener("input", () => {
      btnSudoSubmit.disabled = !sudoPasswordInput.value;
      if (sudoError) sudoError.style.display = "none";
    });

    sudoPasswordInput?.addEventListener("keydown", (e) => {
      if (e.key === "Enter" && sudoPasswordInput.value) handleSudoSubmit();
    });

    btnSudoSubmit?.addEventListener("click", handleSudoSubmit);
  } else {
    // Root or Windows -> skip prompt
    finishBoot();
  }
}

async function handleSudoSubmit() {
  const pwd = sudoPasswordInput.value;
  if (!pwd) return;

  btnSudoSubmit.disabled = true;
  btnSudoSubmit.innerHTML = `<span class="spinner" style="width: 14px; height: 14px; margin-right: 8px;"></span> Verifying...`;

  try {
    const ok = await invoke<boolean>("verify_sudo", { password: pwd });
    if (ok) {
      sudoPassword = pwd;
      finishBoot();
    } else {
      showSudoError("Incorrect password, please try again.");
      sudoPasswordInput.value = "";
      sudoPasswordInput.focus();
    }
  } catch (e: unknown) {
    showSudoError(String(e));
  } finally {
    btnSudoSubmit.disabled = false;
    btnSudoSubmit.textContent = "Continue";
  }
}

function showSudoError(msg: string) {
  if (sudoError) {
    sudoError.textContent = msg;
    sudoError.style.display = "block";
  }
}

function finishBoot() {
  if (sudoOverlay) sudoOverlay.style.display = "none";
  if (appContainer) appContainer.style.display = "block";
  updateInstallButtonState();
  updateEnrollButtonState();
  refreshComponents(); // Initial load
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
  root.style.setProperty("--brand-text-muted", BRAND_CONFIG.colors.textMuted);
  root.style.setProperty("--brand-status-success", BRAND_CONFIG.colors.statusSuccess);
  root.style.setProperty("--brand-status-error", BRAND_CONFIG.colors.statusError);
  root.style.setProperty("--brand-status-warn", BRAND_CONFIG.colors.statusWarn);
  // --brand-status-info is used by .log-line.info in styles.css
  root.style.setProperty("--brand-status-info", "#60a5fa");
}

async function initializeAppHeaderAndOptions(): Promise<void> {
  const appLogo = document.getElementById("app-logo") as HTMLImageElement | null;
  const appTitle = document.getElementById("app-title");
  const appVersion = document.getElementById("app-version");

  if (appLogo) appLogo.src = BRAND_CONFIG.logo;
  if (appTitle) appTitle.textContent = BRAND_CONFIG.appTitle;
  // Read version from Tauri at runtime (single source: tauri.conf.json)
  if (appVersion) {
    const version = hasTauri ? await window.__TAURI__!.app.getVersion() : "dev";
    appVersion.textContent = `v${version}`;
  }
  document.title = BRAND_CONFIG.appTitle;

  populateDropdown("wazuh-manager", BRAND_CONFIG.managers);
  populateDropdown("oauth-issuer", BRAND_CONFIG.oauthIssuers);
  populateDropdown("cert-endpoint", BRAND_CONFIG.certEndpoints);
  populateDropdown("netbird-management-url", BRAND_CONFIG.netbirdManagementUrls);
}

function populateDropdown(selectId: string, options: { value: string; label: string }[]): void {
  const selectEl = document.getElementById(selectId) as HTMLSelectElement | null;
  if (!selectEl) return;
  const placeholderOption = selectEl.options[0];
  selectEl.innerHTML = "";
  if (placeholderOption) selectEl.appendChild(placeholderOption);

  options.forEach((opt) => {
    const option = document.createElement("option");
    option.value = opt.value;
    option.textContent = opt.label;
    selectEl.appendChild(option);
  });

  const otherOpt = document.createElement("option");
  otherOpt.value = "other";
  otherOpt.textContent = "Other (enter manually)…";
  selectEl.appendChild(otherOpt);
}

function setupCustomInputListeners(): void {
  const bindSelectToCustom = (sel: HTMLSelectElement | null, cus: HTMLInputElement | null, updateBtn: () => void) => {
    sel?.addEventListener("change", () => {
      if (sel.value === "other" && cus) {
        cus.style.display = "block";
        cus.focus();
      } else if (cus) {
        cus.style.display = "none";
        cus.value = "";
      }
      updateBtn();
    });
    cus?.addEventListener("input", updateBtn);
  };

  bindSelectToCustom(elManagerSelect, elManagerCustom, updateInstallButtonState);
  bindSelectToCustom(elIssuerSelect, elIssuerCustom, updateEnrollButtonState);
  bindSelectToCustom(elEndpointSelect, elEndpointCustom, updateEnrollButtonState);
  bindSelectToCustom(elNetbirdUrlSelect, elNetbirdUrlCustom, updateNetbirdButtonState);
  elNetbirdSetupKey?.addEventListener("input", updateNetbirdButtonState);
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
  return elManagerSelect?.value === "other"
    ? (elManagerCustom?.value.trim() ?? "")
    : (elManagerSelect?.value.trim() ?? "");
}

function getIssuerValue(): string {
  return elIssuerSelect?.value === "other"
    ? (elIssuerCustom?.value.trim() ?? "")
    : (elIssuerSelect?.value.trim() ?? "");
}

function getEndpointValue(): string {
  return elEndpointSelect?.value === "other"
    ? (elEndpointCustom?.value.trim() ?? "")
    : (elEndpointSelect?.value.trim() ?? "");
}

const NETBIRD_DEFAULT_URL = "https://api.netbird.io:443";

function getNetbirdUrlValue(): string {
  if (elNetbirdUrlSelect?.value === "other") {
    return elNetbirdUrlCustom?.value.trim() ?? "";
  }
  const val = elNetbirdUrlSelect?.value.trim() ?? "";
  return val || NETBIRD_DEFAULT_URL;
}

function getNetbirdSetupKey(): string {
  return elNetbirdSetupKey?.value.trim() ?? "";
}

function getConfig() {
  const selectedModePill = document.querySelector("#suricata-mode-group .pill.selected") as HTMLElement | null;
  return {
    wazuh_manager: getManagerValue(),
    wazuh_agent_name: "wazuh-agent",
    ids_engine: "suricata",
    suricata_mode: selectedModePill ? (selectedModePill.dataset.mode ?? "ids") : "ids",
    install_trivy: elTrivy ? elTrivy.checked : false,
    install_netbird: elNetbirdInstall ? elNetbirdInstall.checked : false,
    oauth_issuer: getIssuerValue(),
    cert_endpoint: getEndpointValue(),
  };
}

function updateInstallButtonState() {
  if (btnStartInstall) {
    btnStartInstall.disabled = !getManagerValue() || installState.running;
  }
}

function updateEnrollButtonState() {
  if (btnStartEnroll) {
    btnStartEnroll.disabled = !getIssuerValue() || !getEndpointValue() || enrollState.running;
  }
}

function updateNetbirdButtonState() {
  if (btnStartNetbird) {
    btnStartNetbird.disabled = netbirdState.running;
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

// ---- Shared streamed-action helper ----
// Unifies the common pattern across startInstall / startEnrollment / startNetbirdConnection:
// guard re-entry → set flag → show terminal → listen + invoke → handle result → cleanup.

interface StreamedActionOptions {
  state: { running: boolean };
  updateButton: () => void;
  terminal: HTMLElement | null;
  showOnStart: HTMLElement | null;
  hideOnStart?: HTMLElement | null;
  retryButton?: HTMLElement | null;
  statusBanner: HTMLElement | null;
  placeholderText: string;
  eventName: string;
  invokeCommand: string;
  invokeArgs: Record<string, unknown>;
  runningMessage: string;
  initialLog?: string;
  successMessage: (result: InstallResult) => string;
  errorPrefix: string;
  saveLogButtonId: string;
  saveLogTerminalId: string;
  saveLogPrefix: string;
  onSuccess?: (result: InstallResult) => void;
  onFailure?: (result: InstallResult) => void;
  onError?: (err: unknown) => void;
  onFinally?: () => void;
}

async function runStreamedAction(opts: StreamedActionOptions): Promise<void> {
  if (opts.state.running) return;
  opts.state.running = true;
  opts.updateButton();

  if (opts.showOnStart) opts.showOnStart.style.display = "block";
  if (opts.hideOnStart) opts.hideOnStart.style.display = "none";
  if (opts.retryButton) opts.retryButton.style.display = "none";
  if (opts.terminal) {
    opts.terminal.innerHTML = `<div class="terminal-placeholder"><span class="spinner"></span> ${opts.placeholderText}</div>`;
  }

  showStatusBanner(opts.statusBanner, "running", opts.runningMessage);
  if (opts.initialLog) appendLog(opts.terminal, opts.initialLog, "info");

  const unlistenLog = await listen<LogLine>(opts.eventName, (e) => {
    appendLog(opts.terminal, e.payload.line, e.payload.level);
  });

  try {
    const result = await invoke<InstallResult>(opts.invokeCommand, opts.invokeArgs);
    if (result.success) {
      showStatusBanner(opts.statusBanner, "success", opts.successMessage(result));
      opts.onSuccess?.(result);
    } else {
      showStatusBanner(opts.statusBanner, "error", `${opts.errorPrefix}: exit code ${result.exit_code}`);
      if (opts.retryButton) opts.retryButton.style.display = "flex";
      opts.onFailure?.(result);
    }
  } catch (err: unknown) {
    showStatusBanner(opts.statusBanner, "error", `${opts.errorPrefix}: ${err}`);
    if (opts.retryButton) opts.retryButton.style.display = "flex";
    opts.onError?.(err);
  } finally {
    unlistenLog();
    opts.state.running = false;
    opts.updateButton();
    opts.onFinally?.();
    enableSaveLogs(opts.saveLogButtonId, opts.saveLogTerminalId, opts.saveLogPrefix);
  }
}

// ---- Installation Flow ----

async function startInstall() {
  await runStreamedAction({
    state: installState,
    updateButton: updateInstallButtonState,
    terminal: terminalInstall,
    showOnStart: installLogCard,
    hideOnStart: resultScreen,
    statusBanner: installStatusBanner,
    placeholderText: "Waiting to start…",
    eventName: "install-log",
    invokeCommand: "run_install",
    invokeArgs: { config: getConfig(), password: sudoPassword || null },
    runningMessage: "Installation in progress…",
    initialLog: "Starting Wazuh Agent installation…",
    successMessage: (result) => result.message,
    errorPrefix: "Installation failed",
    saveLogButtonId: "btn-save-install-logs",
    saveLogTerminalId: "terminal",
    saveLogPrefix: "install",
    onSuccess: () => {
      showInstallResult(true, "The Wazuh Agent stack was installed successfully.");
      setTimeout(() => {
        switchTab("tab-enrollment");
        startEnrollment();
      }, 1500);
    },
    onFailure: (result) => showInstallResult(false, result.message),
    onError: (err) => {
      appendLog(terminalInstall, `ERROR: ${err}`, "error");
      showInstallResult(false, String(err));
    },
  });
}

function showInstallResult(success: boolean, desc: string) {
  if (!resultScreen) return;
  resultScreen.style.display = "block";

  const icon = document.getElementById("result-icon");
  const title = document.getElementById("result-title");
  const descEl = document.getElementById("result-desc");
  const btn = document.getElementById("btn-go-enroll");

  if (icon) {
    icon.className = `result-icon ${success ? "success" : "error"}`;
    icon.textContent = success ? "✓" : "✕";
  }
  if (title) title.textContent = success ? "Installation Complete" : "Installation Failed";
  if (descEl) descEl.textContent = desc;
  if (btn) btn.style.display = success ? "inline-flex" : "none";
}

// ---- Enrollment Flow ----

async function startEnrollment() {
  const issuer = getIssuerValue();
  const endpoint = getEndpointValue();
  if (!issuer || !endpoint) return;

  const elOverwrite = document.getElementById("enroll-overwrite") as HTMLInputElement | null;
  const overwrite = elOverwrite ? elOverwrite.checked : true;

  await runStreamedAction({
    state: enrollState,
    updateButton: updateEnrollButtonState,
    terminal: terminalEnroll,
    showOnStart: terminalEnrollArea,
    retryButton: btnRetryEnroll,
    statusBanner: enrollStatusBanner,
    placeholderText: "Running enrollment…",
    eventName: "enroll-log",
    invokeCommand: "run_enroll",
    invokeArgs: { issuer, endpoint, overwrite, password: sudoPassword || null },
    runningMessage: "Enrollment in progress — check your browser…",
    successMessage: () => "Agent enrolled successfully!",
    errorPrefix: "Enrollment failed",
    saveLogButtonId: "btn-save-enroll-logs",
    saveLogTerminalId: "enroll-terminal",
    saveLogPrefix: "enroll",
    onFinally: refreshComponents,
  });
}

// ---- NetBird Connection Flow ----

async function startNetbirdConnection() {
  const managementUrl = getNetbirdUrlValue();
  const setupKey = getNetbirdSetupKey();

  await runStreamedAction({
    state: netbirdState,
    updateButton: updateNetbirdButtonState,
    terminal: terminalNetbird,
    showOnStart: terminalNetbirdArea,
    retryButton: btnRetryNetbird,
    statusBanner: netbirdStatusBanner,
    placeholderText: "Running netbird up…",
    eventName: "netbird-log",
    invokeCommand: "run_netbird_up",
    invokeArgs: { setupKey, managementUrl, password: sudoPassword || null },
    runningMessage: "Connecting to NetBird…",
    successMessage: () => "NetBird connected successfully!",
    errorPrefix: "NetBird connection failed",
    saveLogButtonId: "btn-save-netbird-logs",
    saveLogTerminalId: "netbird-terminal",
    saveLogPrefix: "netbird",
    onFinally: refreshComponents,
  });
}

// ---- Components Tab ----

async function refreshComponents() {
  const grid = document.getElementById("components-grid");
  if (!grid) return;

  const btn = document.getElementById("btn-refresh-components") as HTMLButtonElement;
  if (btn) btn.innerHTML = `<span class="spinner" style="margin-right: 6px"></span> Refreshing...`;

  try {
    const components = await invoke<ComponentStatus[]>("check_components", {
      password: sudoPassword || null,
    });
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
        <div class="comp-desc">${COMPONENT_DESCRIPTIONS[comp.name] ?? "Security component managed by the Wazuh Installer."}</div>
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

// ---- Helpers ----

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

// ---- Start ----
boot();
