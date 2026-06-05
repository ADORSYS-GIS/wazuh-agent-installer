import { BRAND_CONFIG } from "./config";

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
      if (cmd === "run_install") {
        return { success: true, exit_code: 0, message: "Mock install successful" } as unknown as T;
      }
      if (cmd === "run_enroll") {
        return { success: true, exit_code: 0, message: "Mock enroll successful" } as unknown as T;
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
let currentStep = 0;
const totalSteps = 5;
let isInstalling = false;

// ---- DOM refs ----
const panels = document.querySelectorAll<HTMLElement>(".step-panel");
const stepItems = document.querySelectorAll<HTMLElement>(".step-item");
const connectors = document.querySelectorAll<HTMLElement>(".step-connector");
const btnNext = document.getElementById("btn-next") as HTMLButtonElement | null;
const btnBack = document.getElementById("btn-back") as HTMLButtonElement | null;
const footerHint = document.getElementById("footer-hint");

// Config inputs
const elManagerSelect = document.getElementById("wazuh-manager") as HTMLSelectElement | null;
const elManagerCustom = document.getElementById("wazuh-manager-custom") as HTMLInputElement | null;
const elIssuerSelect = document.getElementById("oauth-issuer") as HTMLSelectElement | null;
const elIssuerCustom = document.getElementById("oauth-issuer-custom") as HTMLInputElement | null;
const elEndpointSelect = document.getElementById("cert-endpoint") as HTMLSelectElement | null;
const elEndpointCustom = document.getElementById("cert-endpoint-custom") as HTMLInputElement | null;
const elTrivy = document.getElementById("install-trivy") as HTMLInputElement | null;

// IDS mode pills
const suricataModePills = document.querySelectorAll<HTMLElement>("#suricata-mode-group .pill");

// Terminal
const terminal = document.getElementById("terminal");
const terminalPlaceholder = document.getElementById("terminal-placeholder");
const statusBanner = document.getElementById("status-banner");

// ---- Initialize Branding dynamically ----
function applyBrandTheme(): void {
  const root = document.documentElement;
  root.style.setProperty("--brand-primary", BRAND_CONFIG.colors.primary);
  root.style.setProperty("--brand-primary-hover", BRAND_CONFIG.colors.primaryHover);
  root.style.setProperty("--brand-primary-ghost", BRAND_CONFIG.colors.primaryGhost);
  root.style.setProperty("--brand-teal", BRAND_CONFIG.colors.teal);
  root.style.setProperty("--brand-teal-dim", BRAND_CONFIG.colors.tealDim);

  root.style.setProperty("--brand-bg-root", BRAND_CONFIG.colors.bgRoot);
  root.style.setProperty("--brand-bg-card", BRAND_CONFIG.colors.bgCard);
  root.style.setProperty("--brand-bg-card-hover", BRAND_CONFIG.colors.bgCardHover);
  root.style.setProperty("--brand-bg-input", BRAND_CONFIG.colors.bgInput);
  root.style.setProperty("--brand-bg-input-focus", BRAND_CONFIG.colors.bgInputFocus);
  root.style.setProperty("--brand-bg-terminal", BRAND_CONFIG.colors.bgTerminal);

  root.style.setProperty("--brand-text-primary", BRAND_CONFIG.colors.textPrimary);
  root.style.setProperty("--brand-text-secondary", BRAND_CONFIG.colors.textSecondary);
  root.style.setProperty("--brand-text-muted", BRAND_CONFIG.colors.textMuted);
  root.style.setProperty("--brand-text-accent", BRAND_CONFIG.colors.textAccent);

  root.style.setProperty("--brand-status-success", BRAND_CONFIG.colors.statusSuccess);
  root.style.setProperty("--brand-status-success-dim", BRAND_CONFIG.colors.statusSuccessDim);
  root.style.setProperty("--brand-status-error", BRAND_CONFIG.colors.statusError);
  root.style.setProperty("--brand-status-error-dim", BRAND_CONFIG.colors.statusErrorDim);
  root.style.setProperty("--brand-status-warn", BRAND_CONFIG.colors.statusWarn);
  root.style.setProperty("--brand-status-warn-dim", BRAND_CONFIG.colors.statusWarnDim);
}

function initializeAppHeaderAndOptions(): void {
  const appLogo = document.getElementById("app-logo") as HTMLImageElement | null;
  const appTitle = document.getElementById("app-title");
  const appVersion = document.getElementById("app-version");
  const staticAgentVersion = document.getElementById("agent-version");

  if (appLogo) appLogo.src = BRAND_CONFIG.logo;
  if (appTitle) appTitle.textContent = BRAND_CONFIG.appTitle;
  if (appVersion) appVersion.textContent = BRAND_CONFIG.appVersion;
  if (staticAgentVersion) staticAgentVersion.textContent = BRAND_CONFIG.wazuhAgentVersion;

  // Document Title
  document.title = BRAND_CONFIG.appTitle;

  // Populates selects
  populateDropdown("wazuh-manager", BRAND_CONFIG.managers);
  populateDropdown("oauth-issuer", BRAND_CONFIG.oauthIssuers);
  populateDropdown("cert-endpoint", BRAND_CONFIG.certEndpoints);
}

function populateDropdown(selectId: string, options: { value: string; label: string }[]): void {
  const selectEl = document.getElementById(selectId) as HTMLSelectElement | null;
  if (!selectEl) return;
  const placeholderOption = selectEl.options[0];
  selectEl.innerHTML = "";
  if (placeholderOption) {
    selectEl.appendChild(placeholderOption);
  }
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

function updateNextButtonState(): void {
  if (!btnNext) return;
  if (currentStep === 0) {
    const manager = getManagerValue();
    const issuer = getIssuerValue();
    const endpoint = getEndpointValue();
    const isValid = !!manager && !!issuer && !!endpoint;
    btnNext.disabled = !isValid;
  } else {
    btnNext.disabled = false;
  }
}

// Show/hide custom inputs
function setupCustomInputListeners(): void {
  elManagerSelect?.addEventListener("change", () => {
    if (elManagerSelect.value === "other") {
      if (elManagerCustom) {
        elManagerCustom.style.display = "block";
        elManagerCustom.focus();
      }
    } else {
      if (elManagerCustom) {
        elManagerCustom.style.display = "none";
        elManagerCustom.value = "";
      }
    }
    updateNextButtonState();
  });
  elManagerCustom?.addEventListener("input", updateNextButtonState);

  elIssuerSelect?.addEventListener("change", () => {
    if (elIssuerSelect.value === "other") {
      if (elIssuerCustom) {
        elIssuerCustom.style.display = "block";
        elIssuerCustom.focus();
      }
    } else {
      if (elIssuerCustom) {
        elIssuerCustom.style.display = "none";
        elIssuerCustom.value = "";
      }
    }
    updateNextButtonState();
  });
  elIssuerCustom?.addEventListener("input", updateNextButtonState);

  elEndpointSelect?.addEventListener("change", () => {
    if (elEndpointSelect.value === "other") {
      if (elEndpointCustom) {
        elEndpointCustom.style.display = "block";
        elEndpointCustom.focus();
      }
    } else {
      if (elEndpointCustom) {
        elEndpointCustom.style.display = "none";
        elEndpointCustom.value = "";
      }
    }
    updateNextButtonState();
  });
  elEndpointCustom?.addEventListener("input", updateNextButtonState);
}

function getManagerValue(): string {
  if (elManagerSelect?.value === "other") return elManagerCustom?.value.trim() ?? "";
  return elManagerSelect?.value.trim() ?? "";
}

// Ensure default version matches what was original
function getIssuerValue(): string {
  if (elIssuerSelect?.value === "other") return elIssuerCustom?.value.trim() ?? "";
  return elIssuerSelect?.value.trim() ?? "";
}

function getEndpointValue(): string {
  if (elEndpointSelect?.value === "other") return elEndpointCustom?.value.trim() ?? "";
  return elEndpointSelect?.value.trim() ?? "";
}

// ---- Helpers ----
function getConfig() {
  const selectedModePill = document.querySelector("#suricata-mode-group .pill.selected") as HTMLElement | null;
  return {
    wazuh_manager: getManagerValue(),
    wazuh_agent_name: "wazuh-agent",
    wazuh_agent_version: BRAND_CONFIG.wazuhAgentVersion,
    log_level: "INFO",
    ids_engine: "suricata",
    suricata_mode: selectedModePill ? (selectedModePill.dataset.mode ?? "ids") : "ids",
    install_trivy: elTrivy ? elTrivy.checked : false,
    oauth_issuer: getIssuerValue(),
    cert_endpoint: getEndpointValue(),
  };
}

function stripAnsi(str: string): string {
  // eslint-disable-next-line no-control-regex
  return str.replace(/\x1b\[[0-9;]*m/g, "");
}

// ---- Stepper navigation ----
function goToStep(step: number): void {
  if (step < 0 || step >= totalSteps) return;
  currentStep = step;

  // Update panels
  panels.forEach((p, i) => {
    p.classList.toggle("active", i === step);
  });

  // Update step indicators
  stepItems.forEach((item, i) => {
    item.classList.remove("active", "done");
    if (i === step) item.classList.add("active");
    else if (i < step) item.classList.add("done");
  });

  connectors.forEach((c, i) => {
    c.classList.toggle("done", i < step);
  });

  // Update buttons
  if (btnBack) {
    btnBack.style.visibility = step === 0 ? "hidden" : "visible";
  }

  if (btnNext && btnBack) {
    if (step === totalSteps - 1) {
      btnNext.style.display = "none";
      btnBack.style.display = "none";
    } else if (step === 3) {
      btnNext.textContent = "⚡ Install";
      btnNext.style.display = "";
      btnBack.style.display = "";
    } else if (step === 2) {
      btnNext.textContent = "Start Install →";
      btnNext.style.display = "";
      btnBack.style.display = "";
    } else {
      btnNext.textContent = "Next →";
      btnNext.style.display = "";
      btnBack.style.display = "";
    }

    if (isInstalling) {
      btnNext.style.display = "none";
      btnBack.style.display = "none";
    }
  }

  if (footerHint) {
    footerHint.textContent = `Step ${step + 1} of ${totalSteps}`;
  }

  // Update button enabled/disabled state based on current step requirements
  updateNextButtonState();

  // Populate summary on step 2
  if (step === 2) populateSummary();

  // Set manager label on enroll step
  if (step === 4) {
    const label = document.getElementById("enroll-manager-label");
    if (label) label.textContent = getManagerValue() || "your Wazuh manager";
  }
}

function populateSummary(): void {
  const cfg = getConfig();
  const list = document.getElementById("summary-list");
  if (!list) return;
  const items = [
    ["Wazuh Manager", cfg.wazuh_manager],
    ["Agent Version", cfg.wazuh_agent_version],
    ["OAuth2 Issuer", cfg.oauth_issuer || "—"],
    ["Cert Endpoint", cfg.cert_endpoint || "—"],
    ["IDS Engine", `Suricata (${cfg.suricata_mode.toUpperCase()})`],
    ["Install Trivy", cfg.install_trivy ? "Yes" : "No"],
    ["Core Components", "Agent, Cert-OAuth2, Agent Status, Yara, USB DLP"],
  ];
  list.innerHTML = items
    .map(([label, value]) => `<li><span class="label">${label}</span><span class="value">${value}</span></li>`)
    .join("");
}

// ---- IDS Mode Pills ----
function setupRadioCards(): void {
  suricataModePills.forEach((pill) => {
    pill.addEventListener("click", () => {
      suricataModePills.forEach((p) => p.classList.remove("selected"));
      pill.classList.add("selected");
    });
  });
}

// ---- Terminal log ----
function appendLog(line: string, level: string): void {
  if (terminalPlaceholder) {
    terminalPlaceholder.remove();
  }
  if (terminal) {
    const div = document.createElement("div");
    div.className = `log-line ${level}`;
    div.textContent = stripAnsi(line);
    terminal.appendChild(div);
    terminal.scrollTop = terminal.scrollHeight;
  }
}

function showStatus(type: string, message: string): void {
  if (statusBanner) {
    statusBanner.className = `status-banner visible ${type}`;
    const icon = type === "running" ? '<span class="spinner"></span>' : type === "success" ? "✓" : "✕";
    statusBanner.innerHTML = `${icon} ${message}`;
  }
}

// ---- Installation ----
async function startInstall(): Promise<void> {
  const cfg = getConfig();
  isInstalling = true;

  if (btnNext) btnNext.style.display = "none";
  if (btnBack) btnBack.style.display = "none";
  if (footerHint) footerHint.textContent = "Installing…";

  showStatus("running", "Installation in progress…");
  appendLog("Starting Wazuh Agent installation…", "info");
  appendLog("A system password prompt will appear — please authenticate to continue.", "info");

  const unlistenLog = await listen<LogLine>("install-log", (event) => {
    appendLog(event.payload.line, event.payload.level);
  });

  try {
    const result = await invoke<InstallResult>("run_install", {
      config: cfg,
      scriptPath: null,
    });

    if (result.success) {
      showStatus("success", result.message);
      showResult(true, result.message);
    } else {
      showStatus("error", result.message);
      showResult(false, result.message);
    }
  } catch (err) {
    const msg = typeof err === "string" ? err : (err as Error).message || "Unknown error";
    appendLog(`ERROR: ${msg}`, "error");
    showStatus("error", `Installation failed: ${msg}`);
    showResult(false, msg);
  }

  unlistenLog();
  isInstalling = false;
}

function showResult(success: boolean, message: string): void {
  const resultScreen = document.getElementById("result-screen");
  const resultIcon = document.getElementById("result-icon");
  const resultTitle = document.getElementById("result-title");
  const resultDesc = document.getElementById("result-desc");
  const btnEnroll = document.getElementById("btn-enroll");

  if (resultScreen) resultScreen.style.display = "block";
  if (resultIcon) {
    resultIcon.className = `result-icon ${success ? "success" : "error"}`;
    resultIcon.textContent = success ? "✓" : "✕";
  }
  if (resultTitle) {
    resultTitle.textContent = success ? "Installation Complete" : "Installation Failed";
  }
  if (resultDesc) {
    resultDesc.textContent = success
      ? "The Wazuh Agent stack was installed successfully. Click below to enroll the agent."
      : message;
  }

  if (btnEnroll) btnEnroll.style.display = success ? "inline-flex" : "none";
  if (footerHint) footerHint.textContent = success ? "Done" : "Failed";
}

// ---- Validation ----
function validateStep(step: number): boolean {
  if (step === 0) {
    const manager = getManagerValue();
    if (!manager) {
      if (elManagerSelect) {
        elManagerSelect.focus();
        elManagerSelect.style.borderColor = "var(--status-error)";
      }
      return false;
    }
    if (elManagerSelect) elManagerSelect.style.borderColor = "";

    if (elManagerSelect?.value === "other" && elManagerCustom && !elManagerCustom.value.trim()) {
      elManagerCustom.focus();
      elManagerCustom.style.borderColor = "var(--status-error)";
      return false;
    }
    if (elManagerCustom) elManagerCustom.style.borderColor = "";

    if (!getIssuerValue()) {
      if (elIssuerSelect) {
        elIssuerSelect.focus();
        elIssuerSelect.style.borderColor = "var(--status-error)";
      }
      return false;
    }
    if (elIssuerSelect) elIssuerSelect.style.borderColor = "";

    if (!getEndpointValue()) {
      if (elEndpointSelect) {
        elEndpointSelect.focus();
        elEndpointSelect.style.borderColor = "var(--status-error)";
      }
      return false;
    }
    if (elEndpointSelect) elEndpointSelect.style.borderColor = "";
  }
  return true;
}

// ---- Event bindings ----
btnNext?.addEventListener("click", () => {
  if (isInstalling) return;

  if (currentStep < 2) {
    if (!validateStep(currentStep)) return;
    goToStep(currentStep + 1);
  } else if (currentStep === 2) {
    goToStep(3);
    startInstall();
  }
});

// Enroll button on Install result screen
document.getElementById("btn-enroll")?.addEventListener("click", () => {
  goToStep(4);
});

// Start Enrollment button on Enroll step
async function runEnrollment(): Promise<void> {
  const startArea = document.getElementById("enroll-start-area");
  const terminalArea = document.getElementById("enroll-terminal-area");
  const enrollTerminal = document.getElementById("enroll-terminal");
  const enrollStatusBanner = document.getElementById("enroll-status-banner");
  const retryBtn = document.getElementById("btn-retry-enroll");

  if (enrollTerminal) {
    enrollTerminal.innerHTML =
      '<div class="terminal-placeholder" id="enroll-terminal-placeholder"><span class="spinner"></span> Running enrollment…</div>';
  }

  if (startArea) startArea.style.display = "none";
  if (terminalArea) terminalArea.style.display = "block";
  if (retryBtn) retryBtn.style.display = "none";

  const enrollResultScreen = document.getElementById("enroll-result-screen");
  if (enrollResultScreen) enrollResultScreen.style.display = "none";

  if (enrollStatusBanner) {
    enrollStatusBanner.className = "status-banner visible running";
    enrollStatusBanner.innerHTML = '<span class="spinner"></span> Enrollment in progress — check your browser…';
  }

  const cfg = getConfig();
  const elOverwrite = document.getElementById("enroll-overwrite") as HTMLInputElement | null;
  const overwriteVal = elOverwrite ? elOverwrite.checked : true;

  const unlistenEnroll = await listen<LogLine>("enroll-log", (event) => {
    const placeholder = document.getElementById("enroll-terminal-placeholder");
    if (placeholder && placeholder.parentNode) placeholder.remove();
    if (enrollTerminal) {
      const div = document.createElement("div");
      div.className = `log-line ${event.payload.level}`;
      div.textContent = stripAnsi(event.payload.line);
      enrollTerminal.appendChild(div);
      enrollTerminal.scrollTop = enrollTerminal.scrollHeight;
    }
  });

  try {
    const result = await invoke<InstallResult>("run_enroll", {
      issuer: cfg.oauth_issuer,
      endpoint: cfg.cert_endpoint,
      overwrite: overwriteVal,
    });

    if (enrollStatusBanner) {
      enrollStatusBanner.className = `status-banner visible ${result.success ? "success" : "error"}`;
      enrollStatusBanner.innerHTML = `${result.success ? "✓" : "✕"} ${result.message}`;
    }

    if (!result.success && retryBtn) retryBtn.style.display = "flex";

    const enrollResultIcon = document.getElementById("enroll-result-icon");
    const enrollResultTitle = document.getElementById("enroll-result-title");
    const enrollResultDesc = document.getElementById("enroll-result-desc");

    if (enrollResultScreen) enrollResultScreen.style.display = "block";
    if (enrollResultIcon) {
      enrollResultIcon.className = `result-icon ${result.success ? "success" : "error"}`;
      enrollResultIcon.textContent = result.success ? "✓" : "✕";
    }
    if (enrollResultTitle) {
      enrollResultTitle.textContent = result.success ? "Enrollment Complete" : "Enrollment Failed";
    }
    if (enrollResultDesc) {
      enrollResultDesc.textContent = result.success
        ? "The agent has been enrolled with the Wazuh manager."
        : result.message;
    }

    if (footerHint) footerHint.textContent = result.success ? "Enrolled" : "Enrollment failed";
  } catch (err) {
    const msg = typeof err === "string" ? err : (err as Error).message || "Unknown error";
    if (enrollStatusBanner) {
      enrollStatusBanner.className = "status-banner visible error";
      enrollStatusBanner.innerHTML = `✕ Enrollment failed: ${msg}`;
    }
    if (retryBtn) retryBtn.style.display = "flex";
    if (footerHint) footerHint.textContent = "Failed";
  }

  unlistenEnroll();
}

document.getElementById("btn-skip-to-enroll")?.addEventListener("click", () => {
  goToStep(4);
});

document.getElementById("btn-start-enroll")?.addEventListener("click", runEnrollment);
document.getElementById("btn-retry-enroll")?.addEventListener("click", runEnrollment);

btnBack?.addEventListener("click", () => {
  if (isInstalling) return;
  if (currentStep > 0) goToStep(currentStep - 1);
});

async function closeWindow(): Promise<void> {
  try {
    await invoke("hide_window");
  } catch {
    try {
      const getCurrentWindow = window.__TAURI__!.window.getCurrentWindow;
      await getCurrentWindow().hide();
    } catch {
      window.close();
    }
  }
}

document.getElementById("btn-close")?.addEventListener("click", closeWindow);
document.getElementById("btn-close-enroll")?.addEventListener("click", closeWindow);

// ---- Init ----
applyBrandTheme();
initializeAppHeaderAndOptions();
setupCustomInputListeners();
setupRadioCards();
goToStep(0);
updateNextButtonState();
