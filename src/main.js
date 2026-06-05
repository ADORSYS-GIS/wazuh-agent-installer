import { BRAND_CONFIG } from "./config";
// ---- Tauri Core Bindings ----
const hasTauri = typeof window !== "undefined" && typeof window.__TAURI__ !== "undefined";
const invoke = hasTauri
    ? window.__TAURI__.core.invoke
    : async (cmd, args) => {
        console.log(`[Mock Invoke] ${cmd}`, args);
        if (cmd === "get_platform")
            return "linux";
        if (cmd === "is_root")
            return false;
        if (cmd === "verify_sudo")
            return (args?.password === "root");
        if (cmd === "run_install") {
            return { success: true, exit_code: 0, message: "Mock install successful" };
        }
        if (cmd === "run_enroll") {
            return { success: true, exit_code: 0, message: "Mock enroll successful" };
        }
        if (cmd === "check_components") {
            return [
                { name: "Wazuh Agent", installed: true, version: "4.14.1", path: "/var/ossec/bin/wazuh-agent" },
                { name: "OAuth2 Client", installed: false, version: null, path: "/var/ossec/bin/wazuh-cert-oauth2-client" },
            ];
        }
        return {};
    };
const listen = hasTauri
    ? window.__TAURI__.event.listen
    : async (event, _handler) => {
        console.log(`[Mock Listen] Registered handler for: ${event}`);
        return () => { };
    };
// ---- State ----
let sudoPassword = "";
let isInstalling = false;
let isEnrolling = false;
// ---- DOM refs ----
// Overlays
const sudoOverlay = document.getElementById("sudo-overlay");
const appContainer = document.getElementById("app");
const sudoPasswordInput = document.getElementById("sudo-password");
const btnSudoSubmit = document.getElementById("btn-sudo-submit");
const sudoError = document.getElementById("sudo-error");
// Nav
const navItems = document.querySelectorAll(".nav-item");
const tabPanels = document.querySelectorAll(".tab-panel");
// Config inputs
const elManagerSelect = document.getElementById("wazuh-manager");
const elManagerCustom = document.getElementById("wazuh-manager-custom");
const elIssuerSelect = document.getElementById("oauth-issuer");
const elIssuerCustom = document.getElementById("oauth-issuer-custom");
const elEndpointSelect = document.getElementById("cert-endpoint");
const elEndpointCustom = document.getElementById("cert-endpoint-custom");
const elTrivy = document.getElementById("install-trivy");
// IDS mode pills
const suricataModePills = document.querySelectorAll("#suricata-mode-group .pill");
// Install / Enroll Action Buttons
const btnStartInstall = document.getElementById("btn-start-install");
const btnStartEnroll = document.getElementById("btn-start-enroll");
const btnRetryEnroll = document.getElementById("btn-retry-enroll");
const btnGoEnroll = document.getElementById("btn-go-enroll");
const btnRefreshComponents = document.getElementById("btn-refresh-components");
// Terminals
const terminalInstall = document.getElementById("terminal");
const installLogCard = document.getElementById("install-log-card");
const installStatusBanner = document.getElementById("status-banner");
const resultScreen = document.getElementById("result-screen");
const terminalEnrollArea = document.getElementById("enroll-terminal-area");
const terminalEnroll = document.getElementById("enroll-terminal");
const enrollStatusBanner = document.getElementById("enroll-status-banner");
// ---- Initialization ----
async function boot() {
    applyBrandTheme();
    initializeAppHeaderAndOptions();
    setupCustomInputListeners();
    setupRadioCards();
    // Tab handling
    navItems.forEach((item) => {
        item.addEventListener("click", () => switchTab(item.dataset.target));
    });
    // Action listeners
    btnStartInstall?.addEventListener("click", startInstall);
    btnStartEnroll?.addEventListener("click", startEnrollment);
    btnRetryEnroll?.addEventListener("click", startEnrollment);
    btnGoEnroll?.addEventListener("click", () => switchTab("tab-enrollment"));
    btnRefreshComponents?.addEventListener("click", refreshComponents);
    const isRoot = await invoke("is_root");
    const platform = await invoke("get_platform");
    if (!isRoot && (platform === "linux" || platform === "macos")) {
        // Show Sudo prompt
        if (sudoOverlay)
            sudoOverlay.style.display = "flex";
        sudoPasswordInput?.addEventListener("input", () => {
            btnSudoSubmit.disabled = !sudoPasswordInput.value;
            if (sudoError)
                sudoError.style.display = "none";
        });
        sudoPasswordInput?.addEventListener("keydown", (e) => {
            if (e.key === "Enter" && sudoPasswordInput.value)
                handleSudoSubmit();
        });
        btnSudoSubmit?.addEventListener("click", handleSudoSubmit);
    }
    else {
        // Root or Windows -> skip prompt
        finishBoot();
    }
}
async function handleSudoSubmit() {
    const pwd = sudoPasswordInput.value;
    if (!pwd)
        return;
    btnSudoSubmit.disabled = true;
    btnSudoSubmit.innerHTML = `<span class="spinner" style="width: 14px; height: 14px; margin-right: 8px;"></span> Verifying...`;
    try {
        const ok = await invoke("verify_sudo", { password: pwd });
        if (ok) {
            sudoPassword = pwd;
            finishBoot();
        }
        else {
            showSudoError("Incorrect password, please try again.");
            sudoPasswordInput.value = "";
            sudoPasswordInput.focus();
        }
    }
    catch (e) {
        showSudoError(String(e));
    }
    finally {
        btnSudoSubmit.disabled = false;
        btnSudoSubmit.textContent = "Continue";
    }
}
function showSudoError(msg) {
    if (sudoError) {
        sudoError.textContent = msg;
        sudoError.style.display = "block";
    }
}
function finishBoot() {
    if (sudoOverlay)
        sudoOverlay.style.display = "none";
    if (appContainer)
        appContainer.style.display = "block";
    updateInstallButtonState();
    updateEnrollButtonState();
    refreshComponents(); // Initial load
}
function switchTab(targetId) {
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
function applyBrandTheme() {
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
}
function initializeAppHeaderAndOptions() {
    const appLogo = document.getElementById("app-logo");
    const appTitle = document.getElementById("app-title");
    const appVersion = document.getElementById("app-version");
    if (appLogo)
        appLogo.src = BRAND_CONFIG.logo;
    if (appTitle)
        appTitle.textContent = BRAND_CONFIG.appTitle;
    if (appVersion)
        appVersion.textContent = BRAND_CONFIG.appVersion;
    document.title = BRAND_CONFIG.appTitle;
    populateDropdown("wazuh-manager", BRAND_CONFIG.managers);
    populateDropdown("oauth-issuer", BRAND_CONFIG.oauthIssuers);
    populateDropdown("cert-endpoint", BRAND_CONFIG.certEndpoints);
}
function populateDropdown(selectId, options) {
    const selectEl = document.getElementById(selectId);
    if (!selectEl)
        return;
    const placeholderOption = selectEl.options[0];
    selectEl.innerHTML = "";
    if (placeholderOption)
        selectEl.appendChild(placeholderOption);
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
function setupCustomInputListeners() {
    const bindSelectToCustom = (sel, cus, updateBtn) => {
        sel?.addEventListener("change", () => {
            if (sel.value === "other" && cus) {
                cus.style.display = "block";
                cus.focus();
            }
            else if (cus) {
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
}
function setupRadioCards() {
    suricataModePills.forEach((pill) => {
        pill.addEventListener("click", () => {
            suricataModePills.forEach((p) => p.classList.remove("selected"));
            pill.classList.add("selected");
        });
    });
}
// ---- Data Retrieval ----
function getManagerValue() {
    return elManagerSelect?.value === "other"
        ? (elManagerCustom?.value.trim() ?? "")
        : (elManagerSelect?.value.trim() ?? "");
}
function getIssuerValue() {
    return elIssuerSelect?.value === "other"
        ? (elIssuerCustom?.value.trim() ?? "")
        : (elIssuerSelect?.value.trim() ?? "");
}
function getEndpointValue() {
    return elEndpointSelect?.value === "other"
        ? (elEndpointCustom?.value.trim() ?? "")
        : (elEndpointSelect?.value.trim() ?? "");
}
function getConfig() {
    const selectedModePill = document.querySelector("#suricata-mode-group .pill.selected");
    return {
        wazuh_manager: getManagerValue(),
        wazuh_agent_name: "wazuh-agent",
        log_level: "INFO",
        ids_engine: "suricata",
        suricata_mode: selectedModePill ? (selectedModePill.dataset.mode ?? "ids") : "ids",
        install_trivy: elTrivy ? elTrivy.checked : false,
        oauth_issuer: getIssuerValue(),
        cert_endpoint: getEndpointValue(),
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
function stripAnsi(str) {
    // eslint-disable-next-line no-control-regex
    return str.replace(/\x1b\[[0-9;]*m/g, "");
}
function appendLog(term, line, level) {
    if (!term)
        return;
    const placeholder = term.querySelector(".terminal-placeholder");
    if (placeholder)
        placeholder.remove();
    const div = document.createElement("div");
    div.className = `log-line ${level}`;
    div.textContent = stripAnsi(line);
    term.appendChild(div);
    term.scrollTop = term.scrollHeight;
}
function showStatusBanner(banner, type, message) {
    if (!banner)
        return;
    banner.className = `status-banner visible ${type}`;
    const icon = type === "running" ? '<span class="spinner"></span>' : type === "success" ? "✓" : "✕";
    banner.innerHTML = `${icon} ${message}`;
}
async function startInstall() {
    if (isInstalling)
        return;
    isInstalling = true;
    updateInstallButtonState();
    if (installLogCard)
        installLogCard.style.display = "block";
    if (resultScreen)
        resultScreen.style.display = "none";
    if (terminalInstall) {
        terminalInstall.innerHTML =
            '<div class="terminal-placeholder"><span class="spinner"></span> Waiting to start…</div>';
    }
    showStatusBanner(installStatusBanner, "running", "Installation in progress…");
    appendLog(terminalInstall, "Starting Wazuh Agent installation…", "info");
    const unlistenLog = await listen("install-log", (e) => {
        appendLog(terminalInstall, e.payload.line, e.payload.level);
    });
    try {
        const result = await invoke("run_install", {
            config: getConfig(),
            password: sudoPassword || null,
        });
        if (result.success) {
            showStatusBanner(installStatusBanner, "success", result.message);
            showInstallResult(true, "The Wazuh Agent stack was installed successfully.");
            // Auto-switch to Enrollment and start it
            setTimeout(() => {
                switchTab("tab-enrollment");
                startEnrollment();
            }, 1500);
        }
        else {
            showStatusBanner(installStatusBanner, "error", `Installation failed: exit code ${result.exit_code}`);
            showInstallResult(false, result.message);
        }
    }
    catch (err) {
        appendLog(terminalInstall, `ERROR: ${err}`, "error");
        showStatusBanner(installStatusBanner, "error", `Installation failed: ${err}`);
        showInstallResult(false, String(err));
    }
    finally {
        unlistenLog();
        isInstalling = false;
        updateInstallButtonState();
        enableSaveLogs("btn-save-install-logs", "terminal", "install");
    }
}
function showInstallResult(success, desc) {
    if (!resultScreen)
        return;
    resultScreen.style.display = "block";
    const icon = document.getElementById("result-icon");
    const title = document.getElementById("result-title");
    const descEl = document.getElementById("result-desc");
    const btn = document.getElementById("btn-go-enroll");
    if (icon) {
        icon.className = `result-icon ${success ? "success" : "error"}`;
        icon.textContent = success ? "✓" : "✕";
    }
    if (title)
        title.textContent = success ? "Installation Complete" : "Installation Failed";
    if (descEl)
        descEl.textContent = desc;
    if (btn)
        btn.style.display = success ? "inline-flex" : "none";
}
// ---- Enrollment Flow ----
async function startEnrollment() {
    if (isEnrolling)
        return;
    const issuer = getIssuerValue();
    const endpoint = getEndpointValue();
    if (!issuer || !endpoint)
        return;
    isEnrolling = true;
    updateEnrollButtonState();
    const elOverwrite = document.getElementById("enroll-overwrite");
    const overwrite = elOverwrite ? elOverwrite.checked : true;
    if (terminalEnrollArea)
        terminalEnrollArea.style.display = "block";
    if (btnRetryEnroll)
        btnRetryEnroll.style.display = "none";
    if (terminalEnroll) {
        terminalEnroll.innerHTML =
            '<div class="terminal-placeholder"><span class="spinner"></span> Running enrollment…</div>';
    }
    showStatusBanner(enrollStatusBanner, "running", "Enrollment in progress — check your browser…");
    const unlistenLog = await listen("enroll-log", (e) => {
        appendLog(terminalEnroll, e.payload.line, e.payload.level);
    });
    try {
        const result = await invoke("run_enroll", {
            issuer,
            endpoint,
            overwrite,
            password: sudoPassword || null,
        });
        if (result.success) {
            showStatusBanner(enrollStatusBanner, "success", "Agent enrolled successfully!");
        }
        else {
            showStatusBanner(enrollStatusBanner, "error", `Enrollment failed: exit code ${result.exit_code}`);
            if (btnRetryEnroll)
                btnRetryEnroll.style.display = "flex";
        }
    }
    catch (err) {
        showStatusBanner(enrollStatusBanner, "error", `Enrollment error: ${err}`);
        if (btnRetryEnroll)
            btnRetryEnroll.style.display = "flex";
    }
    finally {
        unlistenLog();
        isEnrolling = false;
        updateEnrollButtonState();
        refreshComponents();
        enableSaveLogs("btn-save-enroll-logs", "enroll-terminal", "enroll");
    }
}
// ---- Components Tab ----
async function refreshComponents() {
    const grid = document.getElementById("components-grid");
    if (!grid)
        return;
    const btn = document.getElementById("btn-refresh-components");
    if (btn)
        btn.innerHTML = `<span class="spinner" style="margin-right: 6px"></span> Refreshing...`;
    try {
        const components = await invoke("check_components");
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
        ${comp.version ? `<div class="comp-version">📦 ${comp.version}</div>` : ""}
        <div class="comp-path">${comp.path}</div>
      `;
            grid.appendChild(card);
        });
    }
    catch (err) {
        console.error("Failed to check components", err);
    }
    finally {
        if (btn)
            btn.textContent = "↺ Refresh";
    }
}
// ---- Start ----
boot();
// ---- Helpers ----
function enableSaveLogs(buttonId, terminalId, prefix) {
    const btn = document.getElementById(buttonId);
    const term = document.getElementById(terminalId);
    if (!btn || !term)
        return;
    btn.style.display = "inline-flex";
    btn.onclick = async () => {
        const clone = term.cloneNode(true);
        const placeholder = clone.querySelector(".terminal-placeholder");
        if (placeholder)
            placeholder.remove();
        const logs = clone.innerText.trim();
        if (!logs)
            return;
        try {
            const path = await invoke("save_logs", { logs, prefix });
            alert(`Logs successfully saved to:\n${path}`);
        }
        catch (e) {
            alert(`Failed to save logs: ${e}`);
        }
    };
}
