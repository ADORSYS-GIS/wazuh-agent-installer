use serde::{Deserialize, Serialize};
use std::env;
use std::process::Stdio;
use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};
use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    AppHandle, Emitter, Manager,
};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

#[cfg(windows)]
use std::os::windows::process::CommandExt;

// ---- Types ----

#[derive(Serialize, Clone)]
struct LogLine {
    line: String,
    level: String,
}

#[derive(Serialize, Clone)]
struct InstallResult {
    success: bool,
    exit_code: i32,
    message: String,
}

#[derive(Serialize)]
struct ComponentStatus {
    name: String,
    installed: bool,
    version: Option<String>,
    path: String,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct InstallConfig {
    pub wazuh_manager: String,
    pub wazuh_agent_name: String,
    // TODO: ids_engine is reserved for future Snort support; currently always "suricata"
    pub ids_engine: String,
    pub suricata_mode: String,
    pub install_trivy: bool,
    pub install_netbird: bool,
    pub install_velociraptor: bool,
    pub velociraptor_config: String,
    pub oauth_issuer: String,
    pub cert_endpoint: String,
}

// ---- Helpers ----

async fn get_component_version(name: &str, path: &str) -> Option<String> {
    if name == "USB DLP Scripts" {
        return Some("Installed".to_string());
    }

    let mut args = vec![];
    let mut cmd_target = path.to_string();

    if name == "Wazuh Agent" {
        #[cfg(unix)]
        {
            cmd_target = path
                .replace("wazuh-agentd", "wazuh-control")
                .replace("ossec-agentd", "wazuh-control");
            args.push("info".to_string());
        }
        #[cfg(windows)]
        {
            cmd_target = "powershell".to_string();
            args.push("-NoProfile".to_string());
            args.push("-Command".to_string());
            args.push(format!("(Get-Item '{}').VersionInfo.ProductVersion", path));
        }
    } else if name == "Suricata" {
        args.push("-V".to_string());
    } else if name == "NetBird" || name == "Velociraptor" {
        args.push("version".to_string());
    } else {
        args.push("--version".to_string());
    }

    let mut cmd = create_command(&cmd_target);
    cmd.args(&args);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    // Automatically terminate the process if it times out or gets dropped.
    cmd.kill_on_drop(true);

    if let Ok(child) = cmd.spawn() {
        if let Ok(Ok(output)) =
            tokio::time::timeout(std::time::Duration::from_secs(2), child.wait_with_output()).await
        {
            let out_str = String::from_utf8_lossy(&output.stdout).to_string()
                + String::from_utf8_lossy(&output.stderr).as_ref();

            if name == "YARA" {
                let first_line = out_str.lines().next().unwrap_or(&out_str);
                return Some(first_line.trim().to_string());
            } else if name == "Suricata" {
                if let Some(idx) = out_str.find("version ") {
                    let rest = &out_str[idx + 8..];
                    return Some(
                        rest.split_whitespace()
                            .next()
                            .unwrap_or(&out_str)
                            .to_string(),
                    );
                }
                return Some(out_str.trim().to_string());
            } else if name == "Trivy" {
                if let Some(idx) = out_str.find("Version: ") {
                    let rest = &out_str[idx + 9..];
                    return Some(
                        rest.split_whitespace()
                            .next()
                            .unwrap_or(&out_str)
                            .to_string(),
                    );
                }
                return Some(out_str.trim().to_string());
            } else if name == "Wazuh Agent" {
                if let Some(idx) = out_str.find("WAZUH_VERSION=\"") {
                    let rest = &out_str[idx + 15..];
                    if let Some(end) = rest.find("\"") {
                        return Some(rest[..end].to_string());
                    }
                } else if let Some(idx) = out_str.find("Wazuh v") {
                    let rest = &out_str[idx + 7..];
                    return Some(rest.split_whitespace().next().unwrap_or("").to_string());
                } else if cfg!(windows) {
                    let trimmed = out_str.trim();
                    if !trimmed.is_empty() {
                        return Some(trimmed.to_string());
                    }
                }
            } else if name == "NetBird" {
                // `netbird version` outputs just the version on a single line
                let trimmed = out_str.trim();
                if let Some(first) = trimmed.lines().next() {
                    let v = first.trim().to_string();
                    if !v.is_empty() {
                        return Some(v);
                    }
                }
            } else if name == "Velociraptor" {
                // `velociraptor version` outputs YAML-style: `version: 0.75.6`
                for line in out_str.lines() {
                    let trimmed = line.trim().to_string();
                    if let Some(ver) = trimmed.strip_prefix("version:") {
                        let ver = ver.trim().to_string();
                        if !ver.is_empty() {
                            return Some(ver);
                        }
                    }
                }
            } else if name == "OAuth2 Client" {
                // Output may start with a log line like `[2026-07-23T...] starting up`
                // followed by the actual version: `Wazuh Cert Auth CLI X.Y.Z`
                for line in out_str.lines() {
                    let trimmed = line.trim();
                    if trimmed.starts_with('[') {
                        continue;
                    }
                    if let Some(idx) = trimmed.find("CLI ") {
                        let rest = &trimmed[idx + 4..];
                        if let Some(v) = rest.split_whitespace().next() {
                            if !v.is_empty() {
                                return Some(v.to_string());
                            }
                        }
                    }
                    // Fallback: first non-log line containing a version-like number
                    if trimmed.chars().any(|c| c.is_ascii_digit()) && trimmed.contains('.') {
                        return Some(trimmed.to_string());
                    }
                }
            } else {
                for line in out_str.lines() {
                    let trimmed = line.trim();
                    if trimmed.chars().any(|c| c.is_ascii_digit()) {
                        let parts: Vec<&str> = trimmed.split_whitespace().collect();
                        for p in parts {
                            let is_date = p.contains('-') && p.split('-').count() == 3;
                            let is_path = p.contains('/') || p.contains('\\');
                            if p.chars().any(|c| c.is_ascii_digit())
                                && p.contains('.')
                                && !is_date
                                && !is_path
                            {
                                return Some(p.to_string());
                            }
                        }
                        return Some(trimmed.to_string());
                    }
                }
            }
        }
    }
    None
}

/// Create a background command, hiding the console window on Windows.
fn create_command(cmd: &str) -> Command {
    #[cfg(windows)]
    {
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        let mut std_cmd = std::process::Command::new(cmd);
        std_cmd.creation_flags(CREATE_NO_WINDOW);
        Command::from(std_cmd)
    }
    #[cfg(not(windows))]
    {
        Command::new(cmd)
    }
}

/// Classify a log line as "error", "success", or "info" for UI highlighting.
fn classify_line(line: &str) -> &'static str {
    let l = line.to_lowercase();
    if l.contains("[error]")
        || l.contains("failed")
        || l.contains("error:")
        || l.contains("command not found")
    {
        "error"
    } else if l.contains("[success]") || l.contains("successfully") || l.contains("completed") {
        "success"
    } else {
        "info"
    }
}

/// Get the PATH prefix for macOS GUI-launched processes.
/// Returns "/opt/homebrew/bin:/usr/local/bin:" to be prepended to the current PATH.
fn get_macos_gui_path_prefix() -> String {
    "/opt/homebrew/bin:/usr/local/bin:".to_string()
}

/// Inject a PATH that includes common Homebrew locations so macOS GUI-launched
/// processes can find user-installed binaries.
fn inject_path(command: &mut Command) {
    let current_path =
        std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin:/usr/sbin:/sbin".to_string());
    command.env("PATH", format!("{}:{}", get_macos_gui_path_prefix(), current_path));
}

/// Open a URL in the user's default browser.
///
/// The app runs as root after privilege elevation, but the browser must open
/// in the user's desktop session. On Linux we use `runuser -u <user>` to
/// drop back to the original user; on macOS / Windows the native commands
/// already handle the session correctly.
fn open_url_in_browser(url: &str) -> bool {
    // Windows: use rundll32 (cmd `start` breaks with long URLs — opens
    // file explorer instead of the browser).
    #[cfg(target_os = "windows")]
    {
        return std::process::Command::new("rundll32")
            .arg("url.dll,FileProtocolHandler")
            .arg(url)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map(|_| true)
            .unwrap_or(false);
    }

    // macOS: use `open`.
    #[cfg(target_os = "macos")]
    {
        return std::process::Command::new("open")
            .arg(url)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map(|_| true)
            .unwrap_or(false);
    }

    // Linux: prefer runuser to drop back to the original user so xdg-open
    // can reach the desktop session (D-Bus, DISPLAY, etc.).
    #[cfg(target_os = "linux")]
    {
        let mut cmd =
            if let Some(user) = env::var("ORIGINAL_USER")
                .ok()
                .filter(|u| !u.is_empty() && u != "root")
            {
            let mut c = std::process::Command::new("runuser");
            c.arg("-u").arg(&user).arg("--").arg("xdg-open").arg(url);
            c
        } else {
            let mut c = std::process::Command::new("xdg-open");
            c.arg(url);
            c
        };

        // Forward display and dbus session so xdg-open works cleanly.
        if let Ok(display) = env::var("DISPLAY") {
            cmd.env("DISPLAY", display);
        }
        if let Ok(wayland) = env::var("WAYLAND_DISPLAY") {
            cmd.env("WAYLAND_DISPLAY", wayland);
        }
        if let Ok(dbus) = env::var("DBUS_SESSION_BUS_ADDRESS") {
            cmd.env("DBUS_SESSION_BUS_ADDRESS", dbus);
        }

        cmd.stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        cmd.spawn().map(|_| true).unwrap_or(false)
    }
}

/// Try to extract and open a browser URL from a log line.
///
/// Two patterns are supported:
/// - Enrollment: `"Opened your default browser to: <URL>"` (single line)
/// - NetBird: `"use this URL to log in:"` on one line, URL on the next line
///
/// Returns `true` if a URL was opened. `expect_url_next` tracks the NetBird
/// multi-line state across calls.
fn try_open_browser_url(line: &str, expect_url_next: &mut bool) -> bool {
    // Pattern 1: "Opened your default browser to: <URL>" (enrollment binary)
    if let Some(url_start) = line.find("Opened your default browser to: ") {
        let url = line[url_start + "Opened your default browser to: ".len()..].trim();
        if !url.is_empty() {
            open_url_in_browser(url);
            return true;
        }
    }

    // Pattern 2: NetBird SSO — "use this URL to log in:" then URL on next line
    if line.contains("use this URL to log in:") {
        *expect_url_next = true;
        return false;
    }
    if *expect_url_next && line.trim().starts_with("http") {
        let url = line.trim();
        open_url_in_browser(url);
        *expect_url_next = false;
        return true;
    }

    false
}

/// Per-command configuration for [`run_streamed_command`].
struct StreamConfig {
    event_name: &'static str,
    success_msg: &'static str,
    failure_msg: &'static str,
    intercept_browser_url: bool,
    spawn_err: Option<&'static str>,
}

/// Spawn a command, stream its stdout/stderr to the frontend via
/// `cfg.event_name`, and return the exit result.
async fn run_streamed_command(
    app: AppHandle,
    mut command: Command,
    cfg: StreamConfig,
) -> Result<InstallResult, String> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = command.spawn().map_err(|e| match cfg.spawn_err {
        Some(msg) => format!("{}: {}", msg, e),
        None => e.to_string(),
    })?;

    let stdout = child.stdout.take().expect("Failed to capture stdout");
    let stderr = child.stderr.take().expect("Failed to capture stderr");

    let saw_error = Arc::new(AtomicBool::new(false));

    let app_clone1 = app.clone();
    let event_name = cfg.event_name;
    let intercept_stdout = cfg.intercept_browser_url;
    let url_state = Arc::new(Mutex::new(false));
    let url_state_stdout = Arc::clone(&url_state);
    let saw_error_clone1 = Arc::clone(&saw_error);
    tokio::spawn(async move {
        let mut reader = BufReader::new(stdout).lines();
        while let Ok(Some(line)) = reader.next_line().await {
            if intercept_stdout {
                let mut expect_url_next = url_state_stdout.lock().unwrap();
                try_open_browser_url(&line, &mut expect_url_next);
            }
            let level = classify_line(&line);
            if level == "error" {
                saw_error_clone1.store(true, Ordering::Relaxed);
            }
            let _ = app_clone1.emit(
                event_name,
                LogLine {
                    line,
                    level: level.into(),
                },
            );
        }
    });

    let app_clone2 = app.clone();
    let event_name = cfg.event_name;
    let intercept_stderr = cfg.intercept_browser_url;
    let url_state_stderr = Arc::clone(&url_state);
    let saw_error_clone2 = Arc::clone(&saw_error);
    tokio::spawn(async move {
        let mut reader = BufReader::new(stderr).lines();
        while let Ok(Some(line)) = reader.next_line().await {
            if line.trim().is_empty() {
                continue;
            }
            if intercept_stderr {
                let mut expect_url_next = url_state_stderr.lock().unwrap();
                try_open_browser_url(&line, &mut expect_url_next);
            }
            let level = classify_line(&line);
            if level == "error" {
                saw_error_clone2.store(true, Ordering::Relaxed);
            }
            let _ = app_clone2.emit(
                event_name,
                LogLine {
                    line,
                    level: level.into(),
                },
            );
        }
    });

    let status = child.wait().await.map_err(|e| e.to_string())?;

    // Some binaries (e.g. wazuh-cert-oauth2-client) exit 0 even on error.
    // Override success if any ERROR-level output was detected.
    let actually_ok = status.success() && !saw_error.load(Ordering::Relaxed);

    Ok(InstallResult {
        success: actually_ok,
        exit_code: status.code().unwrap_or(-1),
        message: if actually_ok {
            cfg.success_msg.into()
        } else {
            cfg.failure_msg.into()
        },
    })
}

// ---- Commands ----

fn resolve_script(app: &AppHandle) -> Result<String, String> {
    let script_name = if cfg!(windows) {
        "setup-agent.ps1"
    } else {
        "setup-agent.sh"
    };
    let resource_path = app
        .path()
        .resolve(script_name, tauri::path::BaseDirectory::Resource)
        .map_err(|e| format!("Failed to resolve resource path: {}", e))?;

    // If the file is already executable, use it directly (installed .deb case)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(&resource_path) {
            let mode = meta.permissions().mode();
            if mode & 0o111 != 0 {
                // Already executable — use in place
                return resource_path
                    .to_str()
                    .map(|s| s.to_string())
                    .ok_or_else(|| "Script path contains invalid UTF-8".to_string());
            }
        }
        // Not executable — copy to /tmp and chmod (dev mode)
        let tmp_path = std::env::temp_dir().join("wazuh-setup-agent.sh");
        std::fs::copy(&resource_path, &tmp_path)
            .map_err(|e| format!("Failed to copy script to temp dir: {}", e))?;
        std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("Failed to set script permissions: {}", e))?;
        tmp_path
            .to_str()
            .map(|s| s.to_string())
            .ok_or_else(|| "Script path contains invalid UTF-8".to_string())
    }

    #[cfg(not(unix))]
    resource_path
        .to_str()
        .map(|s| s.to_string())
        .ok_or_else(|| "Script path contains invalid UTF-8".to_string())
}

#[tauri::command]
fn get_platform() -> String {
    env::consts::OS.to_string()
}

#[tauri::command]
fn is_root() -> bool {
    #[cfg(unix)]
    unsafe {
        libc::geteuid() == 0
    }
    #[cfg(windows)]
    {
        // On Windows this always returns true. Actual elevation is handled by the OS UAC
        // prompt at process launch time. Callers should not treat this as a reliable
        // indicator of real administrator status — it's a platform-level no-op.
        true
    }
}

#[tauri::command]
async fn run_install(config: InstallConfig, app: AppHandle) -> Result<InstallResult, String> {
    let resolved_path = resolve_script(&app)?;

    // The process is already running as root (elevated at launch), so we can
    // invoke bash directly — no sudo or pkexec wrapper needed.

    #[cfg(target_os = "windows")]
    let mut command = {
        let mut c = create_command("powershell");
        c.args([
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            &resolved_path,
        ]);
        if config.install_netbird {
            c.arg("-InstallNetBird");
        }
        if config.install_velociraptor {
            c.arg("-InstallVelociraptor");
        }
        if !config.velociraptor_config.is_empty() {
            c.arg("-VelociraptorConfig");
            c.arg(&config.velociraptor_config);
        }
        c
    };

    #[cfg(not(target_os = "windows"))]
    let command = {
        let mut c = create_command("bash");
        c.arg(&resolved_path);
        // Inject env vars — we are already root so no env-stripping occurs
        c.env("WAZUH_MANAGER", &config.wazuh_manager)
            .env("WAZUH_AGENT_NAME", &config.wazuh_agent_name)
            .env("IDS_ENGINE", &config.ids_engine)
            .env("SURICATA_MODE", &config.suricata_mode)
            .env(
                "INSTALL_TRIVY",
                if config.install_trivy {
                    "true"
                } else {
                    "false"
                },
            )
            .env(
                "WAZUH_AGENT_REPO_REF",
                std::env::var("WAZUH_AGENT_REPO_REF").unwrap_or_else(|_| "develop".to_string()),
            );

        if config.install_netbird {
            c.arg("-b");
        }
        if config.install_velociraptor {
            c.arg("-v");
        }
        if !config.velociraptor_config.is_empty() {
            c.arg("-c");
            c.arg(&config.velociraptor_config);
        }

        #[cfg(target_os = "macos")]
        inject_path(&mut c);

        c
    };

    run_streamed_command(
        app,
        command,
        StreamConfig {
            event_name: "install-log",
            success_msg: "Installation complete",
            failure_msg: "Installation failed",
            intercept_browser_url: false,
            spawn_err: None,
        },
    )
    .await
}

#[tauri::command]
async fn run_enroll(
    issuer: String,
    endpoint: String,
    overwrite: bool,
    app: AppHandle,
) -> Result<InstallResult, String> {
    let mut oauth_args = vec![
        "o-auth2".to_string(),
        "--issuer".to_string(),
        issuer,
        "--endpoint".to_string(),
        endpoint,
    ];
    if overwrite {
        oauth_args.push("--overwrite".to_string());
    }

    // The process is already root at this point.
    // Call the binary directly — no pkexec or osascript wrapper needed.

    #[cfg(target_os = "windows")]
    let mut command = {
        let exe = "C:\\Program Files (x86)\\ossec-agent\\wazuh-cert-oauth2-client.exe";
        let mut c = create_command(exe);
        c.args(&oauth_args);
        c
    };

    #[cfg(target_os = "linux")]
    let command = {
        let exe = "/var/ossec/bin/wazuh-cert-oauth2-client";
        let mut c = create_command(exe);
        c.args(&oauth_args);
        c
    };

    #[cfg(target_os = "macos")]
    let mut command = {
        // On macOS (running as root), call the binary directly.
        // Intercept the browser URL from stderr and open it via Tauri's GUI context.
        let exe = "/Library/Ossec/bin/wazuh-cert-oauth2-client";
        let mut c = create_command(exe);
        c.args(&oauth_args);
        inject_path(&mut c);
        c
    };

    run_streamed_command(
        app,
        command,
        StreamConfig {
            event_name: "enroll-log",
            success_msg: "Enrollment complete",
            failure_msg: "Enrollment failed",
            intercept_browser_url: true, // sudo strips GUI session; we open URLs ourselves
            spawn_err: None,
        },
    )
    .await
}

#[tauri::command]
async fn run_netbird_up(
    setup_key: String,
    management_url: String,
    app: AppHandle,
) -> Result<InstallResult, String> {
    // Management URL defaults to the public NetBird Cloud when not provided.
    let management_url = if management_url.trim().is_empty() {
        "https://api.netbird.io:443".to_string()
    } else {
        management_url
    };

    let mut args = vec![
        "up".to_string(),
        "--management-url".to_string(),
        management_url,
    ];

    // Only pass --setup-key when one is provided; otherwise let the daemon
    // use its existing configuration or attempt interactive login.
    if !setup_key.trim().is_empty() {
        args.push("--setup-key".to_string());
        args.push(setup_key);
    }

    // The process is already running as root, so we can call netbird directly.
    // On Windows the NSIS installer places netbird.exe under
    // "C:\Program Files\Netbird\" which is not on the default PATH, so we
    // use the full path to avoid "Program not found" errors.
    #[cfg(unix)]
    let mut command = {
        let mut c = create_command("netbird");
        c.args(&args);
        c
    };

    #[cfg(windows)]
    let mut command = {
        let mut c = create_command(r"C:\Program Files\Netbird\netbird.exe");
        c.args(&args);
        c
    };

    inject_path(&mut command);

    run_streamed_command(
        app,
        command,
        StreamConfig {
            event_name: "netbird-log",
            success_msg: "NetBird connected successfully",
            failure_msg: "NetBird connection failed",
            intercept_browser_url: true,
            spawn_err: Some("Failed to spawn netbird. Is the NetBird client installed?"),
        },
    )
    .await
}

/// Build the list of (name, binary path) pairs for all checkable components.
fn component_paths() -> Vec<(&'static str, String)> {
    let ossec_path = if cfg!(windows) {
        r"C:\Program Files (x86)\ossec-agent"
    } else if cfg!(target_os = "macos") {
        "/Library/Ossec"
    } else {
        "/var/ossec"
    };

    vec![
        (
            "Wazuh Agent",
            if cfg!(windows) {
                format!("{}\\wazuh-agent.exe", ossec_path)
            } else {
                format!("{}/bin/wazuh-agentd", ossec_path)
            },
        ),
        (
            "OAuth2 Client",
            if cfg!(windows) {
                format!("{}\\wazuh-cert-oauth2-client.exe", ossec_path)
            } else {
                format!("{}/bin/wazuh-cert-oauth2-client", ossec_path)
            },
        ),
        (
            "Agent Status Monitor",
            if cfg!(windows) {
                r"C:\Program Files\wazuh-agent-status\wazuh-agent-status.exe".to_string()
            } else {
                "/usr/local/bin/wazuh-agent-status".to_string()
            },
        ),
        (
            "YARA",
            if cfg!(windows) {
                "yara64.exe".to_string()
            } else {
                "/usr/local/bin/yara".to_string()
            },
        ),
        (
            "Suricata",
            if cfg!(windows) {
                "suricata.exe".to_string()
            } else if cfg!(target_os = "macos") {
                "/usr/local/bin/suricata".to_string()
            } else {
                "/usr/bin/suricata".to_string()
            },
        ),
        (
            "Trivy",
            if cfg!(windows) {
                "trivy.exe".to_string()
            } else {
                "/usr/local/bin/trivy".to_string()
            },
        ),
        (
            "USB DLP Scripts",
            if cfg!(windows) {
                format!(
                    "{}\\active-response\\bin\\disable-usb-storage.ps1",
                    ossec_path
                )
            } else if cfg!(target_os = "macos") {
                format!(
                    "{}/active-response/bin/disable-usb-storage-macos.sh",
                    ossec_path
                )
            } else {
                format!("{}/active-response/bin/disable-usb-storage.sh", ossec_path)
            },
        ),
        (
            "NetBird",
            if cfg!(windows) {
                r"C:\Program Files\Netbird\netbird.exe".to_string()
            } else {
                "/usr/bin/netbird".to_string()
            },
        ),
        (
            "Velociraptor",
            if cfg!(windows) {
                r"C:\Program Files\Velociraptor\velociraptor.exe".to_string()
            } else {
                "/opt/velociraptor/velociraptor".to_string()
            },
        ),
    ]
}

/// Check if a component is installed on Windows.
#[cfg(windows)]
async fn check_installed_windows(path: &str) -> bool {
    if path == "yara64.exe"
        || path == "suricata.exe"
        || path == "trivy.exe"
        || path.ends_with("netbird.exe")
    {
        create_command(path)
            .arg("--help")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .is_ok()
    } else if path.ends_with("wazuh-agent.exe") {
        std::path::Path::new(path).exists()
            || std::path::Path::new(&path.replace("wazuh-agent.exe", "ossec-agent.exe")).exists()
            || create_command("sc")
                .args(["query", "WazuhSvc"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .await
                .map_or(false, |s| s.success())
    } else {
        std::path::Path::new(path).exists()
    }
}

#[tauri::command]
async fn check_components() -> Result<Vec<ComponentStatus>, String> {
    let mut results = Vec::new();

    for (name, path) in component_paths() {
        // Check existence without sudo — the process is already running as root.
        #[cfg(unix)]
        let installed = std::path::Path::new(&path).exists();

        #[cfg(windows)]
        let installed = check_installed_windows(&path).await;

        let version = if installed {
            get_component_version(name, &path).await
        } else {
            None
        };

        results.push(ComponentStatus {
            name: name.to_string(),
            installed,
            version,
            path,
        });
    }

    Ok(results)
}

#[tauri::command]
async fn save_logs(logs: String, prefix: String) -> Result<String, String> {
    let mut path = dirs::download_dir().unwrap_or_else(|| std::env::current_dir().unwrap());
    let filename = format!("wazuh-{}-logs.txt", prefix);
    path.push(filename);

    tokio::fs::write(&path, logs)
        .await
        .map_err(|e| e.to_string())?;
    Ok(path.to_string_lossy().to_string())
}

#[tauri::command]
async fn pick_velociraptor_config(app: AppHandle) -> Result<Option<String>, String> {
    use tauri_plugin_dialog::DialogExt;

    let (tx, rx) = tokio::sync::oneshot::channel::<Option<String>>();
    app.dialog()
        .file()
        .add_filter("YAML config", &["yaml", "yml"])
        .pick_file(move |path| {
            let result = path.map(|p| p.to_string());
            let _ = tx.send(result);
        });
    Ok(rx.await.unwrap_or(None))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Capture our PID before elevation so the elevated child can watch us.
    // Only needed on Unix — the watchdog that consumes it is #[cfg(unix)].
    #[cfg(unix)]
    let launcher_pid = std::process::id();

    // ---- Privilege elevation ----
    // Relaunch as root if not already elevated. The elevated child inherits
    // our CLI args and watches our PID so it exits when we (the launcher) die.

    #[cfg(target_os = "linux")]
    if unsafe { libc::geteuid() } != 0 {
        let exe = std::env::current_exe().expect("cannot get executable path");
        let args: Vec<String> = {
            let mut raw = std::env::args().skip(1).peekable();
            let mut out = Vec::new();
            while let Some(a) = raw.next() {
                if a == "--parent-pid" {
                    // Skip the flag and its PID value
                    raw.next();
                } else {
                    out.push(a);
                }
            }
            out
        };

        // pkexec strips environment variables for security, including the
        // display-related ones GTK needs. Pass them explicitly via
        //   pkexec env DISPLAY=... XAUTHORITY=... WAYLAND_DISPLAY=... <exe>
        let display = std::env::var("DISPLAY").unwrap_or_default();
        let xauthority = std::env::var("XAUTHORITY").unwrap_or_default();
        let wayland = std::env::var("WAYLAND_DISPLAY").unwrap_or_default();
        let xdg_runtime = std::env::var("XDG_RUNTIME_DIR").unwrap_or_default();
        let home = std::env::var("HOME").unwrap_or_default();
        let xdg_data_dirs = std::env::var("XDG_DATA_DIRS").unwrap_or_default();
        let dbus_session = std::env::var("DBUS_SESSION_BUS_ADDRESS").unwrap_or_default();
        let original_user = std::env::var("USER").unwrap_or_default();

        // Query user's current GTK theme to preserve desktop environment styles
        let gtk_theme = std::process::Command::new("gsettings")
            .args(["get", "org.gnome.desktop.interface", "gtk-theme"])
            .output()
            .ok()
            .and_then(|output| {
                if output.status.success() {
                    let theme = String::from_utf8_lossy(&output.stdout)
                        .trim()
                        .trim_matches('\'')
                        .to_string();
                    if !theme.is_empty() {
                        return Some(theme);
                    }
                }
                None
            });

        let mut cmd = std::process::Command::new("pkexec");
        cmd.arg("env")
            .arg(format!("DISPLAY={display}"))
            .arg(format!("XAUTHORITY={xauthority}"))
            .arg(format!("WAYLAND_DISPLAY={wayland}"))
            .arg(format!("XDG_RUNTIME_DIR={xdg_runtime}"))
            .arg(format!("HOME={home}"))
            .arg(format!("XDG_DATA_DIRS={xdg_data_dirs}"))
            .arg(format!("DBUS_SESSION_BUS_ADDRESS={dbus_session}"))
            .arg(format!("ORIGINAL_USER={original_user}"));

        if let Some(theme) = gtk_theme {
            cmd.arg(format!("GTK_THEME={theme}"));
        }

        // Pass our PID so the elevated child can exit when we (the launcher) die
        let status = cmd
            .arg(&exe)
            .arg("--parent-pid")
            .arg(launcher_pid.to_string())
            .args(&args)
            .status();
        let code = match status {
            Ok(s) => s.code().unwrap_or(1),
            Err(e) => {
                eprintln!("pkexec failed to launch: {e}");
                1
            }
        };
        std::process::exit(code);
    }

    #[cfg(target_os = "macos")]
    if unsafe { libc::geteuid() } != 0 {
        let exe = std::env::current_exe()
            .expect("cannot get executable path")
            .to_string_lossy()
            .to_string();
        let args: Vec<String> = {
            let mut raw = std::env::args().skip(1).peekable();
            let mut out = Vec::new();
            while let Some(a) = raw.next() {
                if a == "--parent-pid" {
                    raw.next();
                } else {
                    out.push(a);
                }
            }
            out
        };

        // Build a single-quoted sh -c argument so that special characters in
        // the exe path or arguments cannot break out of the shell context.
        let sq = |s: &str| format!("'{}'", s.replace('\'', "'\\''"));
        let mut parts = vec![sq(&exe), sq(&format!("--parent-pid {launcher_pid}"))];
        for a in &args {
            parts.push(sq(a));
        }
        let shell_cmd = format!("sh -c {}", sq(&parts.join(" ")));

        // The shell_cmd will be embedded inside a double-quoted AppleScript string.
        // We must escape any backslashes or double-quotes so they don't break the
        // outer AppleScript layer.
        let apple_script_cmd = shell_cmd.replace('\\', "\\\\").replace('"', "\\\"");

        let result = std::process::Command::new("osascript")
            .args([
                "-e",
                &format!(
                    "do shell script \"{}\" with administrator privileges",
                    apple_script_cmd
                ),
            ])
            .status();
        let code = match result {
            Ok(s) => s.code().unwrap_or(1),
            Err(e) => {
                eprintln!("osascript relaunch failed: {e}");
                1
            }
        };
        std::process::exit(code);
    }
    // ---- End privilege elevation ----

    // Watchdog: if we were launched with --parent-pid, watch that process.
    // When tauri-dev kills the unprivileged launcher on hot-reload, we exit too
    // so only one elevated instance is ever alive at a time.
    #[cfg(unix)]
    {
        let raw_args: Vec<String> = std::env::args().collect();
        if let Some(pos) = raw_args.iter().position(|a| a == "--parent-pid") {
            if let Some(pid_str) = raw_args.get(pos + 1) {
                if let Ok(parent_pid) = pid_str.parse::<libc::pid_t>() {
                    std::thread::spawn(move || loop {
                        std::thread::sleep(std::time::Duration::from_millis(500));
                        // kill(pid, 0) just checks if the process exists
                        if unsafe { libc::kill(parent_pid, 0) } != 0 {
                            std::process::exit(0);
                        }
                    });
                }
            }
        }
    }

    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.unminimize();
                let _ = window.set_focus();
            }
        }))
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            is_root,
            get_platform,
            run_install,
            run_enroll,
            run_netbird_up,
            check_components,
            save_logs,
            pick_velociraptor_config
        ])
        .setup(|app| {
            let show_item = MenuItem::with_id(app, "show", "Show Installer", true, None::<&str>)?;
            let quit_item = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show_item, &quit_item])?;

            if let Some(window) = app.get_webview_window("main") {
                #[cfg(unix)]
                if let Some(icon) = app.default_window_icon().cloned() {
                    let _ = window.set_icon(icon);
                }
            }

            if let Some(icon) = app.default_window_icon().cloned() {
                TrayIconBuilder::new()
                    .icon(icon)
                    .tooltip("Wazuh Agent Installer")
                    .menu(&menu)
                    .show_menu_on_left_click(false)
                    .on_menu_event(|app, event| match event.id.as_ref() {
                        "show" => {
                            if let Some(window) = app.get_webview_window("main") {
                                let _ = window.show();
                                let _ = window.set_focus();
                            }
                        }
                        "quit" => {
                            app.exit(0);
                        }
                        _ => {}
                    })
                    .on_tray_icon_event(|tray, event| {
                        if let TrayIconEvent::Click {
                            button: MouseButton::Left,
                            button_state: MouseButtonState::Up,
                            ..
                        } = event
                        {
                            let app = tray.app_handle();
                            if let Some(window) = app.get_webview_window("main") {
                                if window.is_visible().unwrap_or(false) {
                                    let _ = window.hide();
                                } else {
                                    let _ = window.show();
                                    let _ = window.set_focus();
                                }
                            }
                        }
                    })
                    .build(app)?;
            }

            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
