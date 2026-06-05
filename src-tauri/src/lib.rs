use serde::{Deserialize, Serialize};
use std::process::Stdio;
use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    AppHandle, Emitter, Manager,
};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{ChildStdin, Command};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LogLine {
    pub line: String,
    pub level: String, // "info" | "error" | "success"
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct InstallConfig {
    pub wazuh_manager: String,
    pub wazuh_agent_version: String,
    pub wazuh_agent_name: String,
    pub ids_engine: String,    // "suricata" | "snort"
    pub suricata_mode: String, // "ids" | "ips"
    pub install_trivy: bool,
    pub log_level: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct InstallResult {
    pub success: bool,
    pub exit_code: i32,
    pub message: String,
}

fn classify_line(line: &str) -> &'static str {
    let l = line.to_lowercase();
    if l.contains("[error]") || l.contains("failed") || l.contains("error:") {
        "error"
    } else if l.contains("[success]") || l.contains("successfully") || l.contains("completed") {
        "success"
    } else {
        "info"
    }
}

/// Resolve the bundled setup-agent.sh path and return it as a String.
/// When installed from a .deb the script is already executable.
/// When running in dev mode we copy to /tmp first to ensure it's writable.
fn resolve_script(app: &AppHandle) -> Result<String, String> {
    let resource_path = app
        .path()
        .resolve("setup-agent.sh", tauri::path::BaseDirectory::Resource)
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
        return tmp_path
            .to_str()
            .map(|s| s.to_string())
            .ok_or_else(|| "Script path contains invalid UTF-8".to_string());
    }

    #[cfg(not(unix))]
    resource_path
        .to_str()
        .map(|s| s.to_string())
        .ok_or_else(|| "Script path contains invalid UTF-8".to_string())
}

#[tauri::command]
async fn run_install(
    app: AppHandle,
    config: InstallConfig,
    script_path: Option<String>,
) -> Result<InstallResult, String> {
    // Resolve script: prefer caller-supplied path, fall back to bundled resource
    let resolved_path = match script_path {
        Some(ref p) if !p.is_empty() => p.clone(),
        _ => resolve_script(&app)?,
    };

    // Build CLI args from config
    let mut args: Vec<String> = vec![];

    if config.ids_engine == "suricata" {
        args.push("-s".to_string());
        let mode = if config.suricata_mode.is_empty() {
            "ids".to_string()
        } else {
            config.suricata_mode.clone()
        };
        args.push(mode);
    } else if config.ids_engine == "snort" {
        args.push("-n".to_string());
    }

    if config.install_trivy {
        args.push("-t".to_string());
    }

    // On Linux/macOS use pkexec for a GUI privilege prompt.
    // On Windows, run bash directly (WSL or Git Bash) — the script handles elevation internally.
    #[cfg(unix)]
    let mut cmd = {
        let mut c = Command::new("pkexec");
        c.arg("env")
            .arg(format!("WAZUH_MANAGER={}", &config.wazuh_manager))
            .arg(format!("WAZUH_AGENT_VERSION={}", &config.wazuh_agent_version))
            .arg(format!("WAZUH_AGENT_NAME={}", &config.wazuh_agent_name))
            .arg(format!("LOG_LEVEL={}", &config.log_level))
            .arg("bash")
            .arg(&resolved_path)
            .args(&args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        c
    };

    #[cfg(windows)]
    let mut cmd = {
        let mut c = Command::new("bash");
        c.arg(&resolved_path)
            .args(&args)
            .env("WAZUH_MANAGER", &config.wazuh_manager)
            .env("WAZUH_AGENT_VERSION", &config.wazuh_agent_version)
            .env("WAZUH_AGENT_NAME", &config.wazuh_agent_name)
            .env("LOG_LEVEL", &config.log_level)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        c
    };

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("Failed to spawn process: {}", e))?;

    // Stream stdout
    let stdout = child.stdout.take().expect("Failed to capture stdout");
    let stderr = child.stderr.take().expect("Failed to capture stderr");

    let app_stdout = app.clone();
    let stdout_task = tokio::spawn(async move {
        let reader = BufReader::new(stdout);
        let mut lines = reader.lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let level = classify_line(&line);
            let _ = app_stdout.emit(
                "install-log",
                LogLine {
                    line,
                    level: level.to_string(),
                },
            );
        }
    });

    let app_stderr = app.clone();
    let stderr_task = tokio::spawn(async move {
        let reader = BufReader::new(stderr);
        let mut lines = reader.lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let _ = app_stderr.emit(
                "install-log",
                LogLine {
                    line,
                    level: "error".to_string(),
                },
            );
        }
    });

    let status = child
        .wait()
        .await
        .map_err(|e| format!("Failed to wait for process: {}", e))?;

    let _ = tokio::join!(stdout_task, stderr_task);

    let exit_code = status.code().unwrap_or(-1);
    let success = status.success();

    let message = if success {
        "Wazuh Agent installed successfully!".to_string()
    } else {
        format!("Installation failed with exit code {}", exit_code)
    };

    let _ = app.emit(
        "install-done",
        InstallResult {
            success,
            exit_code,
            message: message.clone(),
        },
    );

    Ok(InstallResult {
        success,
        exit_code,
        message,
    })
}

use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::io::AsyncWriteExt;

// Shared stdin handle for the enrollment process
type EnrollStdin = Arc<Mutex<Option<ChildStdin>>>;

#[tauri::command]
async fn run_enroll(app: AppHandle, issuer: String, endpoint: String, overwrite: bool) -> Result<InstallResult, String> {
    // Use sudo for privilege elevation (allows OAuth2 callback unlike pkexec).
    #[cfg(unix)]
    let mut cmd = {
        let mut c = Command::new("sudo");
        c.arg("/var/ossec/bin/wazuh-cert-oauth2-client")
            .arg("o-auth2")
            .arg("--issuer")
            .arg(&issuer)
            .arg("--endpoint")
            .arg(&endpoint)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        if overwrite {
            c.arg("--overwrite");
        }
        c
    };

    #[cfg(windows)]
    let mut cmd = {
        let mut c = Command::new("/var/ossec/bin/wazuh-cert-oauth2-client");
        c.arg("o-auth2")
            .arg("--issuer")
            .arg(&issuer)
            .arg("--endpoint")
            .arg(&endpoint)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        if overwrite {
            c.arg("--overwrite");
        }
        c
    };

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("Failed to start enrollment: {}", e))?;

    // Store stdin in app state so JS can send the OAuth2 code to it
    let stdin = child.stdin.take();
    let stdin_state: EnrollStdin = app.state::<EnrollStdin>().inner().clone();
    {
        let mut guard = stdin_state.lock().await;
        *guard = stdin;
    }

    let stdout = child.stdout.take().expect("Failed to capture stdout");
    let stderr = child.stderr.take().expect("Failed to capture stderr");

    // Track whether an error line was seen in the output
    let had_error_flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

    let app_stdout = app.clone();
    let stdout_task = tokio::spawn(async move {
        let reader = BufReader::new(stdout);
        let mut lines = reader.lines();
        while let Ok(Some(line)) = lines.next_line().await {
            // Detect when the client has printed the URL and is waiting for the code
            let is_code_prompt = line.contains("Please open this URL in your browser")
                || line.contains("Please copy this code")
                || line.contains("paste it into your application")
                || line.contains("Enter the code");
            let level = if is_code_prompt { "success" } else { classify_line(&line) };
            let _ = app_stdout.emit("enroll-log", LogLine { line, level: level.to_string() });
            if is_code_prompt {
                let _ = app_stdout.emit("enroll-needs-code", true);
            }
        }
    });

    let app_stderr = app.clone();
    let had_error_flag_clone = had_error_flag.clone();
    let stderr_task = tokio::spawn(async move {
        let reader = BufReader::new(stderr);
        let mut lines = reader.lines();
        while let Ok(Some(line)) = lines.next_line().await {
            // Track error lines
            if line.to_lowercase().contains("error") || line.contains("invalid_grant") {
                had_error_flag_clone.store(true, std::sync::atomic::Ordering::SeqCst);
            }
            // Also detect code prompt on stderr
            let is_code_prompt = line.contains("Please open this URL in your browser")
                || line.contains("Please copy this code")
                || line.contains("paste it into your application")
                || line.contains("Enter the code");
            let level = if is_code_prompt { "success" } else { "error" };
            let _ = app_stderr.emit("enroll-log", LogLine { line, level: level.to_string() });
            if is_code_prompt {
                let _ = app_stderr.emit("enroll-needs-code", true);
            }
        }
    });

    let status = child
        .wait()
        .await
        .map_err(|e| format!("Enrollment process error: {}", e))?;

    let _ = tokio::join!(stdout_task, stderr_task);

    // Clear stdin state
    {
        let mut guard = stdin_state.lock().await;
        *guard = None;
    }

    let exit_code = status.code().unwrap_or(-1);
    // pkexec bash -c can return 0 even if inner command failed.
    // Check error log state via a shared flag instead.
    let had_error = had_error_flag.load(std::sync::atomic::Ordering::SeqCst);
    let success = status.success() && !had_error;
    let message = if success {
        "Agent enrolled successfully!".to_string()
    } else {
        format!("Enrollment failed — check the log above for details")
    };

    Ok(InstallResult { success, exit_code, message })
}

#[tauri::command]
async fn send_enroll_input(app: AppHandle, code: String) -> Result<(), String> {
    let stdin_state: EnrollStdin = app.state::<EnrollStdin>().inner().clone();
    let mut guard = stdin_state.lock().await;
    if let Some(ref mut stdin) = *guard {
        let input = format!("{}\n", code.trim());
        stdin.write_all(input.as_bytes()).await
            .map_err(|e| format!("Failed to send code: {}", e))?;
        stdin.flush().await
            .map_err(|e| format!("Failed to flush stdin: {}", e))?;
    } else {
        return Err("No active enrollment process".to_string());
    }
    Ok(())
}

#[tauri::command]
async fn hide_window(app: AppHandle) -> Result<(), String> {
    if let Some(window) = app.get_webview_window("main") {
        window.hide().map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[tauri::command]
fn validate_config(config: InstallConfig) -> Result<(), String> {
    if config.wazuh_manager.is_empty() {
        return Err("Wazuh Manager address is required".to_string());
    }
    if config.wazuh_agent_name.is_empty() {
        return Err("Agent name is required".to_string());
    }
    if config.wazuh_agent_version.is_empty() {
        return Err("Agent version is required".to_string());
    }
    if config.ids_engine != "suricata" && config.ids_engine != "snort" {
        return Err("IDS engine must be 'suricata' or 'snort'".to_string());
    }
    if config.ids_engine == "suricata"
        && config.suricata_mode != "ids"
        && config.suricata_mode != "ips"
    {
        return Err("Suricata mode must be 'ids' or 'ips'".to_string());
    }
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_shell::init())
        .manage(EnrollStdin::new(Mutex::new(None)))
        .invoke_handler(tauri::generate_handler![run_install, validate_config, hide_window, run_enroll, send_enroll_input])
        .setup(|app| {
            // ---- Build tray menu ----
            let show_item = MenuItem::with_id(app, "show", "Show Installer", true, None::<&str>)?;
            let quit_item = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show_item, &quit_item])?;

            // ---- Load tray icon — use the app's default window icon ----
            let icon = app
                .default_window_icon()
                .cloned()
                .expect("No default window icon found");

            // ---- Create the tray icon ----
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
                    // Left-click toggles the window
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

            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
