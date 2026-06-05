use serde::{Deserialize, Serialize};
use std::env;
use std::process::Stdio;
use std::sync::Mutex;
use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    AppHandle, Emitter, Manager, State,
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;

// ---- State ----

pub struct AppState {
    pub sudo_password: Mutex<Option<String>>,
}

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
    pub log_level: String,
    pub ids_engine: String,
    pub suricata_mode: String,
    pub install_trivy: bool,
    pub oauth_issuer: String,
    pub cert_endpoint: String,
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
        // On Windows we rely on the OS elevation prompt during command execution
        true
    }
}

#[tauri::command]
async fn verify_sudo(password: String, state: State<'_, AppState>) -> Result<bool, String> {
    #[cfg(unix)]
    {
        let mut child = Command::new("sudo")
            .arg("-S")
            .arg("-k")
            .arg("-p")
            .arg("")
            .arg("id")
            .arg("-u")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("Failed to spawn sudo: {}", e))?;

        if let Some(mut stdin) = child.stdin.take() {
            let pwd = format!("{}\n", password);
            let _ = stdin.write_all(pwd.as_bytes()).await;
        }

        let output = child.wait_with_output().await.map_err(|e| e.to_string())?;

        if output.status.success() {
            let mut stored_pw = state.sudo_password.lock().unwrap();
            *stored_pw = Some(password);
            Ok(true)
        } else {
            Ok(false)
        }
    }
    #[cfg(windows)]
    {
        Ok(true)
    }
}

#[tauri::command]
async fn run_install(
    config: InstallConfig,
    password: Option<String>,
    state: State<'_, AppState>,
    app: AppHandle,
) -> Result<InstallResult, String> {
    if let Some(pw) = password {
        let mut stored = state.sudo_password.lock().unwrap();
        *stored = Some(pw);
    }

    let pw_opt = {
        let stored = state.sudo_password.lock().unwrap();
        stored.clone()
    };

    let resolved_path = resolve_script(&app)?;

    let (cmd_str, args, use_sudo) = if cfg!(target_os = "windows") {
        (
            "powershell",
            vec![
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                &resolved_path as &str,
            ],
            false,
        )
    } else {
        ("bash", vec![&resolved_path as &str], true)
    };

    let mut command = if use_sudo {
        let mut c = Command::new("sudo");
        c.arg("-S").arg("-p").arg("").arg(cmd_str).args(&args);
        c
    } else {
        let mut c = Command::new(cmd_str);
        c.args(&args);
        c
    };

    command
        .env("WAZUH_MANAGER", &config.wazuh_manager)
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
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = command.spawn().map_err(|e| e.to_string())?;

    if use_sudo {
        if let Some(mut stdin) = child.stdin.take() {
            if let Some(pw) = pw_opt {
                let _ = stdin.write_all(format!("{}\n", pw).as_bytes()).await;
            }
        }
    }

    let stdout = child.stdout.take().expect("Failed to capture stdout");
    let stderr = child.stderr.take().expect("Failed to capture stderr");

    let app_clone1 = app.clone();
    tokio::spawn(async move {
        let mut reader = BufReader::new(stdout).lines();
        while let Ok(Some(line)) = reader.next_line().await {
            let level = classify_line(&line);
            let _ = app_clone1.emit(
                "install-log",
                LogLine {
                    line,
                    level: level.into(),
                },
            );
        }
    });

    let app_clone2 = app.clone();
    tokio::spawn(async move {
        let mut reader = BufReader::new(stderr).lines();
        while let Ok(Some(line)) = reader.next_line().await {
            if line.contains("Password:") || line.trim().is_empty() {
                continue;
            }
            let level = classify_line(&line);
            let _ = app_clone2.emit(
                "install-log",
                LogLine {
                    line,
                    level: level.into(),
                },
            );
        }
    });

    let status = child.wait().await.map_err(|e| e.to_string())?;

    Ok(InstallResult {
        success: status.success(),
        exit_code: status.code().unwrap_or(-1),
        message: if status.success() {
            "Installation complete".into()
        } else {
            "Installation failed".into()
        },
    })
}

#[tauri::command]
async fn run_enroll(
    issuer: String,
    endpoint: String,
    overwrite: bool,
    password: Option<String>,
    state: State<'_, AppState>,
    app: AppHandle,
) -> Result<InstallResult, String> {
    if let Some(pw) = password {
        let mut stored = state.sudo_password.lock().unwrap();
        *stored = Some(pw);
    }

    let pw_opt = {
        let stored = state.sudo_password.lock().unwrap();
        stored.clone()
    };

    #[cfg(unix)]
    let (cmd, args, use_sudo) = {
        let mut args = vec![
            "o-auth2".to_string(),
            "--issuer".to_string(),
            issuer,
            "--endpoint".to_string(),
            endpoint,
        ];
        if overwrite {
            args.push("--overwrite".to_string());
        }
        let exe = if cfg!(target_os = "macos") {
            "/Library/Ossec/bin/wazuh-cert-oauth2-client"
        } else {
            "/var/ossec/bin/wazuh-cert-oauth2-client"
        };
        (exe, args, true)
    };

    #[cfg(windows)]
    let (cmd, args, use_sudo) = {
        let mut args = vec![
            "o-auth2".to_string(),
            "--issuer".to_string(),
            issuer,
            "--endpoint".to_string(),
            endpoint,
        ];
        if overwrite {
            args.push("--overwrite".to_string());
        }
        (
            "C:\\Program Files (x86)\\ossec-agent\\wazuh-cert-oauth2-client.exe",
            args,
            false,
        )
    };

    let mut command = if use_sudo {
        let mut c = Command::new("sudo");
        c.arg("-S").arg("-p").arg("").arg(cmd).args(&args);
        c
    } else {
        let mut c = Command::new(cmd);
        c.args(&args);
        c
    };

    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = command.spawn().map_err(|e| e.to_string())?;

    if use_sudo {
        if let Some(mut stdin) = child.stdin.take() {
            if let Some(pw) = pw_opt {
                let _ = stdin.write_all(format!("{}\n", pw).as_bytes()).await;
            }
        }
    }

    let stdout = child.stdout.take().expect("Failed to capture stdout");
    let stderr = child.stderr.take().expect("Failed to capture stderr");

    let app_clone1 = app.clone();
    tokio::spawn(async move {
        let mut reader = BufReader::new(stdout).lines();
        while let Ok(Some(line)) = reader.next_line().await {
            let level = classify_line(&line);
            let _ = app_clone1.emit(
                "enroll-log",
                LogLine {
                    line,
                    level: level.into(),
                },
            );
        }
    });

    let app_clone2 = app.clone();
    tokio::spawn(async move {
        let mut reader = BufReader::new(stderr).lines();
        while let Ok(Some(line)) = reader.next_line().await {
            if line.contains("Password:") || line.trim().is_empty() {
                continue;
            }
            let level = classify_line(&line);
            let _ = app_clone2.emit(
                "enroll-log",
                LogLine {
                    line,
                    level: level.into(),
                },
            );
            // had_error_flag is removed, we don't use it anymore
        }
    });

    let status = child.wait().await.map_err(|e| e.to_string())?;

    Ok(InstallResult {
        success: status.success(),
        exit_code: status.code().unwrap_or(-1),
        message: if status.success() {
            "Enrollment complete".into()
        } else {
            "Enrollment failed".into()
        },
    })
}

#[tauri::command]
async fn check_components(state: State<'_, AppState>) -> Result<Vec<ComponentStatus>, String> {
    let pw_opt = {
        let stored = state.sudo_password.lock().unwrap();
        stored.clone()
    };

    let ossec_path = if cfg!(windows) {
        r"C:\Program Files (x86)\ossec-agent"
    } else if cfg!(target_os = "macos") {
        "/Library/Ossec"
    } else {
        "/var/ossec"
    };

    let components = vec![
        (
            "Wazuh Agent".to_string(),
            format!("{}/bin/wazuh-agentd", ossec_path),
        ),
        (
            "OAuth2 Client".to_string(),
            format!("{}/bin/wazuh-cert-oauth2-client", ossec_path),
        ),
        (
            "Agent Status Monitor".to_string(),
            if cfg!(target_os = "macos") {
                "/usr/local/bin/wazuh-agent-status".to_string()
            } else {
                format!("{}/bin/wazuh-agent-status", ossec_path)
            },
        ),
        ("YARA".to_string(), "/usr/local/bin/yara".to_string()),
        (
            "Suricata".to_string(),
            if cfg!(target_os = "macos") {
                "/opt/homebrew/bin/suricata".to_string()
            } else {
                "/usr/bin/suricata".to_string()
            },
        ),
        ("Trivy".to_string(), "/usr/local/bin/trivy".to_string()),
        (
            "USB DLP Scripts".to_string(),
            format!("{}/active-response/bin/disable-usb-storage.sh", ossec_path),
        ),
    ];

    let mut results = Vec::new();

    for (name, path) in components {
        #[cfg(unix)]
        let installed = {
            if let Some(ref pw) = pw_opt {
                let mut cmd = Command::new("sudo");
                cmd.arg("-S")
                    .arg("-p")
                    .arg("")
                    .arg("test")
                    .arg("-f")
                    .arg(&path)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null());
                if let Ok(mut child) = cmd.spawn() {
                    if let Some(mut stdin) = child.stdin.take() {
                        let _ = stdin.write_all(format!("{}\n", pw).as_bytes()).await;
                    }
                    if let Ok(status) = child.wait().await {
                        status.success()
                    } else {
                        false
                    }
                } else {
                    false
                }
            } else {
                std::path::Path::new(&path).exists()
            }
        };

        #[cfg(windows)]
        let installed = false; // Windows paths would be different, skipping for now

        results.push(ComponentStatus {
            name,
            installed,
            version: None, // Can implement version extraction via commands later
            path,
        });
    }

    Ok(results)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let app_state = AppState {
        sudo_password: Mutex::new(None),
    };

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_opener::init())
        .manage(app_state)
        .invoke_handler(tauri::generate_handler![
            get_platform,
            is_root,
            verify_sudo,
            run_install,
            run_enroll,
            check_components
        ])
        .setup(|app| {
            let show_item = MenuItem::with_id(app, "show", "Show Installer", true, None::<&str>)?;
            let quit_item = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show_item, &quit_item])?;

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
