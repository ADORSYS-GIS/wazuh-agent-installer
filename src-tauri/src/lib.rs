use serde::{Deserialize, Serialize};
use std::env;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    AppHandle, Emitter, Manager, State,
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;

#[cfg(windows)]
use std::os::windows::process::CommandExt;

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

async fn get_component_version(
    name: &str,
    path: &str,
    use_sudo: bool,
    pw_opt: Option<&String>,
) -> Option<String> {
    if name == "USB DLP Scripts" {
        return Some("Installed".to_string());
    }

    let mut args = vec![];
    let cmd_target;

    match name {
        "Wazuh Agent" => {
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
        }
        "Suricata" => {
            cmd_target = path.to_string();
            args.push("-V".to_string());
        }
        _ => {
            cmd_target = path.to_string();
            args.push("--version".to_string());
        }
    }

    let mut cmd = if use_sudo {
        #[cfg(unix)]
        {
            let mut c = create_command("sudo");
            c.arg("-S").arg("-p").arg("").arg(&cmd_target).args(&args);
            c
        }
        #[cfg(windows)]
        {
            let mut c = create_command(&cmd_target);
            c.args(&args);
            c
        }
    } else {
        let mut c = create_command(&cmd_target);
        c.args(&args);
        c
    };

    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

    if let Ok(mut child) = cmd.spawn() {
        if use_sudo {
            #[cfg(unix)]
            if let Some(mut stdin) = child.stdin.take() {
                if let Some(pw) = pw_opt {
                    let _ = stdin.write_all(format!("{}\n", pw).as_bytes()).await;
                }
            }
        }

        if let Ok(output) = child.wait_with_output().await {
            let out_str = String::from_utf8_lossy(&output.stdout).to_string()
                + String::from_utf8_lossy(&output.stderr).as_ref();

            match name {
                "YARA" => {
                    return out_str.lines().next().map(|s| s.trim().to_string());
                }
                "Suricata" => {
                    if let Some(idx) = out_str.find("version ") {
                        let rest = &out_str[idx + 8..];
                        return Some(rest.split_whitespace().next().unwrap_or("").to_string());
                    }
                }
                "Trivy" => {
                    if let Some(idx) = out_str.find("Version: ") {
                        let rest = &out_str[idx + 9..];
                        return Some(rest.split_whitespace().next().unwrap_or("").to_string());
                    }
                }
                "Wazuh Agent" => {
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
                }
                _ => {
                    for line in out_str.lines() {
                        let trimmed = line.trim();
                        if trimmed.chars().any(|c| c.is_ascii_digit()) {
                            let parts: Vec<&str> = trimmed.split_whitespace().collect();
                            for p in parts {
                                if p.chars().any(|c| c.is_ascii_digit()) && p.contains('.') {
                                    return Some(p.to_string());
                                }
                            }
                            return Some(trimmed.to_string());
                        }
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

// ---- Shared helpers ----

/// Store the provided password (if any) into state, then take it out immediately.
/// Taking the password out minimizes how long the plaintext remains in process memory.
fn take_password(password: Option<String>, state: &State<'_, AppState>) -> Option<String> {
    let mut stored = state.sudo_password.lock().unwrap();
    if let Some(pw) = password {
        *stored = Some(pw);
    }
    stored.take()
}

/// Inject a PATH that includes common Homebrew locations so macOS GUI-launched
/// processes can find user-installed binaries.
fn inject_path(command: &mut Command) {
    let current_path =
        std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin:/usr/sbin:/sbin".to_string());
    command.env("PATH", format!("{}:{}", get_macos_gui_path_prefix(), current_path));
}

/// Get the PATH prefix for macOS GUI-launched processes.
/// Returns "/opt/homebrew/bin:/usr/local/bin:" to be prepended to the current PATH.
fn get_macos_gui_path_prefix() -> String {
    "/opt/homebrew/bin:/usr/local/bin:".to_string()
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
            let _ = tauri_plugin_opener::open_url(url, None::<&str>);
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
        let _ = tauri_plugin_opener::open_url(url, None::<&str>);
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
/// `cfg.event_name`, optionally write the sudo password to stdin, and return
/// the exit result.
async fn run_streamed_command(
    app: AppHandle,
    mut command: Command,
    use_sudo: bool,
    pw_opt: Option<String>,
    cfg: StreamConfig,
) -> Result<InstallResult, String> {
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = command.spawn().map_err(|e| match cfg.spawn_err {
        Some(msg) => format!("{}: {}", msg, e),
        None => e.to_string(),
    })?;

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
    let event_name = cfg.event_name;
    let intercept_stdout = cfg.intercept_browser_url;
    let url_state = Arc::new(Mutex::new(false));
    let url_state_stdout = Arc::clone(&url_state);
    tokio::spawn(async move {
        let mut reader = BufReader::new(stdout).lines();
        while let Ok(Some(line)) = reader.next_line().await {
            if intercept_stdout {
                let mut expect_url_next = url_state_stdout.lock().unwrap();
                try_open_browser_url(&line, &mut expect_url_next);
            }
            let level = classify_line(&line);
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
    tokio::spawn(async move {
        let mut reader = BufReader::new(stderr).lines();
        while let Ok(Some(line)) = reader.next_line().await {
            if line.contains("Password:") || line.trim().is_empty() {
                continue;
            }
            if intercept_stderr {
                let mut expect_url_next = url_state_stderr.lock().unwrap();
                try_open_browser_url(&line, &mut expect_url_next);
            }
            let level = classify_line(&line);
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

    Ok(InstallResult {
        success: status.success(),
        exit_code: status.code().unwrap_or(-1),
        message: if status.success() {
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

#[allow(unused_variables)]
#[tauri::command]
async fn verify_sudo(password: String, state: State<'_, AppState>) -> Result<bool, String> {
    #[cfg(unix)]
    {
        let mut child = create_command("sudo")
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
    let pw_opt = take_password(password, &state);

    let resolved_path = resolve_script(&app)?;

    let (cmd_str, args, use_sudo) = if cfg!(target_os = "windows") {
        let mut script_args = vec![
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            &resolved_path as &str,
        ];
        if config.install_netbird {
            script_args.push("-InstallNetBird");
        }
        if config.install_velociraptor {
            script_args.push("-InstallVelociraptor");
        }
        if !config.velociraptor_config.is_empty() {
            script_args.push("-VelociraptorConfig");
            script_args.push(&config.velociraptor_config);
        }
        ("powershell", script_args, false)
    } else {
        let mut script_args = vec![&resolved_path as &str];
        if config.install_netbird {
            script_args.push("-b");
        }
        if config.install_velociraptor {
            script_args.push("-v");
        }
        if !config.velociraptor_config.is_empty() {
            script_args.push("-c");
            script_args.push(&config.velociraptor_config);
        }
        ("bash", script_args, true)
    };

    let command = if use_sudo {
        let mut c = create_command("sudo");
        c.arg("-S").arg("-p").arg("");

        // Pass environment variables via `env` so `sudo` doesn't strip them
        c.arg("env");

        // Inject PATH so macOS GUI apps can find Homebrew and other user binaries
        let current_path =
            std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin:/usr/sbin:/sbin".to_string());

        #[cfg(target_os = "macos")]
        c.arg(format!("PATH={}{}", get_macos_gui_path_prefix(), current_path));

        #[cfg(not(target_os = "macos"))]
        c.arg(format!("PATH={}", current_path));

        c.arg(format!("WAZUH_MANAGER={}", config.wazuh_manager));
        c.arg(format!("WAZUH_AGENT_NAME={}", config.wazuh_agent_name));
        c.arg(format!("IDS_ENGINE={}", config.ids_engine));
        c.arg(format!("SURICATA_MODE={}", config.suricata_mode));
        c.arg(format!(
            "INSTALL_TRIVY={}",
            if config.install_trivy {
                "true"
            } else {
                "false"
            }
        ));
        c.arg(format!(
            "WAZUH_AGENT_REPO_REF={}",
            std::env::var("WAZUH_AGENT_REPO_REF").unwrap_or_else(|_| "develop".to_string())
        ));

        c.arg(cmd_str).args(&args);
        c
    } else {
        // Windows: no sudo, so set env vars directly on the Command.
        let mut c = create_command(cmd_str);
        c.args(&args);
        inject_path(&mut c);
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
        c
    };

    run_streamed_command(
        app,
        command,
        use_sudo,
        pw_opt,
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
    password: Option<String>,
    state: State<'_, AppState>,
    app: AppHandle,
) -> Result<InstallResult, String> {
    let pw_opt = take_password(password, &state);

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
        // The binary is installed with root-only permissions, so we need sudo on all Unix
        // platforms. On macOS, sudo kills the GUI context so the binary cannot open a
        // browser. We intercept the "Opened your default browser to: <URL>" line from
        // stderr and open it ourselves from Tauri's GUI process instead.
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
        let mut c = create_command("sudo");
        c.arg("-S").arg("-p").arg("").arg(cmd).args(&args);
        c
    } else {
        let mut c = create_command(cmd);
        c.args(&args);
        c
    };

    inject_path(&mut command);

    run_streamed_command(
        app,
        command,
        use_sudo,
        pw_opt,
        StreamConfig {
            event_name: "enroll-log",
            success_msg: "Enrollment complete",
            failure_msg: "Enrollment failed",
            intercept_browser_url: true, // macOS sudo strips GUI session
            spawn_err: None,
        },
    )
    .await
}

#[tauri::command]
async fn run_netbird_up(
    setup_key: String,
    management_url: String,
    password: Option<String>,
    state: State<'_, AppState>,
    app: AppHandle,
) -> Result<InstallResult, String> {
    // Management URL defaults to the public NetBird Cloud when not provided.
    let management_url = if management_url.trim().is_empty() {
        "https://api.netbird.io:443".to_string()
    } else {
        management_url
    };

    let pw_opt = take_password(password, &state);

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

    // NetBird runs as a privileged daemon, so we need sudo on Unix. On Windows
    // the installer process is already elevated via UAC.
    // On Windows the NSIS installer places netbird.exe under
    // "C:\Program Files\Netbird\" which is not on the default PATH, so we
    // use the full path to avoid "Program not found" errors.
    #[cfg(unix)]
    let (cmd, cmd_args, use_sudo) = ("netbird", args, true);

    #[cfg(windows)]
    let (cmd, cmd_args, use_sudo) = (r"C:\Program Files\Netbird\netbird.exe", args, false);

    let mut command = if use_sudo {
        let mut c = create_command("sudo");
        c.arg("-S").arg("-p").arg("").arg(cmd).args(&cmd_args);
        c
    } else {
        let mut c = create_command(cmd);
        c.args(&cmd_args);
        c
    };

    inject_path(&mut command);

    run_streamed_command(
        app,
        command,
        use_sudo,
        pw_opt,
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

/// Check if a file exists at `path` using sudo `test -f` on Unix.
#[cfg(unix)]
async fn check_installed_unix(path: &str, pw_opt: &Option<String>) -> bool {
    if let Some(ref pw) = pw_opt {
        let mut cmd = create_command("sudo");
        cmd.arg("-S")
            .arg("-p")
            .arg("")
            .arg("test")
            .arg("-f")
            .arg(path)
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
        std::path::Path::new(path).exists()
    }
}

/// Check if a component is installed on Windows.
#[cfg(windows)]
async fn check_installed_windows(path: &str, config: &InstallConfig) -> bool {
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
async fn check_components(
    password: Option<String>,
    state: State<'_, AppState>
) -> Result<Vec<ComponentStatus>, String> {
    let pw_opt = password.or_else(|| {
        let stored = state.sudo_password.lock().unwrap();
        stored.clone()
    });

    let mut results = Vec::new();

    for (name, path) in component_paths() {
        #[cfg(unix)]
        let installed = check_installed_unix(&path, &pw_opt).await;
        #[cfg(windows)]
        let installed = check_installed_windows(&path, &config).await;

        let version = if installed {
            let needs_sudo = cfg!(unix)
                && (name == "Wazuh Agent"
                    || name == "Suricata"
                    || name == "Trivy"
                    || name == "Velociraptor"
                    || path.contains("/var/ossec"));
            get_component_version(name, &path, needs_sudo, pw_opt.as_ref()).await
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
    let app_state = AppState {
        sudo_password: Mutex::new(None),
    };

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(app_state)
        .invoke_handler(tauri::generate_handler![
            is_root,
            get_platform,
            verify_sudo,
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
