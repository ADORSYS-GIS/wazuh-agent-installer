use serde::{Deserialize, Serialize};
use std::env;
use std::process::Stdio;
use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    AppHandle, Emitter, Manager,
};
use tokio::io::AsyncBufReadExt;
use tokio::process::Command;

#[cfg(windows)]
use std::os::windows::process::CommandExt;

// ---- Types ----

#[derive(Serialize, Deserialize, Clone)]
pub struct AppConfig {
    pub wazuh_manager_url: String,
    pub wazuh_oauth_issuer: String,
    pub wazuh_cert_endpoint: String,
    pub netbird_management_url: String,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            wazuh_manager_url: "manager.wazuh.adorsys.team".to_string(),
            wazuh_oauth_issuer: "https://login.wazuh.adorsys.team/realms/adorsys".to_string(),
            wazuh_cert_endpoint: "https://cert.wazuh.adorsys.team/api/register-agent".to_string(),
            netbird_management_url: "https://netbird.guard.adorsys.com".to_string(),
        }
    }
}

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
    // TODO: ids_engine is reserved for future Snort support; currently always "suricata"
    pub ids_engine: String,
    pub suricata_mode: String,
    pub install_netbird: bool,
    pub oauth_issuer: String,
    pub cert_endpoint: String,
}

// ---- Helpers ----

fn parse_yara_version(out_str: &str) -> Option<String> {
    let first_line = out_str.lines().next().unwrap_or(out_str);
    Some(first_line.trim().to_string())
}

fn parse_suricata_version(out_str: &str) -> Option<String> {
    let lower = out_str.to_lowercase();
    if let Some(idx) = lower.find("version ") {
        let rest = &out_str[idx + 8..];
        if let Some(first_word) = rest.split_whitespace().next() {
            let cleaned = first_word.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '.');
            if !cleaned.is_empty() {
                return Some(cleaned.to_string());
            }
        }
    }
    if let Some(idx) = lower.find("suricata ") {
        let rest = &out_str[idx + 9..];
        if let Some(first_word) = rest.split_whitespace().next() {
            let cleaned = first_word.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '.');
            if !cleaned.is_empty() && cleaned != "version" {
                return Some(cleaned.to_string());
            }
        }
    }
    Some(out_str.trim().to_string())
}

fn parse_wazuh_agent_version(out_str: &str) -> Option<String> {
    if let Some(idx) = out_str.find("WAZUH_VERSION=\"") {
        let rest = &out_str[idx + 15..];
        if let Some(end) = rest.find('\"') {
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
    None
}

fn parse_netbird_version(out_str: &str) -> Option<String> {
    let trimmed = out_str.trim();
    if let Some(first) = trimmed.lines().next() {
        let v = first.trim().to_string();
        if !v.is_empty() {
            return Some(v);
        }
    }
    None
}

fn parse_default_version(out_str: &str) -> Option<String> {
    for line in out_str.lines() {
        let trimmed = line.trim();
        if trimmed.chars().any(|c| c.is_ascii_digit()) {
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            for p in parts {
                let is_date = p.contains('-') && p.split('-').count() == 3;
                let is_path = p.contains('/') || p.contains('\\');
                if p.chars().any(|c| c.is_ascii_digit()) && p.contains('.') && !is_date && !is_path
                {
                    return Some(p.to_string());
                }
            }
            return Some(trimmed.to_string());
        }
    }
    None
}

fn parse_component_version(name: &str, out_str: &str) -> Option<String> {
    match name {
        "YARA" => parse_yara_version(out_str),
        "Suricata" => parse_suricata_version(out_str),
        "Wazuh Agent" => parse_wazuh_agent_version(out_str),
        "NetBird" => parse_netbird_version(out_str),
        _ => parse_default_version(out_str),
    }
}

async fn get_component_version(name: &str, path: &str) -> Option<String> {
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
    } else if name == "NetBird" {
        args.push("version".to_string());
    } else {
        args.push("--version".to_string());
    }

    let mut cmd = create_command(&cmd_target);
    cmd.args(&args);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    // Automatically terminate the process if it times out or gets dropped
    cmd.kill_on_drop(true);

    if let Ok(child) = cmd.spawn() {
        if let Ok(Ok(output)) =
            tokio::time::timeout(std::time::Duration::from_secs(2), child.wait_with_output()).await
        {
            let out_str = String::from_utf8_lossy(&output.stdout).to_string()
                + String::from_utf8_lossy(&output.stderr).as_ref();
            return parse_component_version(name, &out_str);
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
fn build_install_command(config: &InstallConfig, resolved_path: &str) -> Command {
    #[cfg(target_os = "windows")]
    let mut command = {
        let mut c = create_command("powershell");
        c.args([
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            resolved_path,
        ]);
        if config.install_netbird {
            c.arg("-InstallNetBird");
        }
        c
    };

    #[cfg(not(target_os = "windows"))]
    let mut command = {
        let mut c = create_command("bash");
        c.arg(resolved_path);
        if config.install_netbird {
            c.arg("-b");
        }
        c.env("WAZUH_MANAGER", &config.wazuh_manager)
            .env("WAZUH_AGENT_NAME", &config.wazuh_agent_name)
            .env("IDS_ENGINE", &config.ids_engine)
            .env("SURICATA_MODE", &config.suricata_mode);
        #[cfg(target_os = "macos")]
        {
            let current_path = std::env::var("PATH")
                .unwrap_or_else(|_| "/usr/bin:/bin:/usr/sbin:/sbin".to_string());
            c.env(
                "PATH",
                format!("/opt/homebrew/bin:/usr/local/bin:{current_path}"),
            );
        }
        c
    };

    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    command
}

fn spawn_log_reader<T>(
    stream: T,
    app: AppHandle,
    event_name: &'static str,
    mut process_line: impl FnMut(&str) + Send + 'static,
) where
    T: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut reader = tokio::io::BufReader::new(stream).lines();
        while let Ok(Some(line)) = reader.next_line().await {
            if line.trim().is_empty() {
                continue;
            }
            process_line(&line);
            let level = classify_line(&line);
            let _ = app.emit(
                event_name,
                LogLine {
                    line,
                    level: level.into(),
                },
            );
        }
    });
}

#[tauri::command]
async fn run_install(config: InstallConfig, app: AppHandle) -> Result<InstallResult, String> {
    let resolved_path = resolve_script(&app)?;
    let mut command = build_install_command(&config, &resolved_path);

    let mut child = command.spawn().map_err(|e| e.to_string())?;

    let stdout = child.stdout.take().expect("Failed to capture stdout");
    let stderr = child.stderr.take().expect("Failed to capture stderr");

    let (tx_done, mut rx_done) = tokio::sync::mpsc::channel(1);
    let tx_done_clone = tx_done.clone();
    spawn_log_reader(stdout, app.clone(), "install-log", move |line| {
        if line.contains("Wazuh setup has been completed successfully") {
            let _ = tx_done_clone.try_send(true);
        }
    });
    spawn_log_reader(stderr, app, "install-log", move |_| {});

    let status_future = child.wait();

    // Race between the process exiting naturally and our manual success signal
    let (success, exit_code) = tokio::select! {
        Ok(status) = status_future => {
            (status.success(), status.code().unwrap_or(-1))
        }
        Some(_) = rx_done.recv() => {
            // Give it a tiny bit of time to flush remaining logs naturally
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            (true, 0)
        }
    };

    Ok(InstallResult {
        success,
        exit_code,
        message: if success {
            "Installation complete".into()
        } else {
            "Installation failed".into()
        },
    })
}

fn open_browser(url: &str) {
    #[cfg(target_os = "linux")]
    {
        if let Ok(uid) = std::env::var("PKEXEC_UID") {
            let _ = std::process::Command::new("sudo")
                .arg("-u")
                .arg(format!("#{}", uid))
                .arg("xdg-open")
                .arg(url)
                .status();
            return;
        } else if let Ok(sudo_user) = std::env::var("SUDO_USER") {
            let _ = std::process::Command::new("sudo")
                .arg("-u")
                .arg(&sudo_user)
                .arg("xdg-open")
                .arg(url)
                .status();
            return;
        }
    }
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open")
            .arg(url)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
        return;
    }
    // Fallback to Tauri opener for Windows or standard Linux
    let _ = tauri_plugin_opener::open_url(url, None::<&str>);
}
#[tauri::command]
fn build_enroll_command(issuer: &str, endpoint: &str, overwrite: bool) -> Command {
    let mut oauth_args = vec![
        "o-auth2".to_string(),
        "--issuer".to_string(),
        issuer.to_string(),
        "--endpoint".to_string(),
        endpoint.to_string(),
    ];

    if overwrite {
        oauth_args.push("--overwrite".to_string());
        oauth_args.push("true".to_string());
    }

    #[cfg(target_os = "windows")]
    let mut command = {
        let exe = "C:\\Program Files (x86)\\ossec-agent\\wazuh-cert-oauth2-client.exe";
        let mut c = create_command(exe);
        c.args(&oauth_args);
        c
    };

    #[cfg(target_os = "linux")]
    let mut command = {
        let exe = "/var/ossec/bin/wazuh-cert-oauth2-client";
        let mut c = create_command(exe);
        c.args(&oauth_args);
        c
    };

    #[cfg(target_os = "macos")]
    let mut command = {
        let current_path =
            std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin:/usr/sbin:/sbin".to_string());
        let full_path = format!("/opt/homebrew/bin:/usr/local/bin:{current_path}");
        let mut c = create_command("/Library/Ossec/bin/wazuh-cert-oauth2-client");
        c.env("PATH", full_path);
        c.args(&oauth_args);
        c
    };

    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    command
}

fn get_enroll_line_processor(
    enrolled: std::sync::Arc<tokio::sync::Notify>,
) -> impl FnMut(&str) + Send + 'static {
    move |line: &str| {
        if let Some(url_start) = line.find("Opened your default browser to: ") {
            let url = line[url_start + "Opened your default browser to: ".len()..].trim();
            if !url.is_empty() {
                open_browser(url);
            }
        } else if line.trim().starts_with("https://") && line.contains("/realms/") {
            open_browser(line.trim());
        }
        if line.contains("] Done!") || line.trim() == "Done!" {
            enrolled.notify_one();
        }
    }
}

#[tauri::command]
async fn run_enroll(
    issuer: String,
    endpoint: String,
    overwrite: bool,
    app: AppHandle,
) -> Result<InstallResult, String> {
    let mut command = build_enroll_command(&issuer, &endpoint, overwrite);

    let mut child = command.spawn().map_err(|e| e.to_string())?;

    let stdout = child.stdout.take().expect("Failed to capture stdout");
    let stderr = child.stderr.take().expect("Failed to capture stderr");

    let enrolled = std::sync::Arc::new(tokio::sync::Notify::new());
    spawn_log_reader(
        stdout,
        app.clone(),
        "enroll-log",
        get_enroll_line_processor(enrolled.clone()),
    );
    spawn_log_reader(
        stderr,
        app,
        "enroll-log",
        get_enroll_line_processor(enrolled.clone()),
    );

    tokio::select! {
        res = child.wait() => {
            let status = res.map_err(|e| e.to_string())?;
            Ok(InstallResult {
                success: status.success(),
                exit_code: status.code().unwrap_or(-1),
                message: if status.success() {
                    "Enrollment complete".into()
                } else {
                    "Enrollment failed".into()
                },
            })
        },
        _ = enrolled.notified() => {
            Ok(InstallResult {
                success: true,
                exit_code: 0,
                message: "Enrollment complete".into(),
            })
        }
    }
}

fn build_netbird_up_command(setup_key: &str, management_url: &str) -> Command {
    let management_url = if management_url.trim().is_empty() {
        "https://api.netbird.io:443".to_string()
    } else {
        management_url.to_string()
    };

    let mut args = vec![
        "up".to_string(),
        "--management-url".to_string(),
        management_url,
    ];
    if !setup_key.trim().is_empty() {
        args.push("--setup-key".to_string());
        args.push(setup_key.to_string());
    }

    #[cfg(unix)]
    let mut cmd = {
        let mut c = create_command("netbird");
        let current_path =
            std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin:/usr/sbin:/sbin".to_string());
        c.env(
            "PATH",
            format!("/opt/homebrew/bin:/usr/local/bin:{current_path}"),
        );
        c
    };
    #[cfg(windows)]
    let mut cmd = create_command("netbird.exe");

    cmd.args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    cmd
}
fn get_netbird_line_processor(
    connected: std::sync::Arc<tokio::sync::Notify>,
) -> impl FnMut(&str) + Send + 'static {
    move |line: &str| {
        let trimmed = line.trim();
        if trimmed.starts_with("https://") && trimmed.contains("/realms/") {
            open_browser(trimmed);
        }
        if trimmed.to_lowercase().contains("connected")
            && !trimmed.to_lowercase().contains("disconnected")
        {
            connected.notify_one();
        }
    }
}

#[tauri::command]
async fn run_netbird_up(
    setup_key: String,
    management_url: String,
    app: AppHandle,
) -> Result<InstallResult, String> {
    let mut cmd = build_netbird_up_command(&setup_key, &management_url);

    let mut child = cmd.spawn().map_err(|e| e.to_string())?;

    let stdout = child.stdout.take().expect("Failed to capture stdout");
    let stderr = child.stderr.take().expect("Failed to capture stderr");

    let connected = std::sync::Arc::new(tokio::sync::Notify::new());
    spawn_log_reader(
        stdout,
        app.clone(),
        "netbird-log",
        get_netbird_line_processor(connected.clone()),
    );
    spawn_log_reader(
        stderr,
        app,
        "netbird-log",
        get_netbird_line_processor(connected.clone()),
    );

    tokio::select! {
        res = child.wait() => {
            let status = res.map_err(|e| e.to_string())?;
            Ok(InstallResult {
                success: status.success(),
                exit_code: status.code().unwrap_or(-1),
                message: if status.success() {
                    "NetBird connected successfully".into()
                } else {
                    "NetBird connection failed".into()
                },
            })
        },
        _ = connected.notified() => {
            Ok(InstallResult {
                success: true,
                exit_code: 0,
                message: "NetBird connected successfully".into(),
            })
        }
    }
}
#[cfg(unix)]
fn check_netbird_unix(path: &str) -> (bool, String) {
    if std::path::Path::new(path).exists() {
        (true, path.to_string())
    } else if std::path::Path::new("/usr/bin/netbird").exists() {
        (true, "/usr/bin/netbird".to_string())
    } else if std::path::Path::new("/usr/local/bin/netbird").exists() {
        (true, "/usr/local/bin/netbird".to_string())
    } else {
        (false, path.to_string())
    }
}

#[cfg(unix)]
fn check_suricata_unix(path: &str) -> (bool, String) {
    if std::path::Path::new(path).exists() {
        (true, path.to_string())
    } else if std::path::Path::new("/usr/bin/suricata").exists() {
        (true, "/usr/bin/suricata".to_string())
    } else if std::path::Path::new("/usr/local/bin/suricata").exists() {
        (true, "/usr/local/bin/suricata".to_string())
    } else if std::path::Path::new("/opt/homebrew/bin/suricata").exists() {
        (true, "/opt/homebrew/bin/suricata".to_string())
    } else {
        (false, path.to_string())
    }
}

#[cfg(unix)]
fn check_component_unix(name: &str, path: &str) -> (bool, String) {
    match name {
        "NetBird" => check_netbird_unix(path),
        "Suricata" => check_suricata_unix(path),
        _ => (std::path::Path::new(path).exists(), path.to_string()),
    }
}

#[cfg(windows)]
async fn check_netbird_windows(path: &str) -> (bool, String) {
    let default_p1 = r"C:\Program Files\Netbird\netbird.exe";
    let default_p2 = r"C:\Program Files (x86)\Netbird\netbird.exe";
    if std::path::Path::new(default_p1).exists() {
        (true, default_p1.to_string())
    } else if std::path::Path::new(default_p2).exists() {
        (true, default_p2.to_string())
    } else {
        let ok = create_command(path)
            .arg("--help")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .map_or(false, |s| s.success());
        (ok, path.to_string())
    }
}

#[cfg(windows)]
async fn check_suricata_windows(path: &str) -> (bool, String) {
    let p1 = r"C:\Program Files\Suricata\suricata.exe";
    let p2 = r"C:\Program Files (x86)\Suricata\suricata.exe";
    let p3 = r"C:\Suricata\suricata.exe";
    if std::path::Path::new(p1).exists() {
        (true, p1.to_string())
    } else if std::path::Path::new(p2).exists() {
        (true, p2.to_string())
    } else if std::path::Path::new(p3).exists() {
        (true, p3.to_string())
    } else {
        let ok = create_command(path)
            .arg("--help")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .map_or(false, |s| s.success());
        (ok, path.to_string())
    }
}

#[cfg(windows)]
async fn check_yara_windows(path: &str) -> (bool, String) {
    let p1 = r"C:\Program Files\YARA\yara64.exe";
    let p2 = r"C:\Program Files (x86)\YARA\yara64.exe";
    let p3 = r"C:\YARA\yara64.exe";
    if std::path::Path::new(p1).exists() {
        (true, p1.to_string())
    } else if std::path::Path::new(p2).exists() {
        (true, p2.to_string())
    } else if std::path::Path::new(p3).exists() {
        (true, p3.to_string())
    } else {
        let ok = create_command(path)
            .arg("--help")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .map_or(false, |s| s.success());
        (ok, path.to_string())
    }
}

#[cfg(windows)]
async fn check_wazuh_agent_windows(path: &str) -> (bool, String) {
    let ok = std::path::Path::new(path).exists()
        || std::path::Path::new(&path.replace("wazuh-agent.exe", "ossec-agent.exe")).exists()
        || create_command("sc")
            .args(["query", "WazuhSvc"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .map_or(false, |s| s.success());
    (ok, path.to_string())
}

#[cfg(windows)]
async fn check_component_windows(name: &str, path: &str) -> (bool, String) {
    match name {
        "NetBird" => check_netbird_windows(path).await,
        "Suricata" => check_suricata_windows(path).await,
        "YARA" => check_yara_windows(path).await,
        _ if path.ends_with("wazuh-agent.exe") => check_wazuh_agent_windows(path).await,
        _ => (std::path::Path::new(path).exists(), path.to_string()),
    }
}

#[tauri::command]
async fn check_components() -> Result<Vec<ComponentStatus>, String> {
    // Use #[cfg(...)] compile-time blocks for platform-specific paths,
    // consistent with run_enroll() and run_install().
    #[cfg(target_os = "windows")]
    let ossec_path = r"C:\Program Files (x86)\ossec-agent";
    #[cfg(target_os = "macos")]
    let ossec_path = "/Library/Ossec";
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    let ossec_path = "/var/ossec";

    #[cfg(target_os = "windows")]
    let components: Vec<(String, String)> = vec![
        (
            "Wazuh Agent".to_string(),
            format!("{}\\wazuh-agent.exe", ossec_path),
        ),
        (
            "OAuth2 Client".to_string(),
            format!("{}\\wazuh-cert-oauth2-client.exe", ossec_path),
        ),
        (
            "Agent Status Monitor".to_string(),
            r"C:\Program Files\wazuh-agent-status\wazuh-agent-status.exe".to_string(),
        ),
        ("YARA".to_string(), "yara64.exe".to_string()),
        ("Suricata".to_string(), "suricata.exe".to_string()),
        ("NetBird".to_string(), "netbird.exe".to_string()),
    ];

    #[cfg(target_os = "macos")]
    let components: Vec<(String, String)> = vec![
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
            "/usr/local/bin/wazuh-agent-status".to_string(),
        ),
        ("YARA".to_string(), "/usr/local/bin/yara".to_string()),
        (
            "Suricata".to_string(),
            "/usr/local/bin/suricata".to_string(),
        ),
        ("NetBird".to_string(), "/usr/local/bin/netbird".to_string()),
    ];

    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    let components: Vec<(String, String)> = vec![
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
            "/usr/local/bin/wazuh-agent-status".to_string(),
        ),
        ("YARA".to_string(), "/usr/local/bin/yara".to_string()),
        ("Suricata".to_string(), "/usr/bin/suricata".to_string()),
        ("NetBird".to_string(), "/usr/bin/netbird".to_string()),
    ];

    let mut results = Vec::new();

    for (name, path) in components {
        #[cfg(unix)]
        let (installed, effective_path) = check_component_unix(&name, &path);

        #[cfg(windows)]
        let (installed, effective_path) = check_component_windows(&name, &path).await;

        let version = if installed {
            get_component_version(&name, &effective_path).await
        } else {
            None
        };

        results.push(ComponentStatus {
            name,
            installed,
            version,
            path: effective_path,
        });
    }

    Ok(results)
}

// ---- Netbird State ----

#[derive(Serialize)]
struct NetbirdState {
    daemon_status: Option<String>,
    netbird_ip: Option<String>,
    management_connected: bool,
}

#[tauri::command]
#[cfg(target_os = "windows")]
fn fallback_netbird_cmd_windows() -> Option<Command> {
    if std::process::Command::new("netbird")
        .arg("--version")
        .output()
        .is_err()
    {
        if std::path::Path::new(r"C:\Program Files\Netbird\netbird.exe").exists() {
            return Some(create_command(r"C:\Program Files\Netbird\netbird.exe"));
        } else if std::path::Path::new(r"C:\Program Files (x86)\Netbird\netbird.exe").exists() {
            return Some(create_command(
                r"C:\Program Files (x86)\Netbird\netbird.exe",
            ));
        }
    }
    None
}

#[cfg(not(target_os = "windows"))]
fn fallback_netbird_cmd_unix() -> Option<Command> {
    if std::process::Command::new("netbird")
        .arg("--version")
        .output()
        .is_err()
    {
        if std::path::Path::new("/usr/bin/netbird").exists() {
            return Some(create_command("/usr/bin/netbird"));
        } else if std::path::Path::new("/usr/local/bin/netbird").exists() {
            return Some(create_command("/usr/local/bin/netbird"));
        }
    }
    None
}

#[tauri::command]
async fn check_netbird() -> Result<NetbirdState, String> {
    let mut cmd = create_command("netbird");

    #[cfg(target_os = "windows")]
    if let Some(fallback_cmd) = fallback_netbird_cmd_windows() {
        cmd = fallback_cmd;
    }

    #[cfg(not(target_os = "windows"))]
    if let Some(fallback_cmd) = fallback_netbird_cmd_unix() {
        cmd = fallback_cmd;
    }

    cmd.args(["status", "-j"]);

    let output = cmd.output().await.map_err(|e| e.to_string())?;

    if !output.status.success() {
        return Ok(NetbirdState {
            daemon_status: None,
            netbird_ip: None,
            management_connected: false,
        });
    }

    let json_str = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&json_str).map_err(|e| e.to_string())?;

    let daemon_status = parsed["daemonStatus"].as_str().map(|s| s.to_string());
    let netbird_ip = parsed["netbirdIp"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    let management_connected = parsed["management"]["connected"].as_bool().unwrap_or(false);

    Ok(NetbirdState {
        daemon_status,
        netbird_ip,
        management_connected,
    })
}

// ---- Enrollment State ----

#[derive(Serialize)]
struct EnrollmentState {
    enrolled: bool,
    agent_name: Option<String>,
    manager: Option<String>,
}

#[tauri::command]
fn parse_enrollment_agent_name(content: &str) -> Option<String> {
    content
        .lines()
        .find(|l| !l.trim().is_empty())
        .and_then(|line| line.split_whitespace().nth(1))
        .map(|s| s.to_string())
}

fn parse_enrollment_manager(content: &str) -> Option<String> {
    content
        .lines()
        .find(|l| l.trim().starts_with("<address>"))
        .and_then(|line| {
            line.trim()
                .strip_prefix("<address>")
                .and_then(|s| s.strip_suffix("</address>"))
                .map(|s| s.trim().to_string())
        })
}

#[tauri::command]
async fn check_enrollment() -> Result<EnrollmentState, String> {
    #[cfg(target_os = "windows")]
    let keys_path = r"C:\Program Files (x86)\ossec-agent\client.keys";
    #[cfg(target_os = "macos")]
    let keys_path = "/Library/Ossec/etc/client.keys";
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    let keys_path = "/var/ossec/etc/client.keys";

    let keys_content = std::fs::read_to_string(keys_path).unwrap_or_default();
    let agent_name = parse_enrollment_agent_name(&keys_content);

    if agent_name.is_none() {
        return Ok(EnrollmentState {
            enrolled: false,
            agent_name: None,
            manager: None,
        });
    }

    #[cfg(target_os = "windows")]
    let conf_path = r"C:\Program Files (x86)\ossec-agent\ossec.conf";
    #[cfg(target_os = "macos")]
    let conf_path = "/Library/Ossec/etc/ossec.conf";
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    let conf_path = "/var/ossec/etc/ossec.conf";

    let manager = std::fs::read_to_string(conf_path)
        .ok()
        .and_then(|content| parse_enrollment_manager(&content));

    Ok(EnrollmentState {
        enrolled: true,
        agent_name,
        manager,
    })
}

#[tauri::command]
async fn save_logs(logs: String, prefix: String) -> Result<String, String> {
    let mut path = dirs::download_dir().unwrap_or_else(|| std::env::current_dir().unwrap());
    let filename = format!("wazuh-{}-logs.txt", prefix);
    path.push(filename);

    std::fs::write(&path, logs).map_err(|e| e.to_string())?;
    Ok(path.to_string_lossy().to_string())
}

#[tauri::command]
fn get_app_config(app: AppHandle) -> Result<AppConfig, String> {
    let config_dir = app.path().app_config_dir().map_err(|e| e.to_string())?;
    let config_path = config_dir.join("config.json");
    if config_path.exists() {
        let content = std::fs::read_to_string(&config_path).map_err(|e| e.to_string())?;
        match serde_json::from_str(&content) {
            Ok(config) => Ok(config),
            Err(e) => {
                eprintln!(
                    "Failed to parse config.json, falling back to defaults: {}",
                    e
                );
                Ok(AppConfig::default())
            }
        }
    } else {
        Ok(AppConfig::default())
    }
}

#[cfg(unix)]
fn pre_create_config() {
    if unsafe { libc::geteuid() } != 0 {
        let home = std::env::var("HOME").unwrap_or_default();
        if !home.is_empty() {
            let config_dir = if cfg!(target_os = "macos") {
                std::path::PathBuf::from(&home)
                    .join("Library/Application Support/com.adorsys.wazuh-agent-installer")
            } else {
                std::path::PathBuf::from(&home).join(".config/com.adorsys.wazuh-agent-installer")
            };
            let _ = std::fs::create_dir_all(&config_dir);
            let config_file = config_dir.join("config.json");
            if !config_file.exists() {
                let default_config = AppConfig::default();
                if let Ok(json) = serde_json::to_string_pretty(&default_config) {
                    let _ = std::fs::write(config_file, json);
                }
            }
        }
    }
}

#[cfg(unix)]
fn get_launcher_args() -> Vec<String> {
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
}

#[cfg(target_os = "linux")]
fn get_gtk_theme() -> Option<String> {
    std::process::Command::new("gsettings")
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
        })
}

#[cfg(target_os = "linux")]
fn elevate_linux(launcher_pid: u32) {
    if unsafe { libc::geteuid() } != 0 {
        let exe = std::env::current_exe().expect("cannot get executable path");
        let args = get_launcher_args();

        let display = std::env::var("DISPLAY").unwrap_or_default();
        let xauthority = std::env::var("XAUTHORITY").unwrap_or_default();
        let wayland = std::env::var("WAYLAND_DISPLAY").unwrap_or_default();
        let xdg_runtime = std::env::var("XDG_RUNTIME_DIR").unwrap_or_default();
        let home = std::env::var("HOME").unwrap_or_default();
        let xdg_data_dirs = std::env::var("XDG_DATA_DIRS").unwrap_or_default();

        let mut cmd = std::process::Command::new("pkexec");
        cmd.arg("env")
            .arg(format!("DISPLAY={display}"))
            .arg(format!("XAUTHORITY={xauthority}"))
            .arg(format!("WAYLAND_DISPLAY={wayland}"))
            .arg(format!("XDG_RUNTIME_DIR={xdg_runtime}"))
            .arg(format!("HOME={home}"))
            .arg(format!("XDG_DATA_DIRS={xdg_data_dirs}"));

        if let Some(theme) = get_gtk_theme() {
            cmd.arg(format!("GTK_THEME={theme}"));
        }

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
}

#[cfg(target_os = "macos")]
fn elevate_macos(launcher_pid: u32) {
    if unsafe { libc::geteuid() } != 0 {
        let exe = std::env::current_exe()
            .expect("cannot get executable path")
            .to_string_lossy()
            .to_string();
        let args = get_launcher_args();

        let sq = |s: &str| format!("'{}'", s.replace('\'', "'\\''"));
        let mut parts = vec![sq(&exe), sq(&format!("--parent-pid {launcher_pid}"))];
        for a in &args {
            parts.push(sq(a));
        }
        let home = std::env::var("HOME").unwrap_or_default();
        let env_setup = format!("export HOME={};", sq(&home));
        let shell_cmd = format!("{} sh -c {}", env_setup, sq(&parts.join(" ")));

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
}

#[cfg(unix)]
fn get_parent_pid_from_args() -> Option<libc::pid_t> {
    let raw_args: Vec<String> = std::env::args().collect();
    let pos = raw_args.iter().position(|a| a == "--parent-pid")?;
    let pid_str = raw_args.get(pos + 1)?;
    pid_str.parse::<libc::pid_t>().ok()
}

#[cfg(unix)]
fn spawn_watchdog() {
    if let Some(parent_pid) = get_parent_pid_from_args() {
        std::thread::spawn(move || loop {
            std::thread::sleep(std::time::Duration::from_millis(500));
            if unsafe { libc::kill(parent_pid, 0) } != 0 {
                std::process::exit(0);
            }
        });
    }
}

fn handle_tray_menu_event(app: &AppHandle, event: tauri::menu::MenuEvent) {
    match event.id.as_ref() {
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
    }
}

fn handle_tray_icon_event(tray: &tauri::tray::TrayIcon, event: tauri::tray::TrayIconEvent) {
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
}

fn setup_tray(app: &mut tauri::App) -> Result<(), Box<dyn std::error::Error>> {
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
            .on_menu_event(handle_tray_menu_event)
            .on_tray_icon_event(handle_tray_icon_event)
            .build(app)?;
    }
    Ok(())
}

fn setup_app(app: &mut tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    if let Ok(config_dir) = app.path().app_config_dir() {
        let _ = std::fs::create_dir_all(&config_dir);
        let config_path = config_dir.join("config.json");
        if !config_path.exists() {
            let default_config = AppConfig::default();
            if let Ok(json) = serde_json::to_string_pretty(&default_config) {
                let _ = std::fs::write(config_path, json);
            }
        }
    }
    setup_tray(app)?;
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    #[cfg(unix)]
    pre_create_config();

    #[cfg(unix)]
    let launcher_pid = std::process::id();

    #[cfg(target_os = "linux")]
    elevate_linux(launcher_pid);

    #[cfg(target_os = "macos")]
    elevate_macos(launcher_pid);

    #[cfg(unix)]
    spawn_watchdog();

    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.unminimize();
                let _ = window.set_focus();
            }
        }))
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            is_root,
            get_platform,
            run_install,
            run_enroll,
            run_netbird_up,
            check_components,
            check_enrollment,
            check_netbird,
            save_logs,
            get_app_config
        ])
        .setup(setup_app)
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
