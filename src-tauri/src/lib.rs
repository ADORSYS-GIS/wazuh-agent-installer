use serde::{Deserialize, Serialize};
use std::env;
use std::process::Stdio;
use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    AppHandle, Emitter, Manager,
};
#[cfg(not(target_os = "linux"))]
use tauri_plugin_autostart::ManagerExt as AutostartManagerExt;
#[cfg(not(target_os = "linux"))]
use tauri_plugin_notification::NotificationExt;
use tokio::io::AsyncBufReadExt;
use tokio::process::Command;

/// Where the latest published version is read from (kept on the main branch).
const VERSION_FILE_URL: &str =
    "https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-agent-installer/main/version.txt";

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

#[derive(Serialize)]
struct UpdateInfo {
    update_available: bool,
    latest_version: Option<String>,
}

/// Parse a loose semver ("v1.2.3", "1.2.3-rc.1", "1.2") into a comparable tuple.
fn parse_version(v: &str) -> Option<(u64, u64, u64)> {
    let s = v.trim().trim_start_matches('v');
    let core = s.split('-').next().unwrap_or(s);
    let mut it = core.split('.');
    let major = it.next()?.trim().parse().ok()?;
    let minor = it.next().unwrap_or("0").trim().parse().unwrap_or(0);
    let patch = it.next().unwrap_or("0").trim().parse().unwrap_or(0);
    Some((major, minor, patch))
}

/// Fetch version.txt over HTTPS using curl (present on all supported platforms,
/// and already a dependency of the install scripts).
async fn fetch_latest_version() -> Option<String> {
    let child = Command::new("curl")
        .args(["-fsSL", "--proto", "=https", "--tlsv1.2", VERSION_FILE_URL])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .ok()?;
    let output = tokio::time::timeout(std::time::Duration::from_secs(10), child.wait_with_output())
        .await
        .ok()?
        .ok()?;
    parse_curl_version_output(&output)
}

fn parse_curl_version_output(output: &std::process::Output) -> Option<String> {
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let trimmed = text.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn get_local_version_at_path(config_dir: &std::path::Path) -> String {
    let version_path = config_dir.join("version.txt");
    if let Ok(content) = std::fs::read_to_string(version_path) {
        let trimmed = content.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    env!("CARGO_PKG_VERSION").to_string()
}

fn get_local_version(app: &AppHandle) -> String {
    if let Ok(config_dir) = app.path().app_config_dir() {
        return get_local_version_at_path(&config_dir);
    }
    env!("CARGO_PKG_VERSION").to_string()
}

#[tauri::command]
fn get_local_version_command(app: tauri::AppHandle) -> String {
    get_local_version(&app)
}

fn evaluate_update_available(current: &str, latest: Option<&str>) -> UpdateInfo {
    let update_available = match (latest, parse_version(current)) {
        (Some(latest_ver), Some(cur)) => {
            parse_version(latest_ver).map(|l| l > cur).unwrap_or(false)
        }
        _ => false,
    };

    UpdateInfo {
        update_available,
        latest_version: latest.map(str::to_string),
    }
}

#[tauri::command]
async fn check_for_updates(app: tauri::AppHandle) -> Result<UpdateInfo, String> {
    let current = get_local_version(&app);
    let latest = fetch_latest_version().await;
    Ok(evaluate_update_available(&current, latest.as_deref()))
}

fn get_update_script_name_for_os(os: &str) -> &'static str {
    if os == "windows" {
        "windows.ps1"
    } else if os == "macos" {
        "macos.sh"
    } else {
        "ubuntu.sh"
    }
}

fn get_update_script_name() -> &'static str {
    get_update_script_name_for_os(std::env::consts::OS)
}

fn build_app_update_command(resolved_path: &str) -> Command {
    #[cfg(target_os = "windows")]
    let mut cmd = {
        let mut c = create_command("powershell");
        c.args([
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            resolved_path,
        ]);
        c
    };

    #[cfg(target_os = "macos")]
    let mut cmd = {
        let mut c = create_command("bash");
        c.arg(resolved_path);
        c
    };

    #[cfg(target_os = "linux")]
    let mut cmd = {
        let mut c = create_command("bash");
        c.arg(resolved_path);
        c
    };

    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
    cmd
}

async fn write_rx_logs_to_file<P: AsRef<std::path::Path>>(
    path: P,
    mut rx: tokio::sync::mpsc::UnboundedReceiver<String>,
) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await?;
    while let Some(line) = rx.recv().await {
        file.write_all(format!("{}\n", line).as_bytes()).await?;
    }
    file.flush().await?;
    Ok(())
}

fn format_updater_exit_status(status: std::process::ExitStatus) -> Result<String, String> {
    if !status.success() {
        Err(format!(
            "Updater failed with exit code: {}",
            status.code().unwrap_or(-1)
        ))
    } else {
        Ok(format!("Update process exited with status: {}", status))
    }
}

#[tauri::command]
async fn run_app_update(app: AppHandle) -> Result<(), String> {
    let script_name = get_update_script_name();
    let resolved_path = resolve_bundled_script(&app, script_name)?;
    let mut cmd = build_app_update_command(&resolved_path);

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("Failed to spawn updater: {}", e))?;

    let stdout = child.stdout.take().expect("Failed to capture stdout");
    let stderr = child.stderr.take().expect("Failed to capture stderr");

    let (tx_log, rx_log) = tokio::sync::mpsc::unbounded_channel::<String>();

    let tx1 = tx_log.clone();
    spawn_log_reader(stdout, app.clone(), "install-log", move |line| {
        let _ = tx1.send(line.to_string());
    });

    let tx2 = tx_log;
    spawn_log_reader(stderr, app.clone(), "install-log", move |line| {
        let _ = tx2.send(line.to_string());
    });

    let log_file = app.path().app_config_dir().unwrap().join("update.log");
    tokio::spawn(async move {
        let _ = write_rx_logs_to_file(&log_file, rx_log).await;
    });

    let status = child.wait().await.map_err(|e| e.to_string())?;
    let line = format_updater_exit_status(status)?;

    let _ = app.emit(
        "install-log",
        LogLine {
            line,
            level: "info".into(),
        },
    );

    Ok(())
}

#[cfg(target_os = "linux")]
fn notify_update_linux(latest: &str) {
    let _ = std::process::Command::new("notify-send")
        .arg("-a")
        .arg("Wazuh")
        .arg("Wazuh Agent Installer")
        .arg(format!("A new version ({}) is available.", latest))
        .spawn();
}

fn notify_update_for_version(#[allow(unused_variables)] app: Option<&AppHandle>, latest: &str) {
    #[cfg(target_os = "linux")]
    {
        notify_update_linux(latest);
    }
    #[cfg(not(target_os = "linux"))]
    {
        if let Some(app) = app {
            let res = app
                .notification()
                .builder()
                .title("Wazuh Agent Installer update available")
                .body(format!("A new version ({latest}) is available."))
                .show();

            if let Err(e) = res {
                println!("Failed to show system notification: {}", e);
            } else {
                println!(
                    "System notification sent successfully for version {}",
                    latest
                );
            }
        }
    }
}

fn notify_update(app: &AppHandle, latest: &str) {
    notify_update_for_version(Some(app), latest);
}

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
            tokio::time::timeout(std::time::Duration::from_secs(5), child.wait_with_output()).await
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

#[cfg(unix)]
fn make_script_executable_unix(resource_path: &std::path::Path) -> Result<String, String> {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(resource_path) {
        let mode = meta.permissions().mode();
        if mode & 0o111 != 0 {
            // Already executable — use in place
            return resource_path
                .to_str()
                .map(str::to_string)
                .ok_or_else(|| "Script path contains invalid UTF-8".to_string());
        }
    }
    // Not executable — write to a random, unpredictable temp file using O_EXCL
    // (create_new) so a local attacker cannot pre-plant a symlink or race the path.
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp_path = std::env::temp_dir().join(format!(
        "wazuh-bundled-script-{}-{nanos}.sh",
        std::process::id()
    ));
    let bytes = std::fs::read(resource_path)
        .map_err(|e| format!("Failed to read bundled script: {}", e))?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o700)
        .open(&tmp_path)
        .map_err(|e| format!("Failed to create script in temp dir: {}", e))?;
    file.write_all(&bytes)
        .map_err(|e| format!("Failed to write script to temp dir: {}", e))?;
    file.flush()
        .map_err(|e| format!("Failed to flush script to temp dir: {}", e))?;
    tmp_path
        .to_str()
        .map(str::to_string)
        .ok_or_else(|| "Script path contains invalid UTF-8".to_string())
}

fn resolve_script_path(resource_path: &std::path::Path) -> Result<String, String> {
    #[cfg(unix)]
    {
        make_script_executable_unix(resource_path)
    }

    #[cfg(not(unix))]
    resource_path
        .to_str()
        .map(str::to_string)
        .ok_or_else(|| "Script path contains invalid UTF-8".to_string())
}

fn resolve_bundled_script(app: &AppHandle, script_name: &str) -> Result<String, String> {
    let resource_path = app
        .path()
        .resolve(script_name, tauri::path::BaseDirectory::Resource)
        .map_err(|e| format!("Failed to resolve resource path: {}", e))?;

    resolve_script_path(&resource_path)
}

fn get_install_script_name(os: &str) -> &'static str {
    if os == "windows" {
        "setup-agent.ps1"
    } else {
        "setup-agent.sh"
    }
}

fn resolve_script(app: &AppHandle) -> Result<String, String> {
    let script_name = get_install_script_name(env::consts::OS);
    resolve_bundled_script(app, script_name)
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
        c.env("WAZUH_MANAGER", &config.wazuh_manager)
            .env("WAZUH_AGENT_NAME", &config.wazuh_agent_name)
            .env("IDS_ENGINE", &config.ids_engine)
            .env("SURICATA_MODE", &config.suricata_mode);
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

async fn read_log_lines<T, F>(stream: T, mut on_line: F)
where
    T: tokio::io::AsyncRead + Unpin,
    F: FnMut(&str, LogLine),
{
    let mut reader = tokio::io::BufReader::new(stream).lines();
    while let Ok(Some(line)) = reader.next_line().await {
        if line.trim().is_empty() {
            continue;
        }
        let level = classify_line(&line);
        let log_line = LogLine {
            line: line.clone(),
            level: level.into(),
        };
        on_line(&line, log_line);
    }
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
        read_log_lines(stream, move |raw_line, log_line| {
            process_line(raw_line);
            let _ = app.emit(event_name, log_line);
        })
        .await;
    });
}

fn get_install_line_processor(
    tx_done: tokio::sync::mpsc::Sender<bool>,
) -> impl FnMut(&str) + Send + 'static {
    move |line: &str| {
        if line.contains("Wazuh setup has been completed successfully") {
            let _ = tx_done.try_send(true);
        }
    }
}

async fn wait_for_process_or_rx(
    mut child: tokio::process::Child,
    mut rx_done: tokio::sync::mpsc::Receiver<bool>,
    success_msg: &str,
    fail_msg: &str,
) -> Result<InstallResult, String> {
    let status_future = child.wait();

    let (success, exit_code) = tokio::select! {
        Ok(status) = status_future => {
            (status.success(), status.code().unwrap_or(-1))
        }
        Some(_) = rx_done.recv() => {
            let _ = child.kill().await;
            (true, 0)
        }
    };

    Ok(InstallResult {
        success,
        exit_code,
        message: if success {
            success_msg.into()
        } else {
            fail_msg.into()
        },
    })
}

async fn wait_for_process_or_notify(
    mut child: tokio::process::Child,
    notify: std::sync::Arc<tokio::sync::Notify>,
    success_msg: &str,
    fail_msg: &str,
) -> Result<InstallResult, String> {
    tokio::select! {
        res = child.wait() => {
            let status = res.map_err(|e| e.to_string())?;
            Ok(InstallResult {
                success: status.success(),
                exit_code: status.code().unwrap_or(-1),
                message: if status.success() {
                    success_msg.into()
                } else {
                    fail_msg.into()
                },
            })
        },
        _ = notify.notified() => {
            let _ = child.kill().await;
            Ok(InstallResult {
                success: true,
                exit_code: 0,
                message: success_msg.into(),
            })
        }
    }
}

#[tauri::command]
async fn run_install(config: InstallConfig, app: AppHandle) -> Result<InstallResult, String> {
    let resolved_path = resolve_script(&app)?;
    let mut command = build_install_command(&config, &resolved_path);

    let mut child = command.spawn().map_err(|e| e.to_string())?;

    let stdout = child.stdout.take().expect("Failed to capture stdout");
    let stderr = child.stderr.take().expect("Failed to capture stderr");

    let (tx_done, rx_done) = tokio::sync::mpsc::channel(1);
    spawn_log_reader(
        stdout,
        app.clone(),
        "install-log",
        get_install_line_processor(tx_done),
    );
    spawn_log_reader(stderr, app, "install-log", move |_| {});

    wait_for_process_or_rx(
        child,
        rx_done,
        "Installation complete",
        "Installation failed",
    )
    .await
}

fn is_safe_url(url: &str) -> bool {
    let trimmed = url.trim();
    // Only ever open http(s) URLs, and reject any whitespace/control characters
    // that could inject schemes or argument-splitting when passed to a browser opener.
    if !(trimmed.starts_with("https://") || trimmed.starts_with("http://")) {
        return false;
    }
    !trimmed.chars().any(|c| c.is_whitespace() || c.is_control())
}

fn open_browser(url: &str) {
    let url = url.trim();
    if !is_safe_url(url) {
        return;
    }

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

    wait_for_process_or_notify(child, enrolled, "Enrollment complete", "Enrollment failed").await
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

    wait_for_process_or_notify(
        child,
        connected,
        "NetBird connected successfully",
        "NetBird connection failed",
    )
    .await
}
fn check_path_candidates<F>(path: &str, candidates: &[&str], exists: F) -> (bool, String)
where
    F: Fn(&str) -> bool,
{
    if exists(path) {
        return (true, path.to_string());
    }
    for &candidate in candidates {
        if exists(candidate) {
            return (true, candidate.to_string());
        }
    }
    (false, path.to_string())
}

#[cfg(unix)]
fn check_netbird_unix(path: &str) -> (bool, String) {
    check_path_candidates(path, &["/usr/bin/netbird", "/usr/local/bin/netbird"], |p| {
        std::path::Path::new(p).exists()
    })
}

#[cfg(unix)]
fn check_suricata_unix(path: &str) -> (bool, String) {
    check_path_candidates(
        path,
        &[
            "/usr/bin/suricata",
            "/usr/local/bin/suricata",
            "/opt/homebrew/bin/suricata",
        ],
        |p| std::path::Path::new(p).exists(),
    )
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
        ("YARA".to_string(), "/opt/wazuh/yara/bin/yara".to_string()),
        (
            "Suricata".to_string(),
            "/opt/wazuh/suricata/bin/suricata".to_string(),
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
        ("YARA".to_string(), "/opt/wazuh/yara/bin/yara".to_string()),
        (
            "Suricata".to_string(),
            "/opt/wazuh/suricata/bin/suricata".to_string(),
        ),
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

fn find_netbird_binary<F>(exists: F) -> Option<&'static str>
where
    F: Fn(&str) -> bool,
{
    if exists("/usr/bin/netbird") {
        Some("/usr/bin/netbird")
    } else if exists("/usr/local/bin/netbird") {
        Some("/usr/local/bin/netbird")
    } else {
        None
    }
}

#[cfg(not(target_os = "windows"))]
fn fallback_netbird_cmd_unix_with<F, C>(mut check_err: C, find_bin: F) -> Option<Command>
where
    C: FnMut() -> bool,
    F: FnOnce() -> Option<&'static str>,
{
    if check_err() {
        if let Some(bin) = find_bin() {
            return Some(create_command(bin));
        }
    }
    None
}

#[cfg(not(target_os = "windows"))]
fn fallback_netbird_cmd_unix() -> Option<Command> {
    fallback_netbird_cmd_unix_with(
        || {
            std::process::Command::new("netbird")
                .arg("--version")
                .output()
                .is_err()
        },
        || find_netbird_binary(|p| std::path::Path::new(p).exists()),
    )
}

fn parse_netbird_cmd_output(output: &std::process::Output) -> Result<NetbirdState, String> {
    if !output.status.success() {
        return Ok(NetbirdState {
            daemon_status: None,
            netbird_ip: None,
            management_connected: false,
        });
    }

    let json_str = String::from_utf8_lossy(&output.stdout);
    parse_netbird_status_json(&json_str)
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
    parse_netbird_cmd_output(&output)
}

fn parse_netbird_status_json(json_str: &str) -> Result<NetbirdState, String> {
    let parsed: serde_json::Value = serde_json::from_str(json_str).map_err(|e| e.to_string())?;

    let daemon_status = parsed["daemonStatus"].as_str().map(str::to_string);
    let netbird_ip = parsed["netbirdIp"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(str::to_string);
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
        .map(str::to_string)
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

fn parse_enrollment_from_content(
    keys_content: &str,
    conf_content: Option<&str>,
) -> EnrollmentState {
    let agent_name = parse_enrollment_agent_name(keys_content);
    if agent_name.is_none() {
        return EnrollmentState {
            enrolled: false,
            agent_name: None,
            manager: None,
        };
    }

    let manager = conf_content.and_then(parse_enrollment_manager);
    EnrollmentState {
        enrolled: true,
        agent_name,
        manager,
    }
}

async fn check_enrollment_at_paths<P1: AsRef<std::path::Path>, P2: AsRef<std::path::Path>>(
    keys_path: P1,
    conf_path: P2,
) -> EnrollmentState {
    let keys_content = tokio::fs::read_to_string(keys_path)
        .await
        .unwrap_or_default();
    let manager_conf = tokio::fs::read_to_string(conf_path).await.ok();
    parse_enrollment_from_content(&keys_content, manager_conf.as_deref())
}

#[tauri::command]
async fn check_enrollment() -> Result<EnrollmentState, String> {
    #[cfg(target_os = "windows")]
    let keys_path = r"C:\Program Files (x86)\ossec-agent\client.keys";
    #[cfg(target_os = "macos")]
    let keys_path = "/Library/Ossec/etc/client.keys";
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    let keys_path = "/var/ossec/etc/client.keys";

    #[cfg(target_os = "windows")]
    let conf_path = r"C:\Program Files (x86)\ossec-agent\ossec.conf";
    #[cfg(target_os = "macos")]
    let conf_path = "/Library/Ossec/etc/ossec.conf";
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    let conf_path = "/var/ossec/etc/ossec.conf";

    Ok(check_enrollment_at_paths(keys_path, conf_path).await)
}

fn is_valid_log_prefix(prefix: &str) -> bool {
    !prefix.is_empty()
        && prefix
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn get_log_save_path(base_dir: &std::path::Path, prefix: &str) -> std::path::PathBuf {
    base_dir.join(format!("wazuh-{}-logs.txt", prefix))
}

#[tauri::command]
async fn save_logs(logs: String, prefix: String) -> Result<String, String> {
    if !is_valid_log_prefix(&prefix) {
        return Err("Invalid log prefix".to_string());
    }
    let base_dir = dirs::download_dir().unwrap_or_else(|| std::env::current_dir().unwrap());
    let path = get_log_save_path(&base_dir, &prefix);

    tokio::fs::write(&path, logs)
        .await
        .map_err(|e| e.to_string())?;
    Ok(path.to_string_lossy().to_string())
}

fn parse_app_config_from_str(content: &str) -> AppConfig {
    match serde_json::from_str(content) {
        Ok(config) => config,
        Err(e) => {
            eprintln!(
                "Failed to parse config.json, falling back to defaults: {}",
                e
            );
            AppConfig::default()
        }
    }
}

fn get_app_config_at_path(config_dir: &std::path::Path) -> Result<AppConfig, String> {
    let config_path = config_dir.join("config.json");
    if config_path.exists() {
        let content = std::fs::read_to_string(&config_path).map_err(|e| e.to_string())?;
        Ok(parse_app_config_from_str(&content))
    } else {
        Ok(AppConfig::default())
    }
}

#[tauri::command]
fn get_app_config(app: AppHandle) -> Result<AppConfig, String> {
    let config_dir = app.path().app_config_dir().map_err(|e| e.to_string())?;
    get_app_config_at_path(&config_dir)
}

#[cfg(unix)]
fn pre_create_config_at_home(home: &str) {
    if !home.is_empty() {
        let config_dir = if cfg!(target_os = "macos") {
            std::path::PathBuf::from(home)
                .join("Library/Application Support/com.adorsys.wazuh-agent-installer")
        } else {
            std::path::PathBuf::from(home).join(".config/com.adorsys.wazuh-agent-installer")
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

#[cfg(unix)]
fn pre_create_config() {
    if unsafe { libc::geteuid() } != 0 {
        let home = std::env::var("HOME").unwrap_or_default();
        pre_create_config_at_home(&home);
    }
}

#[cfg(unix)]
fn get_launcher_args_from<I: IntoIterator<Item = String>>(args: I) -> Vec<String> {
    let mut raw = args.into_iter().peekable();
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

#[cfg(unix)]
fn get_launcher_args() -> Vec<String> {
    get_launcher_args_from(std::env::args().skip(1))
}

fn parse_gtk_theme(output_str: &str) -> Option<String> {
    let theme = output_str.trim().trim_matches('\'').to_string();
    if !theme.is_empty() {
        Some(theme)
    } else {
        None
    }
}

fn parse_gsettings_output(output: &std::process::Output) -> Option<String> {
    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        parse_gtk_theme(&stdout)
    } else {
        None
    }
}

#[cfg(target_os = "linux")]
fn get_gtk_theme() -> Option<String> {
    std::process::Command::new("gsettings")
        .args(["get", "org.gnome.desktop.interface", "gtk-theme"])
        .output()
        .ok()
        .and_then(|output| parse_gsettings_output(&output))
}

#[cfg(target_os = "linux")]
fn build_pkexec_command(
    exe: &std::path::Path,
    launcher_pid: u32,
    args: &[String],
    theme: Option<&str>,
) -> std::process::Command {
    let display = std::env::var("DISPLAY").unwrap_or_default();
    let xauthority = std::env::var("XAUTHORITY").unwrap_or_default();
    let wayland = std::env::var("WAYLAND_DISPLAY").unwrap_or_default();
    let xdg_runtime = std::env::var("XDG_RUNTIME_DIR").unwrap_or_default();
    let home = std::env::var("HOME").unwrap_or_default();
    let xdg_data_dirs = std::env::var("XDG_DATA_DIRS").unwrap_or_default();
    let dbus = std::env::var("DBUS_SESSION_BUS_ADDRESS").unwrap_or_default();

    let xdg_current_desktop = std::env::var("XDG_CURRENT_DESKTOP").unwrap_or_default();
    let xdg_session_type = std::env::var("XDG_SESSION_TYPE").unwrap_or_default();
    let xdg_session_desktop = std::env::var("XDG_SESSION_DESKTOP").unwrap_or_default();

    let mut cmd = std::process::Command::new("pkexec");
    cmd.arg("env")
        .arg(format!("DISPLAY={display}"))
        .arg(format!("XAUTHORITY={xauthority}"))
        .arg(format!("WAYLAND_DISPLAY={wayland}"))
        .arg(format!("XDG_RUNTIME_DIR={xdg_runtime}"))
        .arg(format!("HOME={home}"))
        .arg(format!("XDG_DATA_DIRS={xdg_data_dirs}"))
        .arg(format!("DBUS_SESSION_BUS_ADDRESS={dbus}"))
        .arg(format!("XDG_CURRENT_DESKTOP={xdg_current_desktop}"))
        .arg(format!("XDG_SESSION_TYPE={xdg_session_type}"))
        .arg(format!("XDG_SESSION_DESKTOP={xdg_session_desktop}"))
        .arg("GTK_DECORATION_LAYOUT=menu:minimize,maximize,close");

    if let Some(t) = theme {
        cmd.arg(format!("GTK_THEME={t}"));
    }

    cmd.arg(exe)
        .arg("--parent-pid")
        .arg(launcher_pid.to_string())
        .args(args);

    cmd
}

#[cfg(target_os = "linux")]
fn elevate_linux(launcher_pid: u32) {
    if unsafe { libc::geteuid() } != 0 {
        let exe = std::env::current_exe().expect("cannot get executable path");
        let args = get_launcher_args();
        let theme = get_gtk_theme();
        let mut cmd = build_pkexec_command(&exe, launcher_pid, &args, theme.as_deref());
        let status = cmd.status();
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
        let mut parts = vec![sq(&exe), sq("--parent-pid"), sq(&launcher_pid.to_string())];
        for a in &args {
            parts.push(sq(a));
        }
        let home = std::env::var("HOME").unwrap_or_default();
        let shell_cmd = format!("export HOME={}; {}", sq(&home), parts.join(" "));

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
fn parse_parent_pid<I, S>(args: I) -> Option<libc::pid_t>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let args: Vec<S> = args.into_iter().collect();
    let pos = args.iter().position(|a| a.as_ref() == "--parent-pid")?;
    let pid_str = args.get(pos + 1)?.as_ref();
    pid_str.parse::<libc::pid_t>().ok()
}

#[cfg(unix)]
fn get_parent_pid_from_args() -> Option<libc::pid_t> {
    parse_parent_pid(std::env::args())
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

#[derive(Debug, PartialEq, Eq)]
enum TrayMenuAction {
    Show,
    Quit,
    Unknown,
}

fn parse_tray_menu_action(id: &str) -> TrayMenuAction {
    match id {
        "show" => TrayMenuAction::Show,
        "quit" => TrayMenuAction::Quit,
        _ => TrayMenuAction::Unknown,
    }
}

fn execute_tray_menu_action<F1, F2>(action: TrayMenuAction, mut on_show: F1, mut on_quit: F2)
where
    F1: FnMut(),
    F2: FnMut(),
{
    match action {
        TrayMenuAction::Show => on_show(),
        TrayMenuAction::Quit => on_quit(),
        TrayMenuAction::Unknown => {}
    }
}

fn handle_tray_menu_event(app: &AppHandle, event: tauri::menu::MenuEvent) {
    execute_tray_menu_action(
        parse_tray_menu_action(event.id.as_ref()),
        || {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.set_focus();
            }
        },
        || {
            app.exit(0);
        },
    );
}

fn should_toggle_window_on_tray_click(event: &tauri::tray::TrayIconEvent) -> bool {
    matches!(
        event,
        TrayIconEvent::Click {
            button: MouseButton::Left,
            button_state: MouseButtonState::Up,
            ..
        }
    )
}

#[derive(Debug, PartialEq, Eq)]
enum WindowToggleAction {
    Hide,
    ShowAndFocus,
}

fn determine_window_toggle_action(is_visible: bool) -> WindowToggleAction {
    if is_visible {
        WindowToggleAction::Hide
    } else {
        WindowToggleAction::ShowAndFocus
    }
}

fn handle_tray_icon_event(tray: &tauri::tray::TrayIcon, event: tauri::tray::TrayIconEvent) {
    if should_toggle_window_on_tray_click(&event) {
        let app = tray.app_handle();
        if let Some(window) = app.get_webview_window("main") {
            match determine_window_toggle_action(window.is_visible().unwrap_or(false)) {
                WindowToggleAction::Hide => {
                    let _ = window.hide();
                }
                WindowToggleAction::ShowAndFocus => {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
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

fn check_is_checker_mode<I: IntoIterator<Item = S>, S: AsRef<str>>(args: I) -> bool {
    args.into_iter().any(|a| a.as_ref() == "--check-updates")
}

fn is_checker_mode() -> bool {
    check_is_checker_mode(env::args())
}

fn should_notify_update(current: &str, latest: Option<&str>) -> bool {
    evaluate_update_available(current, latest).update_available
}

fn check_and_notify_update<F>(current: &str, latest: Option<&str>, mut notify: F) -> bool
where
    F: FnMut(&str),
{
    if should_notify_update(current, latest) {
        if let Some(ver) = latest {
            notify(ver);
            return true;
        }
    }
    false
}

/// Non-elevated background checker: launched at login, reads version.txt once,
/// shows an OS notification if an update is available, then exits. It never
/// downloads or installs anything.
fn start_background_checker(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        if let Some(win) = app.get_webview_window("main") {
            let _ = win.hide();
        }
        let current = get_local_version(&app);
        let latest = fetch_latest_version().await;
        check_and_notify_update(&current, latest.as_deref(), |ver| notify_update(&app, ver));
        app.exit(0);
    });
}

fn init_config_dir_at_path(config_dir: &std::path::Path) {
    let _ = std::fs::create_dir_all(config_dir);

    let config_path = config_dir.join("config.json");
    if !config_path.exists() {
        let default_config = AppConfig::default();
        if let Ok(json) = serde_json::to_string_pretty(&default_config) {
            let _ = std::fs::write(config_path, json);
        }
    }

    let version_path = config_dir.join("version.txt");
    let cargo_version = env!("CARGO_PKG_VERSION");
    if version_path.exists() {
        let local_content = std::fs::read_to_string(&version_path).unwrap_or_default();
        let local_version = local_content.trim();
        let cargo_parsed = parse_version(cargo_version).unwrap_or((0, 0, 0));
        let local_parsed = parse_version(local_version).unwrap_or((0, 0, 0));
        if cargo_parsed > local_parsed {
            let _ = std::fs::write(&version_path, cargo_version);
        }
    } else {
        let _ = std::fs::write(&version_path, cargo_version);
    }
}

fn init_config_dir(app: &tauri::App) {
    let Ok(config_dir) = app.path().app_config_dir() else {
        return;
    };
    init_config_dir_at_path(&config_dir);
}

fn start_update_poller(app_handle: tauri::AppHandle) {
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        loop {
            let current = get_local_version(&app_handle);
            let latest = fetch_latest_version().await;
            check_and_notify_update(&current, latest.as_deref(), |ver| {
                notify_update(&app_handle, ver);
            });
            tokio::time::sleep(std::time::Duration::from_secs(60 * 60 * 4)).await;
        }
    });
}

#[cfg(target_os = "linux")]
fn get_runtime_path_with_home(home: Option<&str>, filename: &str) -> String {
    let mut path = std::path::PathBuf::from(home.unwrap_or("/tmp"));
    path.push(".config");
    path.push("wazuh-agent-installer");
    let _ = std::fs::create_dir_all(&path);
    path.push(filename);
    path.to_string_lossy().to_string()
}

#[cfg(target_os = "linux")]
fn get_runtime_path(filename: &str) -> String {
    let home = std::env::var("HOME").ok();
    get_runtime_path_with_home(home.as_deref(), filename)
}

fn check_show_file_signal(path: &str) -> bool {
    if std::fs::metadata(path).is_ok() {
        let _ = std::fs::remove_file(path);
        true
    } else {
        false
    }
}

#[cfg(target_os = "linux")]
fn setup_linux_show_watcher(app_handle: tauri::AppHandle) {
    std::thread::spawn(move || {
        let show_file = get_runtime_path(".show");
        let _ = std::fs::remove_file(&show_file);
        loop {
            std::thread::sleep(std::time::Duration::from_millis(300));
            if check_show_file_signal(&show_file) {
                let app_handle_clone = app_handle.clone();
                let _ = app_handle.run_on_main_thread(move || {
                    use tauri::Manager;
                    if let Some(window) = app_handle_clone.get_webview_window("main") {
                        let _ = window.show();
                        let _ = window.unminimize();
                        let _ = window.set_focus();
                    }
                });
            }
        }
    });
}

#[derive(Debug, PartialEq, Eq)]
enum AppStartupMode {
    BackgroundChecker,
    InteractiveApp,
}

fn determine_app_startup_mode(is_checker: bool) -> AppStartupMode {
    if is_checker {
        AppStartupMode::BackgroundChecker
    } else {
        AppStartupMode::InteractiveApp
    }
}

fn setup_app(app: &mut tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    init_config_dir(app);

    match determine_app_startup_mode(is_checker_mode()) {
        AppStartupMode::BackgroundChecker => {
            start_background_checker(app.handle().clone());
        }
        AppStartupMode::InteractiveApp => {
            setup_tray(app)?;

            // 1. Periodically check for updates while the app is running (every 4 hours)
            start_update_poller(app.handle().clone());

            // 2. Register for startup on boot/login.
            // We skip this on Linux at runtime because writing to ~/.config/autostart while
            // the app is running causes GNOME to glitch out the window decorations.
            #[cfg(not(target_os = "linux"))]
            if !app.autolaunch().is_enabled().unwrap_or(false) {
                let _ = app.autolaunch().enable();
            }

            #[cfg(target_os = "linux")]
            setup_linux_show_watcher(app.handle().clone());
        }
    }

    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
enum InstanceLockAction {
    HoldLock,
    Elevate(u32),
    SignalRunningInstance,
}

#[cfg(target_os = "linux")]
fn determine_instance_action(lock_acquired: bool, is_root: bool, pid: u32) -> InstanceLockAction {
    if lock_acquired {
        if is_root {
            InstanceLockAction::HoldLock
        } else {
            InstanceLockAction::Elevate(pid)
        }
    } else {
        InstanceLockAction::SignalRunningInstance
    }
}

#[cfg(target_os = "linux")]
fn try_lock_at_path(lock_path: &str) -> Option<i32> {
    let c_path = std::ffi::CString::new(lock_path).ok()?;

    // Open the file. Use 0o666 so any user can open it.
    let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDWR | libc::O_CREAT, 0o666) };

    if fd < 0 {
        return None;
    }

    // Ensure the file is actually world-writable so root doesn't lock out the user from opening it next time
    unsafe { libc::chmod(c_path.as_ptr(), 0o666) };

    // Try to get an exclusive lock without blocking
    let ret = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
    if ret < 0 {
        // Someone else has the lock
        unsafe { libc::close(fd) };
        return None;
    }

    Some(fd)
}

#[cfg(target_os = "linux")]
fn try_lock_instance() -> Option<i32> {
    let lock_path = get_runtime_path(".lock");
    try_lock_at_path(&lock_path)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    #[cfg(unix)]
    pre_create_config();

    let checker_mode = is_checker_mode();

    if !checker_mode {
        #[cfg(unix)]
        let launcher_pid = std::process::id();

        #[cfg(target_os = "linux")]
        {
            let maybe_fd = try_lock_instance();
            match determine_instance_action(
                maybe_fd.is_some(),
                unsafe { libc::geteuid() == 0 },
                launcher_pid,
            ) {
                InstanceLockAction::HoldLock => {
                    // We are root! We hold the lock for the lifetime of the app.
                    // We intentionally leak `fd`.
                }
                InstanceLockAction::Elevate(pid) => {
                    // We are user! We drop the lock before elevating so the root process can grab it.
                    if let Some(fd) = maybe_fd {
                        unsafe { libc::close(fd) };
                    }
                    elevate_linux(pid);
                }
                InstanceLockAction::SignalRunningInstance => {
                    // Someone else is holding the lock (usually the root instance).
                    let show_path = get_runtime_path(".show");
                    let _ = std::fs::write(&show_path, "show");
                    // Ensure anyone can remove it later
                    let c_path = std::ffi::CString::new(show_path).unwrap();
                    unsafe { libc::chmod(c_path.as_ptr(), 0o666) };
                    std::process::exit(0);
                }
            }
        }

        #[cfg(target_os = "macos")]
        elevate_macos(launcher_pid);

        #[cfg(unix)]
        spawn_watchdog();
    }

    let mut builder = tauri::Builder::default();

    // The background checker is short-lived and non-elevated; let it run without
    // the single-instance lock so a real app launch always opens a fresh instance.
    if !checker_mode {
        builder = builder.plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.unminimize();
                let _ = window.set_focus();
            }
        }));
    }

    builder
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            Some(vec!["--check-updates"]),
        ))
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
            get_app_config,
            check_for_updates,
            run_app_update,
            get_local_version_command
        ])
        .setup(setup_app)
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod tests;
