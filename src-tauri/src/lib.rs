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
use rcgen::{Certificate, CertificateParams, KeyPair, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, BasicConstraints};

const ROOT_CA_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg/Shyem90Ti8j0Dmd
l3Moe2Iv5MC2NwDvRao8o9DD0KGhRANCAARcOtAxYWjYncJ79k0ppY82XxJvcziD
ZLpkcFBMIJIp4GfbV3syOsQZ/OY9KC+Ll9BJbNDZJ/1qZAkZcCSkXRAT
-----END PRIVATE KEY-----"#;

const ROOT_CA_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIB6TCCAY+gAwIBAgIUDh3PiCMN481t4sU48qZIUaCuNsIwCgYIKoZIzj0EAwIw
SjELMAkGA1UEBhMCREUxDzANBgNVBAcMBkJheWVybjESMBAGA1UECgwJU2t5RW5n
UHJvMRYwFAYDVQQDDA13YXp1aC1yb290LWNhMB4XDTI2MDYxMTE2MTU1OFoXDTM2
MDYwODE2MTU1OFowSjELMAkGA1UEBhMCREUxDzANBgNVBAcMBkJheWVybjESMBAG
A1UECgwJU2t5RW5nUHJvMRYwFAYDVQQDDA13YXp1aC1yb290LWNhMFkwEwYHKoZI
zj0CAQYIKoZIzj0DAQcDQgAEXDrQMWFo2J3Ce/ZNKaWPNl8Sb3M4g2S6ZHBQTCCS
KeBn21d7MjrEGfzmPSgvi5fQSWzQ2Sf9amQJGXAkpF0QE6NTMFEwHQYDVR0OBBYE
FCGKYwmbb4Xbcn3/9uQ+wBXFpeYdMB8GA1UdIwQYMBaAFCGKYwmbb4Xbcn3/9uQ+
wBXFpeYdMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIhAL9hx15P
RZu2jXTMVOE4XQs544SYXdyN0o9mEac3PfECAiB9NhE0/xYcoAT0Eo6+MjP5Qq9z
OzCto8KGAt1CbW2iLA==
-----END CERTIFICATE-----
"#;

const MANAGER_TRUSTED_CA: &str = r#"-----BEGIN CERTIFICATE-----
MIIDdTCCAl2gAwIBAgIUPbYlU4PUUi+jgQJgkcifMkXX1lcwDQYJKoZIhvcNAQEL
BQAwSjELMAkGA1UEBhMCREUxDzANBgNVBAcMBkJheWVybjESMBAGA1UECgwJU2t5
RW5nUHJvMRYwFAYDVQQDDA13YXp1aC1yb290LWNhMB4XDTI2MDYxMDE4NTYxNVoX
DTM2MDYwNzE4NTYxNVowSjELMAkGA1UEBhMCREUxDzANBgNVBAcMBkJheWVybjES
MBAGA1UECgwJU2t5RW5nUHJvMRYwFAYDVQQDDA13YXp1aC1yb290LWNhMIIBIjAN
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArxgxf1WcFyzR8B9fcDljzzqcmPsZ
pEGs0SqLTM8bXmT4kmsJnXxY5tKNkHw/np9DVM5yLmPI0hbN7i4ixQJcJelBrEp1
ZjZhDPTcj+qi27q0AvaWlMuyLW+84II/Ca2ezIQ7PAkDSDJMPQD4YK11cGnqlXw4
PI7LWNX8azu2+ijvJlB14HY1cRIRe7/gDHqM33OdXDKnfPcHeZyvKhjmjgIzVXnb
cu3sjBdRmxS4isq+bgFyUZnak/CxkdRehzUe+80BmtkcFVi4cSJSnI4hMjnP7B4g
3jF0i8Pzsy7jsDg559stHsQTAQNvvBkau5uMNUMWIsDJJTQcqzPb+pJaxwIDAQAB
o1MwUTAdBgNVHQ4EFgQUBzB5FvbS4zGJcDYBkRmdmJ2aSw8wHwYDVR0jBBgwFoAU
BzB5FvbS4zGJcDYBkRmdmJ2aSw8wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0B
AQsFAAOCAQEAPreO6x63DuXOIPngydBUhLbwgrZQC4dQyWtYE62DRF7JpgcUUcVX
mIIKP1UtfJYn+WY1Qv2MXYmY55Cwi2cXT3qMTKTuIghIModw7bubpMLAWloxSYAB
RvFghJcj+CR0r6T6HnQH+/0DP6Vc94aaMtXCENvU7jRqUxza4NKLVUzvgwuyktP0
89BG8HlgxR4gl9f4Xq/sCG2fTgYwLkrDdwfDr4QNL3lDiTO5h7PAmm+JNUhhp8ej
7SZCCrRLXPr9j14n3lMsqn50L6EOUKG2VIXuTWWR1U7l6UmJf5PuAoNOPUdWxfCO
qZSWKMImizUDsWwGeot4U1bqUje+HxsIjw==
-----END CERTIFICATE-----
"#;


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
    // TODO: ids_engine is reserved for future Snort support; currently always "suricata"
    pub ids_engine: String,
    pub suricata_mode: String,
    pub install_trivy: bool,
    pub oauth_issuer: String,
    pub cert_endpoint: String,
}

// ---- Helpers ----

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

#[allow(unused_variables)]
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

    // Take the password out of state immediately after reading it, to minimize
    // how long the plaintext remains in process memory.
    let pw_opt = {
        let mut stored = state.sudo_password.lock().unwrap();
        stored.take()
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
        c.arg("-S").arg("-p").arg("");

        // Pass environment variables via `env` so `sudo` doesn't strip them
        c.arg("env");
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
        c.arg("INSTALL_CERT_AUTH=FALSE");
        c.arg("WAZUH_AGENT_STATUS_VERSION=v0.5.0-skyengpro");
        c.arg("WAZUH_AGENT_STATUS_REPO_REF=v0.5.0-skyengpro");

        c.arg(cmd_str).args(&args);
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
        .env("INSTALL_CERT_AUTH", "FALSE")
        .env("WAZUH_AGENT_STATUS_VERSION", "v0.5.0-skyengpro")
        .env("WAZUH_AGENT_STATUS_REPO_REF", "v0.5.0-skyengpro")
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
    app: AppHandle,
    agent_name: Option<String>,
    overwrite: Option<bool>,
    password: Option<String>,
    state: State<'_, AppState>,
) -> Result<InstallResult, String> {
    let overwrite = overwrite.unwrap_or(false);

    if let Some(pw) = password {
        let mut stored = state.sudo_password.lock().unwrap();
        *stored = Some(pw);
    }
    let pw_opt = {
        let mut stored = state.sudo_password.lock().unwrap();
        stored.take()
    };

    let log = |msg: &str, is_error: bool| {
        let _ = app.emit(
            "enroll-log",
            LogLine {
                line: msg.to_string(),
                level: if is_error { "error".into() } else { "info".into() },
            },
        );
    };

    log("Starting manual certificate generation...", false);

    let ossec_etc = if cfg!(windows) {
        "C:\\Program Files (x86)\\ossec-agent"
    } else if cfg!(target_os = "macos") {
        "/Library/Ossec/etc"
    } else {
        "/var/ossec/etc"
    };

    let cert_path = format!("{}/sslagent.cert", ossec_etc);
    let key_path = format!("{}/sslagent.key", ossec_etc);
    let ca_path = format!("{}/rootCA.pem", ossec_etc);
    let conf_path = format!("{}/ossec.conf", ossec_etc);

    if !overwrite && std::path::Path::new(&cert_path).exists() {
        log("Certificates already exist and 'Overwrite' is unchecked. SKIPPING ENROLLMENT SCRIPT!", true);
        return Ok(InstallResult {
            success: true,
            exit_code: 0,
            message: "Certificates already exist".into(),
        });
    }

    let a_name = if agent_name.clone().unwrap_or_default().trim().is_empty() {
        hostname::get()
            .unwrap_or_else(|_| std::ffi::OsString::from("wazuh-agent"))
            .to_string_lossy()
            .to_string()
    } else {
        agent_name.unwrap().trim().to_string()
    };

    log(&format!("Generating certificate for agent: {}", a_name), false);

    let agent_key = KeyPair::generate(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(|e| format!("Failed to generate key: {}", e))?;
    let agent_key_pem = agent_key.serialize_pem();
    let san_name = if a_name.is_ascii() { a_name.clone() } else { "wazuh-agent".to_string() };
    let mut params = CertificateParams::new(vec![san_name]);
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(DnType::CountryName, "DE");
    dn.push(DnType::LocalityName, "Bayern");
    dn.push(DnType::OrganizationName, "SkyEngPro");
    dn.push(DnType::CommonName, a_name.clone());
    params.distinguished_name = dn;
    params.is_ca = IsCa::NoCa;
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    params.key_pair = Some(agent_key);

    let root_key = KeyPair::from_pem(ROOT_CA_KEY_PEM).map_err(|e| format!("Invalid Root CA Key: {}", e))?;
    
    let mut root_params = CertificateParams::new(vec!["wazuh-root-ca".to_string()]);
    let mut root_dn = DistinguishedName::new();
    root_dn.push(DnType::CountryName, "DE");
    root_dn.push(DnType::LocalityName, "Bayern");
    root_dn.push(DnType::OrganizationName, "SkyEngPro");
    root_dn.push(DnType::CommonName, "wazuh-root-ca");
    root_params.distinguished_name = root_dn;
    root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    root_params.key_pair = Some(root_key);
    
    let root_cert = Certificate::from_params(root_params).map_err(|e| format!("Root Cert Error: {}", e))?;
    let agent_cert = Certificate::from_params(params).map_err(|e| format!("Agent Cert Error: {}", e))?;

    let temp_dir = std::env::temp_dir();
    let temp_cert = temp_dir.join("sslagent.cert");
    let temp_key = temp_dir.join("sslagent.key");

    std::fs::write(&temp_cert, agent_cert.serialize_pem_with_signer(&root_cert).map_err(|e| e.to_string())?).unwrap();
    std::fs::write(&temp_key, agent_key_pem).unwrap();

    log("Certificates generated successfully. Applying configuration...", false);

    let (cmd, args, use_sudo) = if cfg!(windows) {
        let mut script = format!("
            $ErrorActionPreference = 'Stop';
            $CertDest = '{cert_path}';
            $KeyDest = '{key_path}';
            $ConfPath = '{conf_path}';
            Copy-Item -Path '{temp_cert}' -Destination $CertDest -Force;
            Copy-Item -Path '{temp_key}' -Destination $KeyDest -Force;
            [System.IO.File]::WriteAllText('{ca_path}', '{MANAGER_TRUSTED_CA}');
            if (Test-Path $ConfPath) {{
                [xml]$xml = Get-Content $ConfPath;
                if ($xml.ossec_config.client.server) {{
                    $xml.ossec_config.client.server.address = '167.235.217.255';
                }}
                if (-not $xml.ossec_config.client.enrollment) {{
                    $enrollment = $xml.CreateElement('enrollment');
                    $xml.ossec_config.client.AppendChild($enrollment) | Out-Null;
                }}
                
                $enrollment = $xml.ossec_config.client.enrollment;
                
                $nodes = @(
                    @('manager_address', '91.98.223.191'),
                    @('port', '1515'),
                    @('agent_name', '{agent_name}'),
                    @('agent_certificate_path', $CertDest),
                    @('agent_key_path', $KeyDest),
                    @('server_ca_path', '{ca_path}')
                );
                
                foreach ($node in $nodes) {{
                    $name = $node[0];
                    $val = $node[1];
                    if (-not $enrollment.$name) {{
                        $newEl = $xml.CreateElement($name);
                        $newEl.InnerText = $val;
                        $enrollment.AppendChild($newEl) | Out-Null;
                    }} else {{
                        $enrollment.$name = $val;
                    }}
                }}
                $xml.Save($ConfPath);
            }}
            Restart-Service -Name WazuhSvc -Force;
            ",
            cert_path=cert_path, key_path=key_path, conf_path=conf_path, temp_cert=temp_cert.display(), temp_key=temp_key.display(), agent_name=a_name, ca_path=ca_path, MANAGER_TRUSTED_CA=MANAGER_TRUSTED_CA
        );
        let script_path = temp_dir.join("enroll.ps1");
        std::fs::write(&script_path, script).unwrap();
        ("powershell".to_string(), vec!["-ExecutionPolicy".to_string(), "Bypass".to_string(), "-File".to_string(), script_path.to_string_lossy().to_string()], false)
    } else {
        let mut script = format!("set -e\n");
        if overwrite {
            script.push_str("rm -f /var/ossec/etc/client.keys /Library/Ossec/etc/client.keys || true\n");
        }
        script.push_str(&format!(
            "cp '{temp_cert}' '{cert_path}'
            cp '{temp_key}' '{key_path}'
            cat << 'EOF' > '{ca_path}'
{MANAGER_TRUSTED_CA}EOF
            chown root:wazuh '{cert_path}' '{key_path}' '{ca_path}' || true
            chmod 640 '{cert_path}' '{key_path}' '{ca_path}'
            
            if [ -f '{conf_path}' ]; then
                # Only replace the first <address> element inside <server>
                sed -i.bak 's/<address>.*<\\/address>/<address>167.235.217.255<\\/address>/g' '{conf_path}'
                
                # Crude XML replacement for cert path, inside <enrollment>
                if grep -q '<enrollment>' '{conf_path}'; then
                    if grep -q '<manager_address>' '{conf_path}'; then
                        sed -i.bak 's/<manager_address>.*<\\/manager_address>/<manager_address>91.98.223.191<\\/manager_address>/g' '{conf_path}'
                    else
                        sed -i.bak '/<enrollment>/a \\    <manager_address>91.98.223.191</manager_address>\\n    <port>1515</port>' '{conf_path}'
                    fi
                
                    if grep -q '<agent_name>' '{conf_path}'; then
                        sed -i.bak 's/<agent_name>.*<\\/agent_name>/<agent_name>{agent_name}<\\/agent_name>/g' '{conf_path}'
                    else
                        sed -i.bak '/<enrollment>/a \\    <agent_name>{agent_name}</agent_name>' '{conf_path}'
                    fi
                
                    if ! grep -q '<agent_certificate_path>' '{conf_path}'; then
                        sed -i.bak '/<enrollment>/a \\    <agent_certificate_path>{cert_path}</agent_certificate_path>' '{conf_path}'
                    fi
                    if ! grep -q '<agent_key_path>' '{conf_path}'; then
                        sed -i.bak '/<enrollment>/a \\    <agent_key_path>{key_path}</agent_key_path>' '{conf_path}'
                    fi
                    if ! grep -q '<server_ca_path>' '{conf_path}'; then
                        sed -i.bak '/<enrollment>/a \\    <server_ca_path>{ca_path}</server_ca_path>' '{conf_path}'
                    fi
                else
                    sed -i.bak '/<client>/a \\  <enrollment>\\n    <manager_address>91.98.223.191</manager_address>\\n    <port>1515</port>\\n    <agent_name>{agent_name}</agent_name>\\n    <agent_certificate_path>{cert_path}</agent_certificate_path>\\n    <agent_key_path>{key_path}</agent_key_path>\\n    <server_ca_path>{ca_path}</server_ca_path>\\n  </enrollment>' '{conf_path}'
                fi
                rm -f '{conf_path}.bak'
            fi
            
            if command -v systemctl >/dev/null 2>&1; then
                systemctl restart wazuh-agent
            elif command -v launchctl >/dev/null 2>&1; then
                /Library/Ossec/bin/wazuh-control restart
            else
                /var/ossec/bin/wazuh-control restart
            fi
            ",
            temp_cert=temp_cert.display(), cert_path=cert_path, temp_key=temp_key.display(), key_path=key_path,
            ca_path=ca_path, MANAGER_TRUSTED_CA=MANAGER_TRUSTED_CA, conf_path=conf_path, agent_name=a_name
        ));
        let script_path = temp_dir.join("enroll.sh");
        std::fs::write(&script_path, script).unwrap();
        ("bash".to_string(), vec![script_path.to_string_lossy().to_string()], true)
    };

    let mut command = if use_sudo {
        let mut c = Command::new("sudo");
        c.arg("-S").arg("-p").arg("").arg(&cmd).args(&args);
        c
    } else {
        let mut c = Command::new(&cmd);
        c.args(&args);
        c
    };

    command.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command.spawn().map_err(|e| e.to_string())?;

    if use_sudo {
        if let Some(mut stdin) = child.stdin.take() {
            if let Some(pw) = pw_opt {
                let _ = stdin.write_all(format!("{}\n", pw).as_bytes()).await;
            }
        }
    }

    let output = child.wait_with_output().await.map_err(|e| e.to_string())?;
    
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        log(&format!("Failed to configure agent: {}", err), true);
        return Ok(InstallResult {
            success: false,
            exit_code: output.status.code().unwrap_or(-1),
            message: "Configuration failed".into(),
        });
    }

    log("Agent successfully enrolled and restarted!", false);
    Ok(InstallResult {
        success: true,
        exit_code: 0,
        message: "Enrollment complete".into(),
    })
}

#[tauri::command]
async fn check_components(
    password: Option<String>,
    state: State<'_, AppState>,
) -> Result<Vec<ComponentStatus>, String> {
    let pw_opt = password.or_else(|| {
        let stored = state.sudo_password.lock().unwrap();
        stored.clone()
    });

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
            if cfg!(windows) {
                format!("{}\\wazuh-agent.exe", ossec_path)
            } else {
                format!("{}/bin/wazuh-agentd", ossec_path)
            },
        ),
        (
            "OAuth2 Client".to_string(),
            if cfg!(windows) {
                format!("{}\\wazuh-cert-oauth2-client.exe", ossec_path)
            } else {
                format!("{}/bin/wazuh-cert-oauth2-client", ossec_path)
            },
        ),
        (
            "Agent Status Monitor".to_string(),
            if cfg!(windows) {
                r"C:\Program Files\wazuh-agent-status\wazuh-agent-status.exe".to_string()
            } else if cfg!(target_os = "macos") {
                "/usr/local/bin/wazuh-agent-status".to_string()
            } else {
                format!("{}/bin/wazuh-agent-status", ossec_path)
            },
        ),
        (
            "YARA".to_string(),
            if cfg!(windows) {
                "yara64.exe".to_string()
            } else {
                "/usr/local/bin/yara".to_string()
            },
        ),
        (
            "Suricata".to_string(),
            if cfg!(windows) {
                "suricata.exe".to_string()
            } else if cfg!(target_os = "macos") {
                "/usr/local/bin/suricata".to_string()
            } else {
                "/usr/bin/suricata".to_string()
            },
        ),
        (
            "Trivy".to_string(),
            if cfg!(windows) {
                "trivy.exe".to_string()
            } else {
                "/usr/local/bin/trivy".to_string()
            },
        ),
        (
            "USB DLP Scripts".to_string(),
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
        let installed = {
            if path == "yara64.exe" || path == "suricata.exe" || path == "trivy.exe" {
                Command::new(&path)
                    .arg("--help")
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .await
                    .is_ok()
            } else if path.ends_with("wazuh-agent.exe") {
                std::path::Path::new(&path).exists()
                    || std::path::Path::new(&path.replace("wazuh-agent.exe", "ossec-agent.exe"))
                        .exists()
                    || Command::new("sc")
                        .args(["query", "WazuhSvc"])
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .status()
                        .await
                        .map_or(false, |s| s.success())
            } else {
                std::path::Path::new(&path).exists()
            }
        };

        results.push(ComponentStatus {
            name,
            installed,
            version: None, // Can implement version extraction via commands later
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

    std::fs::write(&path, logs).map_err(|e| e.to_string())?;
    Ok(path.to_string_lossy().to_string())
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
            is_root,
            get_platform,
            verify_sudo,
            run_install,
            run_enroll,
            check_components,
            save_logs
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
