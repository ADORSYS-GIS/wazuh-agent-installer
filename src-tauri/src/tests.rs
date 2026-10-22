use super::*;

#[test]
fn test_app_config_default() {
    let config = AppConfig::default();
    assert_eq!(config.wazuh_manager_url, "manager.wazuh.adorsys.team");
    assert_eq!(
        config.wazuh_oauth_issuer,
        "https://login.wazuh.adorsys.team/realms/adorsys"
    );
    assert_eq!(
        config.wazuh_cert_endpoint,
        "https://cert.wazuh.adorsys.team/api/register-agent"
    );
    assert_eq!(
        config.netbird_management_url,
        "https://netbird.guard.adorsys.com"
    );
}

#[test]
fn test_app_config_serialization() {
    let config = AppConfig::default();
    let json = serde_json::to_string(&config).unwrap();
    let deserialized: AppConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.wazuh_manager_url, config.wazuh_manager_url);
}

#[test]
fn test_install_config_serialization() {
    let config = InstallConfig {
        wazuh_manager: "wazuh.local".to_string(),
        wazuh_agent_name: "test-agent".to_string(),
        log_level: "debug".to_string(),
        ids_engine: "suricata".to_string(),
        suricata_mode: "ips".to_string(),
        install_netbird: true,
        oauth_issuer: "https://auth.local".to_string(),
        cert_endpoint: "https://cert.local".to_string(),
    };
    let json = serde_json::to_string(&config).unwrap();
    let deserialized: InstallConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.wazuh_manager, "wazuh.local");
    assert!(deserialized.install_netbird);
}

#[test]
fn test_parse_version() {
    assert_eq!(parse_version("1.2.3"), Some((1, 2, 3)));
    assert_eq!(parse_version("v1.2.3"), Some((1, 2, 3)));
    assert_eq!(parse_version("v2.1"), Some((2, 1, 0)));
    assert_eq!(parse_version("3"), Some((3, 0, 0)));
    assert_eq!(parse_version("v1.2.3-rc.1"), Some((1, 2, 3)));
    assert_eq!(parse_version("   v4.5.6   "), Some((4, 5, 6)));
    assert_eq!(parse_version("1.abc"), Some((1, 0, 0)));
    assert_eq!(parse_version("1.2.xyz"), Some((1, 2, 0)));
    assert_eq!(parse_version("invalid"), None);
    assert_eq!(parse_version(""), None);
    assert_eq!(parse_version("v"), None);
}

#[test]
fn test_parse_curl_version_output() {
    let fail_output = std::process::Command::new("false").output().unwrap();
    assert_eq!(parse_curl_version_output(&fail_output), None);

    let empty_output = std::process::Command::new("echo")
        .arg("-n")
        .output()
        .unwrap();
    assert_eq!(parse_curl_version_output(&empty_output), None);

    let ok_output = std::process::Command::new("echo")
        .arg("1.2.3")
        .output()
        .unwrap();
    assert_eq!(
        parse_curl_version_output(&ok_output),
        Some("1.2.3".to_string())
    );
}

#[test]
fn test_parse_yara_version() {
    assert_eq!(
        parse_yara_version("4.3.2\nCopyright 2023"),
        Some("4.3.2".to_string())
    );
    assert_eq!(parse_yara_version("  4.2.0  "), Some("4.2.0".to_string()));
    assert_eq!(parse_yara_version(""), Some("".to_string()));
}

#[test]
fn test_parse_suricata_version() {
    assert_eq!(
        parse_suricata_version("This is Suricata version 7.0.2 RELEASE"),
        Some("7.0.2".to_string())
    );
    assert_eq!(
        parse_suricata_version("suricata 6.0.10"),
        Some("6.0.10".to_string())
    );
    assert_eq!(
        parse_suricata_version("suricata version 7.0.0-dev"),
        Some("7.0.0-dev".to_string())
    );
    assert_eq!(
        parse_suricata_version("version --- suricata 6.0.2"),
        Some("6.0.2".to_string())
    );
    assert_eq!(
        parse_suricata_version("suricata ---"),
        Some("suricata ---".to_string())
    );
    assert_eq!(
        parse_suricata_version("Unknown scanner 1.0"),
        Some("Unknown scanner 1.0".to_string())
    );
}

#[test]
fn test_parse_wazuh_agent_version() {
    assert_eq!(
        parse_wazuh_agent_version("WAZUH_VERSION=\"v4.8.0\"\nWAZUH_REVISION=\"123\""),
        Some("v4.8.0".to_string())
    );
    assert_eq!(
        parse_wazuh_agent_version("Wazuh v4.7.2 (installed)"),
        Some("4.7.2".to_string())
    );
    assert_eq!(parse_wazuh_agent_version("Wazuh v"), Some("".to_string()));
    #[cfg(not(windows))]
    assert_eq!(parse_wazuh_agent_version("WAZUH_VERSION=\"unclosed"), None);
    #[cfg(not(windows))]
    assert_eq!(parse_wazuh_agent_version("No match"), None);
    #[cfg(windows)]
    assert_eq!(
        parse_wazuh_agent_version("Some Windows output"),
        Some("Some Windows output".to_string())
    );
}

#[test]
fn test_parse_netbird_version() {
    assert_eq!(
        parse_netbird_version("0.26.1\ncommit hash: abc"),
        Some("0.26.1".to_string())
    );
    assert_eq!(
        parse_netbird_version("  0.25.0  "),
        Some("0.25.0".to_string())
    );
    assert_eq!(parse_netbird_version(""), None);
    assert_eq!(parse_netbird_version("   \n   "), None);
}

#[test]
fn test_parse_default_version() {
    assert_eq!(
        parse_default_version("Tool version 2.34.1"),
        Some("2.34.1".to_string())
    );
    assert_eq!(
        parse_default_version("Release 1.0 (2024-01-01)"),
        Some("1.0".to_string())
    );
    assert_eq!(
        parse_default_version("Tool 2024-01-01 /path/to/bin.1.0 3.2.1"),
        Some("3.2.1".to_string())
    );
    assert_eq!(
        parse_default_version(r"Tool C:\Program.Files\app 4.5.6"),
        Some("4.5.6".to_string())
    );
    assert_eq!(
        parse_default_version("Tool /path/to/bin.1.0"),
        Some("Tool /path/to/bin.1.0".to_string())
    );
    assert_eq!(parse_default_version("no numbers here"), None);
    assert_eq!(parse_default_version(""), None);
}

#[test]
fn test_parse_component_version() {
    assert_eq!(
        parse_component_version("YARA", "4.3.0\n"),
        Some("4.3.0".to_string())
    );
    assert_eq!(
        parse_component_version("Suricata", "Suricata version 7.0.1"),
        Some("7.0.1".to_string())
    );
    assert_eq!(
        parse_component_version("Wazuh Agent", "WAZUH_VERSION=\"4.8.1\""),
        Some("4.8.1".to_string())
    );
    assert_eq!(
        parse_component_version("NetBird", "0.27.0"),
        Some("0.27.0".to_string())
    );
    assert_eq!(
        parse_component_version("Other", "Utility 5.6.7"),
        Some("5.6.7".to_string())
    );
}

#[test]
fn test_classify_line() {
    assert_eq!(classify_line("Installation [ERROR] failed"), "error");
    assert_eq!(classify_line("error: missing dependency"), "error");
    assert_eq!(classify_line("bash: command not found"), "error");
    assert_eq!(classify_line("Task completed [SUCCESS]"), "success");
    assert_eq!(classify_line("Agent installed successfully"), "success");
    assert_eq!(classify_line("All steps completed"), "success");
    assert_eq!(classify_line("Downloading package 45%"), "info");
}

#[test]
fn test_is_safe_url() {
    assert!(is_safe_url("https://adorsys.com"));
    assert!(is_safe_url(
        "https://login.wazuh.adorsys.team/auth?code=123"
    ));
    assert!(is_safe_url("http://localhost:8080/register"));
    assert!(!is_safe_url("ftp://malicious.com"));
    assert!(!is_safe_url("javascript:alert(1)"));
    assert!(!is_safe_url("https://example.com/has space"));
    assert!(!is_safe_url("https://example.com\nnew-arg"));
    assert!(!is_safe_url(""));
}

#[test]
fn test_parse_enrollment_agent_name() {
    let content = "001 agent-charlie 192.168.1.100 89abcdef\n";
    assert_eq!(
        parse_enrollment_agent_name(content),
        Some("agent-charlie".to_string())
    );

    let multi_line = "\n\n002 prod-worker 10.0.0.5 token123\n";
    assert_eq!(
        parse_enrollment_agent_name(multi_line),
        Some("prod-worker".to_string())
    );

    assert_eq!(parse_enrollment_agent_name(""), None);
    assert_eq!(parse_enrollment_agent_name("single_word"), None);
}

#[test]
fn test_parse_enrollment_manager() {
    let xml = "
<ossec_config>
  <client>
    <server>
      <address>wazuh-manager.adorsys.team</address>
      <port>1514</port>
    </server>
  </client>
</ossec_config>";
    assert_eq!(
        parse_enrollment_manager(xml),
        Some("wazuh-manager.adorsys.team".to_string())
    );

    let invalid = "<ossec_config><no_address>none</no_address></ossec_config>";
    assert_eq!(parse_enrollment_manager(invalid), None);
    assert_eq!(parse_enrollment_manager("<address>unclosed"), None);
}

#[test]
fn test_build_netbird_up_command() {
    let cmd = build_netbird_up_command("key-12345", "https://netbird.custom.com");
    let debug = format!("{:?}", cmd);
    assert!(debug.contains("netbird"));
    assert!(debug.contains("https://netbird.custom.com"));
    assert!(debug.contains("key-12345"));

    // Default management URL fallback
    let default_cmd = build_netbird_up_command("", "");
    let default_debug = format!("{:?}", default_cmd);
    assert!(default_debug.contains("https://api.netbird.io:443"));
}

#[test]
fn test_build_enroll_command() {
    let cmd = build_enroll_command("https://issuer.com", "https://cert.com", true);
    let debug = format!("{:?}", cmd);
    assert!(debug.contains("o-auth2"));
    assert!(debug.contains("--issuer"));
    assert!(debug.contains("https://issuer.com"));
    assert!(debug.contains("--endpoint"));
    assert!(debug.contains("https://cert.com"));
    assert!(debug.contains("--overwrite"));

    let no_overwrite_cmd = build_enroll_command("https://issuer.com", "https://cert.com", false);
    let no_overwrite_debug = format!("{:?}", no_overwrite_cmd);
    assert!(!no_overwrite_debug.contains("--overwrite"));
}

#[test]
fn test_build_install_command() {
    let config = InstallConfig {
        wazuh_manager: "mgr.wazuh.team".to_string(),
        wazuh_agent_name: "test-node".to_string(),
        log_level: "info".to_string(),
        ids_engine: "suricata".to_string(),
        suricata_mode: "ids".to_string(),
        install_netbird: true,
        oauth_issuer: "https://issuer.com".to_string(),
        cert_endpoint: "https://cert.com".to_string(),
    };
    let cmd = build_install_command(&config, "/path/to/install.sh");
    let debug = format!("{:?}", cmd);
    #[cfg(not(target_os = "windows"))]
    {
        assert!(debug.contains("bash"));
        assert!(debug.contains("-b"));
    }
    #[cfg(target_os = "windows")]
    {
        assert!(debug.contains("powershell"));
        assert!(debug.contains("-InstallNetBird"));
    }
}

#[test]
fn test_get_platform() {
    let platform = get_platform();
    assert!(!platform.is_empty());
    assert_eq!(platform, std::env::consts::OS);
}

#[tokio::test]
async fn test_save_logs_invalid_prefix() {
    assert!(save_logs("some logs".into(), "".into()).await.is_err());
    assert!(save_logs("some logs".into(), "../bad".into())
        .await
        .is_err());
    assert!(save_logs("some logs".into(), "invalid space".into())
        .await
        .is_err());
    assert!(save_logs("some logs".into(), "inv@lid!".into())
        .await
        .is_err());
}

#[tokio::test]
async fn test_save_logs_valid_prefix() {
    let logs_content = "2026-10-21 Log line 1\n2026-10-21 Log line 2";
    let prefix = "test_valid_logs";
    let res = save_logs(logs_content.into(), prefix.into()).await;
    if let Ok(file_path) = res {
        assert!(std::path::Path::new(&file_path).exists());
        let read_back = tokio::fs::read_to_string(&file_path).await.unwrap();
        assert_eq!(read_back, logs_content);
        let _ = tokio::fs::remove_file(file_path).await;
    }
}

#[test]
fn test_classify_line_comprehensive() {
    assert_eq!(classify_line("ERROR: Process terminated"), "error");
    assert_eq!(classify_line("[ERROR] Fatal error occurred"), "error");
    assert_eq!(classify_line("Download failed completely"), "error");
    assert_eq!(classify_line("zsh: command not found: yara"), "error");
    assert_eq!(classify_line("Operation [SUCCESS] finished"), "success");
    assert_eq!(classify_line("Package installed successfully"), "success");
    assert_eq!(
        classify_line("Installation completed without errors"),
        "success"
    );
    assert_eq!(classify_line("Normal informational log output"), "info");
    assert_eq!(classify_line(""), "info");
}

#[tokio::test]
async fn test_get_enroll_line_processor() {
    let notify = std::sync::Arc::new(tokio::sync::Notify::new());
    let mut processor = get_enroll_line_processor(notify.clone());

    // Line without done should not notify
    processor("Processing certificate request...");

    // Line with ] Done! should notify
    processor("[Step 5/5] Done!");
    let notified =
        tokio::time::timeout(std::time::Duration::from_millis(50), notify.notified()).await;
    assert!(notified.is_ok());

    // Line with exact "Done!" should notify
    processor("Done!");
    let notified2 =
        tokio::time::timeout(std::time::Duration::from_millis(50), notify.notified()).await;
    assert!(notified2.is_ok());
}

#[tokio::test]
async fn test_get_netbird_line_processor() {
    let notify = std::sync::Arc::new(tokio::sync::Notify::new());
    let mut processor = get_netbird_line_processor(notify.clone());

    // Disconnected line should not trigger
    processor("Disconnected from peer");

    // Connected line should notify
    processor("Connected to NetBird management service");
    let notified =
        tokio::time::timeout(std::time::Duration::from_millis(50), notify.notified()).await;
    assert!(notified.is_ok());
}

#[cfg(unix)]
#[test]
fn test_check_component_unix() {
    let (found, _) = check_component_unix("Other", "/bin/sh");
    assert!(found);

    let (not_found, _) = check_component_unix("Other", "/tmp/non_existent_binary_xyz_123");
    assert!(!not_found);

    let (netbird_res, _) = check_component_unix("NetBird", "/bin/sh");
    assert!(netbird_res);

    let (suricata_res, _) = check_component_unix("Suricata", "/bin/sh");
    assert!(suricata_res);
}

#[test]
fn test_create_command() {
    let cmd = create_command("echo");
    let debug = format!("{:?}", cmd);
    assert!(debug.contains("echo"));
}

#[tokio::test]
async fn test_get_component_version_async() {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let tmp_script =
            std::env::temp_dir().join(format!("mock-tool-{}-{nanos}.sh", std::process::id()));
        let script_content = r#"#!/bin/sh
if [ "$1" = "-V" ]; then
    echo "Suricata 7.0.3"
elif [ "$1" = "--version" ]; then
    echo "yara 4.5.2"
elif [ "$1" = "version" ]; then
    echo "0.28.3"
elif [ "$1" = "info" ]; then
    echo 'WAZUH_VERSION="4.8.0"'
fi
"#;
        {
            use std::io::Write;
            let mut file = std::fs::File::create(&tmp_script).unwrap();
            file.write_all(script_content.as_bytes()).unwrap();
            file.sync_all().unwrap();
        }
        let mut perms = std::fs::metadata(&tmp_script).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&tmp_script, perms).unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let script_path = tmp_script.to_string_lossy().to_string();

        let suricata_ver = get_component_version("Suricata", &script_path).await;
        assert_eq!(suricata_ver, Some("7.0.3".to_string()));

        let yara_ver = get_component_version("YARA", &script_path).await;
        assert_eq!(yara_ver, Some("yara 4.5.2".to_string()));

        let netbird_ver = get_component_version("NetBird", &script_path).await;
        assert_eq!(netbird_ver, Some("0.28.3".to_string()));

        let other_ver = get_component_version("CustomTool", &script_path).await;
        assert_eq!(other_ver, Some("4.5.2".to_string()));

        let tmp_dir = tmp_script.parent().unwrap();
        let wazuh_control = tmp_dir.join(format!("mock-wazuh-control-{nanos}.sh"));
        {
            use std::io::Write;
            let mut file = std::fs::File::create(&wazuh_control).unwrap();
            file.write_all(script_content.as_bytes()).unwrap();
            file.sync_all().unwrap();
        }
        let mut ctrl_perms = std::fs::metadata(&wazuh_control).unwrap().permissions();
        ctrl_perms.set_mode(0o755);
        std::fs::set_permissions(&wazuh_control, ctrl_perms).unwrap();

        let fake_agentd = wazuh_control
            .to_string_lossy()
            .to_string()
            .replace("wazuh-control", "wazuh-agentd");
        let wazuh_ver = get_component_version("Wazuh Agent", &fake_agentd).await;
        assert_eq!(wazuh_ver, Some("4.8.0".to_string()));

        let fake_ossec = wazuh_control
            .to_string_lossy()
            .to_string()
            .replace("wazuh-control", "ossec-agentd");
        let ossec_ver = get_component_version("Wazuh Agent", &fake_ossec).await;
        assert_eq!(ossec_ver, Some("4.8.0".to_string()));

        let _ = std::fs::remove_file(wazuh_control);

        let none_ver = get_component_version("Suricata", "/tmp/non_existent_mock_file").await;
        assert_eq!(none_ver, None);

        let _ = std::fs::remove_file(tmp_script);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn test_try_lock_at_temp_path() {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp_lock =
        std::env::temp_dir().join(format!("test-lock-{}-{nanos}.lock", std::process::id()));
    let tmp_lock_str = tmp_lock.to_string_lossy();

    if let Some(fd) = try_lock_at_path(&tmp_lock_str) {
        let second_lock = try_lock_at_path(&tmp_lock_str);
        assert!(second_lock.is_none());
        unsafe { libc::close(fd) };
    }
    let _ = std::fs::remove_file(&tmp_lock);
}

#[cfg(unix)]
#[test]
fn test_pre_create_config_unix() {
    // Empty home does nothing
    pre_create_config_at_home("");

    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp_home = std::env::temp_dir().join(format!("test-home-{}-{nanos}", std::process::id()));
    let _ = std::fs::create_dir_all(&tmp_home);

    let home_str = tmp_home.to_string_lossy();
    pre_create_config_at_home(&home_str);

    let cfg_file = tmp_home.join(".config/com.adorsys.wazuh-agent-installer/config.json");
    assert!(cfg_file.exists());

    // Calling again when config.json exists exercises the already-exists branch
    pre_create_config_at_home(&home_str);

    let content = std::fs::read_to_string(&cfg_file).unwrap();
    let parsed: Result<AppConfig, _> = serde_json::from_str(&content);
    assert!(parsed.is_ok());

    let _ = std::fs::remove_dir_all(&tmp_home);
}

#[test]
fn test_struct_representations() {
    let log = LogLine {
        line: "Started install".to_string(),
        level: "info".to_string(),
    };
    let serialized_log = serde_json::to_string(&log).unwrap();
    assert!(serialized_log.contains("Started install"));

    let res = InstallResult {
        success: true,
        exit_code: 0,
        message: "Setup done".to_string(),
    };
    let serialized = serde_json::to_string(&res).unwrap();
    assert!(serialized.contains("Setup done"));
    assert!(serialized.contains("\"exit_code\":0"));

    let status = ComponentStatus {
        name: "YARA".to_string(),
        installed: true,
        version: Some("4.5.4".to_string()),
        path: "/usr/local/bin/yara".to_string(),
    };
    let status_json = serde_json::to_string(&status).unwrap();
    assert!(status_json.contains("YARA"));
    assert!(status_json.contains("/usr/local/bin/yara"));

    let netbird_state = NetbirdState {
        daemon_status: Some("Connected".to_string()),
        netbird_ip: Some("100.64.0.1".to_string()),
        management_connected: true,
    };
    let nb_json = serde_json::to_string(&netbird_state).unwrap();
    assert!(nb_json.contains("100.64.0.1"));
    assert!(nb_json.contains("Connected"));

    let enroll_state = EnrollmentState {
        enrolled: true,
        agent_name: Some("test-agent".to_string()),
        manager: Some("manager.wazuh.team".to_string()),
    };
    let enroll_json = serde_json::to_string(&enroll_state).unwrap();
    assert!(enroll_json.contains("test-agent"));
    assert!(enroll_json.contains("manager.wazuh.team"));

    let update_info = UpdateInfo {
        update_available: true,
        latest_version: Some("1.1.0".to_string()),
    };
    let update_json = serde_json::to_string(&update_info).unwrap();
    assert!(update_json.contains("1.1.0"));
    assert!(update_json.contains("true"));
}

#[test]
fn test_is_root_matches_euid() {
    #[cfg(unix)]
    {
        let expected = unsafe { libc::geteuid() == 0 };
        assert_eq!(is_root(), expected);
    }
}

#[cfg(unix)]
#[test]
fn test_launcher_args_and_checker_mode() {
    let args = get_launcher_args();
    assert_eq!(args, get_launcher_args_from(std::env::args().skip(1)));

    let checker = is_checker_mode();
    assert_eq!(checker, std::env::args().any(|a| a == "--check-updates"));
}

#[test]
fn test_build_install_command_without_netbird() {
    let config = InstallConfig {
        wazuh_manager: "127.0.0.1".to_string(),
        wazuh_agent_name: "node-1".to_string(),
        log_level: "debug".to_string(),
        ids_engine: "none".to_string(),
        suricata_mode: "ips".to_string(),
        install_netbird: false,
        oauth_issuer: "".to_string(),
        cert_endpoint: "".to_string(),
    };
    let cmd = build_install_command(&config, "/opt/script.sh");
    let debug = format!("{:?}", cmd);
    #[cfg(not(target_os = "windows"))]
    {
        assert!(!debug.contains(" -b"));
    }
    #[cfg(target_os = "windows")]
    {
        assert!(!debug.contains("-InstallNetBird"));
    }
}

#[tokio::test]
async fn test_check_enrollment_execution() {
    let state = check_enrollment().await;
    assert!(state.is_ok());
}

#[tokio::test]
async fn test_check_enrollment_at_paths() {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp_dir =
        std::env::temp_dir().join(format!("test-enroll-paths-{}-{nanos}", std::process::id()));
    let _ = std::fs::create_dir_all(&tmp_dir);

    let keys_path = tmp_dir.join("client.keys");
    let conf_path = tmp_dir.join("ossec.conf");

    // With valid client.keys and ossec.conf
    std::fs::write(&keys_path, "001 agent-linux-01 any 123456789\n").unwrap();
    let conf_xml = "<ossec_config>\n  <client>\n    <server>\n      <address>mgr.local</address>\n    </server>\n  </client>\n</ossec_config>";
    std::fs::write(&conf_path, conf_xml).unwrap();

    let state = check_enrollment_at_paths(&keys_path, &conf_path).await;
    assert!(state.enrolled);
    assert_eq!(state.agent_name, Some("agent-linux-01".to_string()));
    assert_eq!(state.manager, Some("mgr.local".to_string()));

    // With non-existent paths
    let state_none = check_enrollment_at_paths(
        tmp_dir.join("nonexistent.keys"),
        tmp_dir.join("nonexistent.conf"),
    )
    .await;
    assert!(!state_none.enrolled);

    let _ = std::fs::remove_dir_all(&tmp_dir);
}

#[cfg(unix)]
#[test]
fn test_check_components_helpers_unix() {
    let (found, path) = check_netbird_unix("/bin/sh");
    assert!(found);
    assert_eq!(path, "/bin/sh");

    let (not_found, _) = check_netbird_unix("/non_existent_path_xyz_123");
    let _ = not_found;

    let (s_found, s_path) = check_suricata_unix("/bin/sh");
    assert!(s_found);
    assert_eq!(s_path, "/bin/sh");

    let (s_not_found, _) = check_suricata_unix("/non_existent_suricata_path");
    let _ = s_not_found;

    let fallback = fallback_netbird_cmd_unix();
    let _ = fallback;
}

#[test]
fn test_open_browser_unsafe_noop() {
    // Unsafe URLs must be immediately rejected and should never spawn any external browser process
    open_browser("ftp://unsafe.com");
    open_browser("javascript:alert(1)");
    open_browser("   ");
}

#[test]
fn test_get_parent_pid_from_args() {
    #[cfg(unix)]
    {
        let pid = get_parent_pid_from_args();
        assert_eq!(pid, None);
    }
}

#[tokio::test]
async fn test_get_enroll_line_processor_url_detection() {
    let notify = std::sync::Arc::new(tokio::sync::Notify::new());
    let mut processor = get_enroll_line_processor(notify.clone());

    processor("Navigate to https://auth.company.com/realms/corp/device to authenticate");
    processor("https://auth.company.com/realms/corp/direct");
}

#[test]
fn test_evaluate_update_available() {
    // Newer version available
    let info = evaluate_update_available("1.2.0", Some("1.3.0"));
    assert!(info.update_available);
    assert_eq!(info.latest_version, Some("1.3.0".to_string()));

    // Same version
    let info_same = evaluate_update_available("1.2.0", Some("1.2.0"));
    assert!(!info_same.update_available);

    // Older version
    let info_old = evaluate_update_available("1.2.0", Some("1.1.0"));
    assert!(!info_old.update_available);

    // No latest version
    let info_none = evaluate_update_available("1.2.0", None);
    assert!(!info_none.update_available);
    assert_eq!(info_none.latest_version, None);

    // Invalid semver strings
    let info_invalid = evaluate_update_available("not-a-ver", Some("1.3.0"));
    assert!(!info_invalid.update_available);
}

#[test]
fn test_get_local_version_at_path() {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp_dir = std::env::temp_dir().join(format!("test-ver-{}-{nanos}", std::process::id()));
    let _ = std::fs::create_dir_all(&tmp_dir);

    // Empty directory falls back to CARGO_PKG_VERSION
    assert_eq!(
        get_local_version_at_path(&tmp_dir),
        env!("CARGO_PKG_VERSION")
    );

    // File with valid version string
    let ver_file = tmp_dir.join("version.txt");
    let _ = std::fs::write(&ver_file, "2.4.6\n");
    assert_eq!(get_local_version_at_path(&tmp_dir), "2.4.6");

    // File with empty string falls back to CARGO_PKG_VERSION
    let _ = std::fs::write(&ver_file, "   \n");
    assert_eq!(
        get_local_version_at_path(&tmp_dir),
        env!("CARGO_PKG_VERSION")
    );

    let _ = std::fs::remove_dir_all(&tmp_dir);
}

#[test]
fn test_init_config_dir_at_path() {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp_dir = std::env::temp_dir().join(format!("test-init-{}-{nanos}", std::process::id()));

    // Initializes missing directory, config.json and version.txt
    init_config_dir_at_path(&tmp_dir);
    assert!(tmp_dir.join("config.json").exists());
    assert!(tmp_dir.join("version.txt").exists());

    // Existing older version is upgraded to CARGO_PKG_VERSION
    let _ = std::fs::write(tmp_dir.join("version.txt"), "0.0.1");
    init_config_dir_at_path(&tmp_dir);
    let updated_ver = std::fs::read_to_string(tmp_dir.join("version.txt")).unwrap();
    assert_eq!(updated_ver.trim(), env!("CARGO_PKG_VERSION"));

    // Existing newer version is kept
    let _ = std::fs::write(tmp_dir.join("version.txt"), "99.0.0");
    init_config_dir_at_path(&tmp_dir);
    let kept_ver = std::fs::read_to_string(tmp_dir.join("version.txt")).unwrap();
    assert_eq!(kept_ver.trim(), "99.0.0");

    let _ = std::fs::remove_dir_all(&tmp_dir);
}

#[test]
fn test_parse_netbird_status_json() {
    let json_ok =
        r#"{"daemonStatus":"Connected","netbirdIp":"100.64.0.1","management":{"connected":true}}"#;
    let state = parse_netbird_status_json(json_ok).unwrap();
    assert_eq!(state.daemon_status, Some("Connected".to_string()));
    assert_eq!(state.netbird_ip, Some("100.64.0.1".to_string()));
    assert!(state.management_connected);

    let json_empty_ip =
        r#"{"daemonStatus":"Connecting","netbirdIp":"","management":{"connected":false}}"#;
    let state_empty = parse_netbird_status_json(json_empty_ip).unwrap();
    assert_eq!(state_empty.daemon_status, Some("Connecting".to_string()));
    assert_eq!(state_empty.netbird_ip, None);
    assert!(!state_empty.management_connected);

    let json_invalid = "not-json";
    assert!(parse_netbird_status_json(json_invalid).is_err());
}

#[test]
fn test_parse_enrollment_from_content() {
    let keys = "001 test-agent 192.168.1.100 a1b2c3d4";
    let conf = "<ossec_config>\n  <server>\n    <address>wazuh.corp.com</address>\n  </server>\n</ossec_config>";

    let enrolled = parse_enrollment_from_content(keys, Some(conf));
    assert!(enrolled.enrolled);
    assert_eq!(enrolled.agent_name, Some("test-agent".to_string()));
    assert_eq!(enrolled.manager, Some("wazuh.corp.com".to_string()));

    let keys_no_manager = "002 second-agent 192.168.1.101 e5f6";
    let enrolled_no_mgr = parse_enrollment_from_content(keys_no_manager, None);
    assert!(enrolled_no_mgr.enrolled);
    assert_eq!(enrolled_no_mgr.agent_name, Some("second-agent".to_string()));
    assert_eq!(enrolled_no_mgr.manager, None);

    let empty_keys = "";
    let not_enrolled = parse_enrollment_from_content(empty_keys, Some(conf));
    assert!(!not_enrolled.enrolled);
    assert_eq!(not_enrolled.agent_name, None);
    assert_eq!(not_enrolled.manager, None);
}

#[test]
fn test_parse_app_config_from_str() {
    let valid = r#"{
            "wazuh_manager_url": "custom.mgr.org",
            "wazuh_oauth_issuer": "https://custom.issuer",
            "wazuh_cert_endpoint": "https://custom.cert",
            "netbird_management_url": "https://custom.netbird"
        }"#;
    let cfg = parse_app_config_from_str(valid);
    assert_eq!(cfg.wazuh_manager_url, "custom.mgr.org");
    assert_eq!(cfg.wazuh_oauth_issuer, "https://custom.issuer");

    let invalid = "invalid json {}";
    let fallback = parse_app_config_from_str(invalid);
    assert_eq!(
        fallback.wazuh_manager_url,
        AppConfig::default().wazuh_manager_url
    );
}

#[cfg(unix)]
#[test]
fn test_make_script_executable_unix() {
    use std::os::unix::fs::PermissionsExt;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp_file =
        std::env::temp_dir().join(format!("test-script-{}-{nanos}.sh", std::process::id()));

    // 1. When non-executable: copies to temp with 0700 permissions
    let _ = std::fs::write(&tmp_file, "#!/bin/sh\necho ok\n");
    let mut perms = std::fs::metadata(&tmp_file).unwrap().permissions();
    perms.set_mode(0o600);
    let _ = std::fs::set_permissions(&tmp_file, perms);

    let resolved = make_script_executable_unix(&tmp_file).unwrap();
    assert!(resolved.ends_with(".sh"));
    assert!(std::path::Path::new(&resolved).exists());
    let _ = std::fs::remove_file(&resolved);

    // 2. When already executable: returns in-place path
    let mut perms = std::fs::metadata(&tmp_file).unwrap().permissions();
    perms.set_mode(0o755);
    let _ = std::fs::set_permissions(&tmp_file, perms);
    let resolved_inplace = make_script_executable_unix(&tmp_file).unwrap();
    assert_eq!(resolved_inplace, tmp_file.to_str().unwrap());

    // 3. Non-existent file errors
    let non_existent = std::path::Path::new("/tmp/does_not_exist_xyz_999");
    assert!(make_script_executable_unix(non_existent).is_err());

    let _ = std::fs::remove_file(&tmp_file);
}

#[test]
fn test_check_is_checker_mode() {
    assert!(check_is_checker_mode(["--check-updates"]));
    assert!(check_is_checker_mode(["foo", "--check-updates", "bar"]));
    assert!(!check_is_checker_mode(["--install", "--other"]));
    assert!(!check_is_checker_mode(Vec::<String>::new()));
}

#[test]
fn test_get_launcher_args_from() {
    let args = vec![
        "--parent-pid".to_string(),
        "12345".to_string(),
        "--keep-this".to_string(),
        "--also-this".to_string(),
    ];
    let filtered = get_launcher_args_from(args);
    assert_eq!(filtered, vec!["--keep-this", "--also-this"]);
}

#[test]
fn test_parse_gtk_theme() {
    assert_eq!(
        parse_gtk_theme("'Yaru-dark'"),
        Some("Yaru-dark".to_string())
    );
    assert_eq!(parse_gtk_theme("Adwaita\n"), Some("Adwaita".to_string()));
    assert_eq!(parse_gtk_theme("   ''   "), None);
    assert_eq!(parse_gtk_theme(""), None);
}

#[cfg(target_os = "linux")]
#[test]
fn test_notify_update_linux() {
    notify_update_linux("1.2.0");
}

#[test]
fn test_get_update_script_name_for_os() {
    assert_eq!(get_update_script_name_for_os("windows"), "windows.ps1");
    assert_eq!(get_update_script_name_for_os("macos"), "macos.sh");
    assert_eq!(get_update_script_name_for_os("linux"), "ubuntu.sh");
    assert_eq!(get_update_script_name_for_os("freebsd"), "ubuntu.sh");

    let current_script = get_update_script_name();
    assert!(!current_script.is_empty());
}

#[test]
fn test_build_app_update_command() {
    let cmd = build_app_update_command("/tmp/sample_updater.sh");
    let debug = format!("{:?}", cmd);
    #[cfg(target_os = "windows")]
    {
        assert!(debug.contains("powershell"));
        assert!(debug.contains("sample_updater.sh"));
    }
    #[cfg(not(target_os = "windows"))]
    {
        assert!(debug.contains("bash"));
        assert!(debug.contains("sample_updater.sh"));
    }
}

#[tokio::test]
async fn test_read_log_lines() {
    use std::sync::{Arc, Mutex};
    let input =
        "hello world\n\n[error] something went wrong\n   \n[success] all done\nfinal info line\n";
    let cursor = std::io::Cursor::new(input.as_bytes());

    let lines = Arc::new(Mutex::new(Vec::new()));
    let levels = Arc::new(Mutex::new(Vec::new()));

    let l_clone = lines.clone();
    let lev_clone = levels.clone();
    read_log_lines(cursor, move |raw, log_line| {
        l_clone.lock().unwrap().push(raw.to_string());
        lev_clone.lock().unwrap().push(log_line.level);
    })
    .await;

    let collected_lines = lines.lock().unwrap().clone();
    let collected_levels = levels.lock().unwrap().clone();

    assert_eq!(collected_lines.len(), 4);
    assert_eq!(collected_lines[0], "hello world");
    assert_eq!(collected_lines[1], "[error] something went wrong");
    assert_eq!(collected_lines[2], "[success] all done");
    assert_eq!(collected_lines[3], "final info line");

    assert_eq!(collected_levels, vec!["info", "error", "success", "info"]);
}

#[test]
fn test_get_install_line_processor() {
    let (tx, mut rx) = tokio::sync::mpsc::channel(1);
    let mut processor = get_install_line_processor(tx);

    processor("Some regular log line");
    assert!(rx.try_recv().is_err());

    processor("Wazuh setup has been completed successfully!");
    assert_eq!(rx.try_recv().ok(), Some(true));
}

#[tokio::test]
async fn test_wait_for_process_or_rx() {
    // 1. Process exits naturally with 0
    let child_ok = Command::new("true").spawn().unwrap();
    let (_tx, rx) = tokio::sync::mpsc::channel(1);
    let res_ok = wait_for_process_or_rx(child_ok, rx, "Success", "Failed")
        .await
        .unwrap();
    assert!(res_ok.success);
    assert_eq!(res_ok.exit_code, 0);
    assert_eq!(res_ok.message, "Success");

    // 2. Process exits naturally with failure
    let child_fail = Command::new("false").spawn().unwrap();
    let (_tx2, rx2) = tokio::sync::mpsc::channel(1);
    let res_fail = wait_for_process_or_rx(child_fail, rx2, "Success", "Failed")
        .await
        .unwrap();
    assert!(!res_fail.success);
    assert_ne!(res_fail.exit_code, 0);
    assert_eq!(res_fail.message, "Failed");

    // 3. Process is waiting, but rx signal arrives early
    let child_sleep = Command::new("sleep").arg("5").spawn().unwrap();
    let (tx3, rx3) = tokio::sync::mpsc::channel(1);
    let _ = tx3.send(true).await;
    let res_early = wait_for_process_or_rx(child_sleep, rx3, "Early OK", "Failed")
        .await
        .unwrap();
    assert!(res_early.success);
    assert_eq!(res_early.exit_code, 0);
    assert_eq!(res_early.message, "Early OK");
}

#[tokio::test]
async fn test_wait_for_process_or_notify() {
    use std::sync::Arc;

    // 1. Process exits naturally with 0
    let child_ok = Command::new("true").spawn().unwrap();
    let notify = Arc::new(tokio::sync::Notify::new());
    let res_ok = wait_for_process_or_notify(child_ok, notify.clone(), "Connected", "Failed")
        .await
        .unwrap();
    assert!(res_ok.success);
    assert_eq!(res_ok.exit_code, 0);
    assert_eq!(res_ok.message, "Connected");

    // 2. Process exits naturally with failure
    let child_fail = Command::new("false").spawn().unwrap();
    let res_fail = wait_for_process_or_notify(child_fail, notify.clone(), "Connected", "Failed")
        .await
        .unwrap();
    assert!(!res_fail.success);
    assert_ne!(res_fail.exit_code, 0);
    assert_eq!(res_fail.message, "Failed");

    // 3. Notify fires before child finishes
    let child_sleep = Command::new("sleep").arg("5").spawn().unwrap();
    let notify_early = Arc::new(tokio::sync::Notify::new());
    notify_early.notify_one();
    let res_early =
        wait_for_process_or_notify(child_sleep, notify_early, "Connected Early", "Failed")
            .await
            .unwrap();
    assert!(res_early.success);
    assert_eq!(res_early.exit_code, 0);
    assert_eq!(res_early.message, "Connected Early");
}

#[test]
fn test_check_path_candidates() {
    // Case 1: Primary path exists
    let (found, path) = check_path_candidates("/primary", &["/alt1", "/alt2"], |p| p == "/primary");
    assert!(found);
    assert_eq!(path, "/primary");

    // Case 2: Candidate path exists
    let (found_alt, path_alt) =
        check_path_candidates("/primary", &["/alt1", "/alt2"], |p| p == "/alt2");
    assert!(found_alt);
    assert_eq!(path_alt, "/alt2");

    // Case 3: Neither exists
    let (not_found, path_orig) = check_path_candidates("/primary", &["/alt1", "/alt2"], |_| false);
    assert!(!not_found);
    assert_eq!(path_orig, "/primary");
}

#[cfg(target_os = "linux")]
#[test]
fn test_build_pkexec_command() {
    let exe = std::path::PathBuf::from("/usr/bin/wazuh-agent-installer");
    let args = vec!["--arg1".to_string(), "--arg2".to_string()];

    // With GTK theme
    let cmd = build_pkexec_command(&exe, 9876, &args, Some("Adwaita"));
    let debug = format!("{:?}", cmd);
    assert!(debug.contains("pkexec"));
    assert!(debug.contains("GTK_THEME=Adwaita"));
    assert!(debug.contains("--parent-pid"));
    assert!(debug.contains("9876"));
    assert!(debug.contains("--arg1"));

    // Without GTK theme
    let cmd_no_theme = build_pkexec_command(&exe, 5432, &[], None);
    let debug_no_theme = format!("{:?}", cmd_no_theme);
    assert!(debug_no_theme.contains("pkexec"));
    assert!(!debug_no_theme.contains("GTK_THEME="));
    assert!(debug_no_theme.contains("5432"));
}

#[test]
fn test_should_notify_update() {
    assert!(should_notify_update("1.0.0", Some("1.2.0")));
    assert!(!should_notify_update("1.2.0", Some("1.0.0")));
    assert!(!should_notify_update("1.2.0", Some("1.2.0")));
    assert!(!should_notify_update("1.2.0", None));
}

#[test]
fn test_line_processors_extra_branches() {
    use std::sync::Arc;
    let enrolled = Arc::new(tokio::sync::Notify::new());
    let mut enroll_proc = get_enroll_line_processor(enrolled.clone());
    enroll_proc("Opened your default browser to: https://login.example.com");
    enroll_proc("Opened your default browser to:    ");
    enroll_proc("Done!");
    enroll_proc("[info] Done!");

    let connected = Arc::new(tokio::sync::Notify::new());
    let mut nb_proc = get_netbird_line_processor(connected.clone());
    nb_proc("https://netbird.example.com/realms/corp");
    nb_proc("Management: Connected");
    nb_proc("Status: Disconnected");
}

#[tokio::test]
async fn test_write_rx_logs_to_file() {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp_log =
        std::env::temp_dir().join(format!("test-rx-logs-{}-{nanos}.log", std::process::id()));

    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    tx.send("First line".to_string()).unwrap();
    tx.send("Second line".to_string()).unwrap();
    drop(tx);

    let res = write_rx_logs_to_file(&tmp_log, rx).await;
    assert!(res.is_ok());

    let content = std::fs::read_to_string(&tmp_log).unwrap();
    assert!(content.contains("First line\n"));
    assert!(content.contains("Second line\n"));

    let _ = std::fs::remove_file(&tmp_log);
}

#[test]
fn test_format_updater_exit_status() {
    let ok_status = std::process::Command::new("true").status().unwrap();
    let res_ok = format_updater_exit_status(ok_status);
    assert!(res_ok.is_ok());
    assert!(res_ok
        .unwrap()
        .contains("Update process exited with status:"));

    let fail_status = std::process::Command::new("false").status().unwrap();
    let res_fail = format_updater_exit_status(fail_status);
    assert!(res_fail.is_err());
    assert!(res_fail
        .unwrap_err()
        .contains("Updater failed with exit code:"));

    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        let sig_status = std::process::ExitStatus::from_raw(9);
        let res_sig = format_updater_exit_status(sig_status);
        assert!(res_sig.is_err());
        assert!(res_sig
            .unwrap_err()
            .contains("Updater failed with exit code: -1"));
    }
}

#[test]
fn test_get_install_script_name() {
    assert_eq!(get_install_script_name("windows"), "setup-agent.ps1");
    assert_eq!(get_install_script_name("linux"), "setup-agent.sh");
    assert_eq!(get_install_script_name("macos"), "setup-agent.sh");
}

#[test]
fn test_find_netbird_binary() {
    let path1 = find_netbird_binary(|p| p == "/usr/bin/netbird");
    assert_eq!(path1, Some("/usr/bin/netbird"));

    let path2 = find_netbird_binary(|p| p == "/usr/local/bin/netbird");
    assert_eq!(path2, Some("/usr/local/bin/netbird"));

    let path_none = find_netbird_binary(|_| false);
    assert_eq!(path_none, None);
}

#[test]
fn test_parse_netbird_cmd_output() {
    // Failure exit
    let fail_output = std::process::Command::new("false").output().unwrap();
    let fail_state = parse_netbird_cmd_output(&fail_output).unwrap();
    assert_eq!(fail_state.daemon_status, None);
    assert!(!fail_state.management_connected);

    // Success exit with valid JSON
    let ok_output = std::process::Command::new("echo")
        .arg(
            r#"{"daemonStatus":"Connected","netbirdIp":"100.64.0.9","management":{"connected":true}}"#,
        )
        .output()
        .unwrap();
    let ok_state = parse_netbird_cmd_output(&ok_output).unwrap();
    assert_eq!(ok_state.daemon_status, Some("Connected".to_string()));
    assert_eq!(ok_state.netbird_ip, Some("100.64.0.9".to_string()));
    assert!(ok_state.management_connected);
}

#[test]
fn test_is_valid_log_prefix_and_path() {
    assert!(is_valid_log_prefix("setup"));
    assert!(is_valid_log_prefix("agent-123_valid"));
    assert!(!is_valid_log_prefix(""));
    assert!(!is_valid_log_prefix("bad/prefix"));
    assert!(!is_valid_log_prefix("bad space"));
    assert!(!is_valid_log_prefix("bad.dot"));

    let path = get_log_save_path(std::path::Path::new("/tmp"), "custom");
    assert_eq!(path, std::path::PathBuf::from("/tmp/wazuh-custom-logs.txt"));
}

#[test]
fn test_get_app_config_at_path() {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp_dir =
        std::env::temp_dir().join(format!("test-cfg-path-{}-{nanos}", std::process::id()));
    let _ = std::fs::create_dir_all(&tmp_dir);

    // 1. Missing config.json falls back to default
    let cfg_default = get_app_config_at_path(&tmp_dir).unwrap();
    assert_eq!(
        cfg_default.wazuh_manager_url,
        AppConfig::default().wazuh_manager_url
    );

    // 2. Valid config.json is loaded
    let custom = r#"{"wazuh_manager_url":"mgr.custom.local","wazuh_oauth_issuer":"https://issuer","wazuh_cert_endpoint":"https://cert","netbird_management_url":"https://nb"}"#;
    std::fs::write(tmp_dir.join("config.json"), custom).unwrap();
    let cfg_custom = get_app_config_at_path(&tmp_dir).unwrap();
    assert_eq!(cfg_custom.wazuh_manager_url, "mgr.custom.local");

    // 3. Corrupted config.json falls back to default
    std::fs::write(tmp_dir.join("config.json"), "invalid json").unwrap();
    let cfg_corrupt = get_app_config_at_path(&tmp_dir).unwrap();
    assert_eq!(
        cfg_corrupt.wazuh_manager_url,
        AppConfig::default().wazuh_manager_url
    );

    // 4. config.json cannot be read (is a directory)
    let _ = std::fs::remove_file(tmp_dir.join("config.json"));
    let _ = std::fs::create_dir(tmp_dir.join("config.json"));
    assert!(get_app_config_at_path(&tmp_dir).is_err());

    let _ = std::fs::remove_dir_all(&tmp_dir);
}

#[test]
fn test_parse_tray_menu_action() {
    assert_eq!(parse_tray_menu_action("show"), TrayMenuAction::Show);
    assert_eq!(parse_tray_menu_action("quit"), TrayMenuAction::Quit);
    assert_eq!(parse_tray_menu_action("unknown"), TrayMenuAction::Unknown);
    assert_eq!(parse_tray_menu_action(""), TrayMenuAction::Unknown);
}

#[test]
fn test_should_toggle_window_on_tray_click() {
    let click_left_up = TrayIconEvent::Click {
        id: "tray".into(),
        position: tauri::PhysicalPosition { x: 100.0, y: 100.0 },
        rect: tauri::Rect {
            position: tauri::PhysicalPosition { x: 0, y: 0 }.into(),
            size: tauri::PhysicalSize {
                width: 10u32,
                height: 10u32,
            }
            .into(),
        },
        button: MouseButton::Left,
        button_state: MouseButtonState::Up,
    };
    assert!(should_toggle_window_on_tray_click(&click_left_up));

    let click_left_down = TrayIconEvent::Click {
        id: "tray".into(),
        position: tauri::PhysicalPosition { x: 100.0, y: 100.0 },
        rect: tauri::Rect {
            position: tauri::PhysicalPosition { x: 0, y: 0 }.into(),
            size: tauri::PhysicalSize {
                width: 10u32,
                height: 10u32,
            }
            .into(),
        },
        button: MouseButton::Left,
        button_state: MouseButtonState::Down,
    };
    assert!(!should_toggle_window_on_tray_click(&click_left_down));

    let click_right_up = TrayIconEvent::Click {
        id: "tray".into(),
        position: tauri::PhysicalPosition { x: 100.0, y: 100.0 },
        rect: tauri::Rect {
            position: tauri::PhysicalPosition { x: 0, y: 0 }.into(),
            size: tauri::PhysicalSize {
                width: 10u32,
                height: 10u32,
            }
            .into(),
        },
        button: MouseButton::Right,
        button_state: MouseButtonState::Up,
    };
    assert!(!should_toggle_window_on_tray_click(&click_right_up));
}

#[test]
fn test_check_show_file_signal() {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp_show =
        std::env::temp_dir().join(format!("test-show-{}-{nanos}.signal", std::process::id()));
    let path_str = tmp_show.to_string_lossy().to_string();

    // Before creation -> false
    assert!(!check_show_file_signal(&path_str));

    // After creation -> true, and file gets deleted
    std::fs::write(&tmp_show, "show").unwrap();
    assert!(check_show_file_signal(&path_str));
    assert!(!tmp_show.exists());

    // Subsequent check -> false
    assert!(!check_show_file_signal(&path_str));
}

#[cfg(unix)]
#[test]
fn test_parse_parent_pid() {
    assert_eq!(
        parse_parent_pid(["app", "--parent-pid", "12345"]),
        Some(12345)
    );
    assert_eq!(parse_parent_pid(["app", "--parent-pid", "invalid"]), None);
    assert_eq!(parse_parent_pid(["app", "--parent-pid"]), None);
    assert_eq!(parse_parent_pid(["app", "--other-flag"]), None);
}

#[cfg(not(target_os = "windows"))]
#[test]
fn test_fallback_netbird_cmd_unix_with() {
    // When check_err is false, returns None
    assert!(fallback_netbird_cmd_unix_with(|| false, || Some("/usr/bin/netbird")).is_none());

    // When check_err is true and binary found
    let cmd = fallback_netbird_cmd_unix_with(|| true, || Some("/usr/bin/netbird"));
    assert!(cmd.is_some());
    let debug = format!("{:?}", cmd.unwrap());
    assert!(debug.contains("/usr/bin/netbird"));

    // When check_err is true and binary not found
    assert!(fallback_netbird_cmd_unix_with(|| true, || None).is_none());
}

#[test]
fn test_notify_update_for_version() {
    notify_update_for_version(None, "2.0.0");
}

#[cfg(target_os = "linux")]
#[test]
fn test_determine_instance_action_and_lock() {
    assert_eq!(
        determine_instance_action(true, true, 1234),
        InstanceLockAction::HoldLock
    );
    assert_eq!(
        determine_instance_action(true, false, 1234),
        InstanceLockAction::Elevate(1234)
    );
    assert_eq!(
        determine_instance_action(false, false, 1234),
        InstanceLockAction::SignalRunningInstance
    );
    assert_eq!(
        determine_instance_action(false, true, 1234),
        InstanceLockAction::SignalRunningInstance
    );

    // Invalid path where open() fails
    assert_eq!(
        try_lock_at_path("/invalid_nonexistent_dir_1234/test.lock"),
        None
    );
}

#[test]
fn test_execute_tray_menu_action() {
    let mut show_called = false;
    let mut quit_called = false;

    execute_tray_menu_action(
        TrayMenuAction::Show,
        || show_called = true,
        || quit_called = true,
    );
    assert!(show_called);
    assert!(!quit_called);

    show_called = false;
    quit_called = false;
    execute_tray_menu_action(
        TrayMenuAction::Quit,
        || show_called = true,
        || quit_called = true,
    );
    assert!(!show_called);
    assert!(quit_called);

    show_called = false;
    quit_called = false;
    execute_tray_menu_action(
        TrayMenuAction::Unknown,
        || show_called = true,
        || quit_called = true,
    );
    assert!(!show_called);
    assert!(!quit_called);
}

#[test]
fn test_determine_window_toggle_action() {
    assert_eq!(
        determine_window_toggle_action(true),
        WindowToggleAction::Hide
    );
    assert_eq!(
        determine_window_toggle_action(false),
        WindowToggleAction::ShowAndFocus
    );
}

#[test]
fn test_check_and_notify_update() {
    let mut notified_ver = None;
    let res = check_and_notify_update("1.0.0", Some("1.2.0"), |v| {
        notified_ver = Some(v.to_string())
    });
    assert!(res);
    assert_eq!(notified_ver, Some("1.2.0".to_string()));

    let mut notified_none = None;
    let res_none = check_and_notify_update("1.2.0", Some("1.0.0"), |v| {
        notified_none = Some(v.to_string())
    });
    assert!(!res_none);
    assert!(notified_none.is_none());

    let res_no_latest = check_and_notify_update("1.0.0", None, |_| ());
    assert!(!res_no_latest);
}

#[test]
fn test_parse_gsettings_output() {
    let ok_output = std::process::Command::new("echo")
        .arg("'Yaru-dark'")
        .output()
        .unwrap();
    assert_eq!(
        parse_gsettings_output(&ok_output),
        Some("Yaru-dark".to_string())
    );

    let fail_output = std::process::Command::new("false").output().unwrap();
    assert_eq!(parse_gsettings_output(&fail_output), None);

    let empty_output = std::process::Command::new("echo").arg("").output().unwrap();
    assert_eq!(parse_gsettings_output(&empty_output), None);
}

#[cfg(target_os = "linux")]
#[test]
fn test_get_runtime_path_with_home() {
    let path_with_none = get_runtime_path_with_home(None, "sample.txt");
    assert!(path_with_none.contains("/tmp"));
    assert!(path_with_none.contains("sample.txt"));

    let path_with_home = get_runtime_path_with_home(Some("/home/testuser"), "sample.txt");
    assert!(path_with_home.contains("/home/testuser"));
    assert!(path_with_home.contains("sample.txt"));
}

#[test]
fn test_resolve_script_path() {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp = std::env::temp_dir().join(format!("test_resolve_script_{nanos}.sh"));
    std::fs::write(&tmp, "#!/bin/sh\necho ok\n").unwrap();
    let res = resolve_script_path(&tmp);
    assert!(res.is_ok());
    let _ = std::fs::remove_file(&tmp);
}

#[test]
fn test_determine_app_startup_mode() {
    assert_eq!(
        determine_app_startup_mode(true),
        AppStartupMode::BackgroundChecker
    );
    assert_eq!(
        determine_app_startup_mode(false),
        AppStartupMode::InteractiveApp
    );
}

#[cfg(target_os = "windows")]
#[test]
fn test_fallback_netbird_cmd_windows() {
    let cmd = fallback_netbird_cmd_windows();
    let _ = cmd;
}

#[test]
fn test_parse_version_shorthand_and_invalid() {
    assert_eq!(parse_version("4"), Some((4, 0, 0)));
    assert_eq!(parse_version("4.2"), Some((4, 2, 0)));
    assert_eq!(parse_version(""), None);
    assert_eq!(parse_version("not-a-version"), None);
}

#[test]
fn test_parse_component_version_default_fallback() {
    let parsed = parse_component_version("unknown_daemon", "v1.2.3");
    assert_eq!(parsed, Some("v1.2.3".to_string()));

    // Date and path skipping in default parser
    let complex = "built on 2026-04-12 from /opt/bin/tool.1.0 with release 2.4.1";
    assert_eq!(parse_default_version(complex), Some("2.4.1".to_string()));

    // Default parser with digit but no dot
    assert_eq!(
        parse_default_version("release 4"),
        Some("release 4".to_string())
    );

    // Default parser with no digits
    assert_eq!(parse_default_version("unknown output"), None);

    // Suricata with "suricata version 7.0"
    assert_eq!(
        parse_suricata_version("Suricata version 7.0.2"),
        Some("7.0.2".to_string())
    );
    assert_eq!(
        parse_suricata_version("version !!!"),
        Some("version !!!".to_string())
    );

    // Netbird empty
    assert_eq!(parse_netbird_version("   "), None);

    // Wazuh agent with "Wazuh v" and invalid
    assert_eq!(
        parse_wazuh_agent_version("Wazuh v4.7.2 (built on Linux)"),
        Some("4.7.2".to_string())
    );
    assert_eq!(parse_wazuh_agent_version("completely unknown format"), None);
}
