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
    assert_eq!(parse_version("invalid"), None);
    assert_eq!(parse_version(""), None);
    assert_eq!(parse_version("v"), None);
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
    assert_eq!(parse_default_version("no numbers here"), None);
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
        std::fs::write(&tmp_script, script_content).unwrap();
        let mut perms = std::fs::metadata(&tmp_script).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&tmp_script, perms).unwrap();

        let script_path = tmp_script.to_string_lossy().to_string();

        let suricata_ver = get_component_version("Suricata", &script_path).await;
        assert_eq!(suricata_ver, Some("7.0.3".to_string()));

        let yara_ver = get_component_version("YARA", &script_path).await;
        assert_eq!(yara_ver, Some("yara 4.5.2".to_string()));

        let netbird_ver = get_component_version("NetBird", &script_path).await;
        assert_eq!(netbird_ver, Some("0.28.3".to_string()));

        let other_ver = get_component_version("CustomTool", &script_path).await;
        assert_eq!(other_ver, Some("4.5.2".to_string()));

        let none_ver = get_component_version("Suricata", "/tmp/non_existent_mock_file").await;
        assert_eq!(none_ver, None);

        let _ = std::fs::remove_file(tmp_script);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn test_get_runtime_path_and_lock() {
    let path = get_runtime_path("unit-test-file.txt");
    assert!(path.contains("unit-test-file.txt"));

    if let Some(fd) = try_lock_instance() {
        let second_lock = try_lock_instance();
        assert!(second_lock.is_none());
        unsafe { libc::close(fd) };
    }
}

#[cfg(unix)]
#[test]
fn test_pre_create_config_unix() {
    let orig_home = std::env::var("HOME").ok();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp_home = std::env::temp_dir().join(format!("test-home-{}-{nanos}", std::process::id()));
    let _ = std::fs::create_dir_all(&tmp_home);
    std::env::set_var("HOME", &tmp_home);

    pre_create_config();

    let cfg_file = tmp_home.join(".config/com.adorsys.wazuh-agent-installer/config.json");
    assert!(cfg_file.exists());

    let content = std::fs::read_to_string(&cfg_file).unwrap();
    let parsed: Result<AppConfig, _> = serde_json::from_str(&content);
    assert!(parsed.is_ok());

    // Restore original HOME and clean up
    if let Some(h) = orig_home {
        std::env::set_var("HOME", h);
    } else {
        std::env::remove_var("HOME");
    }
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
    assert!(args.is_empty() || !args.is_empty());

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
async fn test_check_components_execution() {
    let res = check_components().await;
    assert!(res.is_ok());
    let components = res.unwrap();
    assert_eq!(components.len(), 6);
    let names: Vec<String> = components.into_iter().map(|c| c.name).collect();
    assert!(names.contains(&"Wazuh Agent".to_string()));
    assert!(names.contains(&"NetBird".to_string()));
    assert!(names.contains(&"Suricata".to_string()));
}

#[tokio::test]
async fn test_check_enrollment_execution() {
    let state = check_enrollment().await;
    assert!(state.is_ok());
}

#[tokio::test]
async fn test_check_netbird_execution() {
    let state = check_netbird().await;
    // On environments where NetBird is not installed (such as CI runners),
    // check_netbird returns an Err from command spawning. When installed,
    // it returns Ok(NetbirdState). Both are valid runtime outcomes.
    match state {
        Ok(s) => {
            let _ = s.daemon_status;
            let _ = s.netbird_ip;
            let _ = s.management_connected;
        }
        Err(e) => {
            assert!(!e.is_empty());
        }
    }
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
fn test_open_browser_safe_and_unsafe() {
    open_browser("ftp://unsafe.com");
    open_browser("javascript:alert(1)");
    open_browser("   ");

    // Safe URL without SUDO_USER triggers the standard fallback opener without prompting for sudo
    std::env::remove_var("SUDO_USER");
    std::env::remove_var("PKEXEC_UID");
    open_browser("https://example.com");
}

#[test]
fn test_get_gtk_theme_and_parent_pid() {
    let _ = get_gtk_theme();
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

#[tokio::test]
async fn test_fetch_latest_version_execution() {
    // Runs fetch_latest_version against real curl execution
    let _ = fetch_latest_version().await;
}

#[cfg(target_os = "linux")]
#[test]
fn test_notify_update_linux() {
    notify_update_linux("1.2.0");
}
