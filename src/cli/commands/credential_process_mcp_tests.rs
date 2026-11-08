use super::*;
use crate::auth::aws::read_only::{ReadOnlyCapability, TargetName};
use crate::config::McpClientGrant;
use clap::Parser;

#[tokio::test]
async fn authenticated_reads_do_not_open_the_normal_gate_or_return_source_credentials() {
    const DIRECTORY: &str = "AWZARS_MCP_PIPELINE_TEST";
    let Ok(directory) = std::env::var(DIRECTORY) else {
        let directory = tempfile::tempdir().unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "cli::commands::credential_process::mcp_tests::authenticated_reads_do_not_open_the_normal_gate_or_return_source_credentials"])
            .env(DIRECTORY, directory.path())
            .env("XDG_RUNTIME_DIR", directory.path())
            .env("AWZARS_SESSION_ID", "mcp_pipeline_test")
            .env("AWZARS_MCP_TEST_AI", "1")
            .stdin(std::process::Stdio::null()).output().unwrap();
        assert!(
            output.status.success(),
            "{} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!String::from_utf8_lossy(&output.stdout).contains("SOURCE-MARKER"));
        let sessions = directory.path().join("awzars/sessions");
        if sessions.exists() {
            assert_eq!(std::fs::read_dir(sessions).unwrap().count(), 0);
        }
        return;
    };
    config::set_config_dir_override(&directory).unwrap();
    let mut profile = Profile::new(crate::config::AzureConfig::new(
        "tenant",
        "https://signin.aws.amazon.com/saml",
    ));
    profile.mcp_readonly_accessible = true;
    profile.role_arn = Some("arn:aws:iam::111111111111:role/Source".into());
    profile.lock_verifier = Some("test-locked-profile".into());
    profile.lock_ai_markers = Some(vec!["AWZARS_MCP_TEST_AI".into()]);
    profile.read_only = Some(
        toml::from_str(
            r#"
        [targets.workload]
        role_arn = "arn:aws:iam::123456789012:role/Workload"
        region = "ap-southeast-1"
        capabilities = ["s3-list-buckets"]
    "#,
        )
        .unwrap(),
    );
    let client: crate::auth::mcp::McpClientName = "incident-agent".parse().unwrap();
    let target: TargetName = "workload".parse().unwrap();
    let (grant, secret) = McpClientGrant::enroll(
        "work",
        &profile,
        target.clone(),
        [ReadOnlyCapability::S3ListBuckets].into(),
    )
    .unwrap();
    profile
        .read_only
        .as_mut()
        .unwrap()
        .insert_client(client.clone(), grant)
        .unwrap();
    let args = Args::try_parse_from(["awzars", "--profile", "work", "credential-process"]).unwrap();
    let before = load_credentials(&args, &profile, false, false, false, false).await;
    assert!(matches!(before, Err(AwzarsError::AiContextBlocked { .. })));

    let identity = crate::auth::credentials::credential_identity(
        &profile.azure.tenant_id,
        &profile.azure.app_id_uri,
        profile.role_arn.as_deref(),
    );
    // A fresh cached source without a session token must reach the restricted
    // issuer's validation, never a real STS call or credential output.
    let source = CredentialProcessOutput::new("SOURCE-MARKER", "source-secret")
        .with_expiration("2030-01-01T00:00:00Z");
    let cache = crate::storage::cache::CacheHandle::new("work").unwrap();
    cache.store(&source, &identity).unwrap();
    let request = profile
        .authenticate_mcp(
            "work",
            &client,
            &target,
            ReadOnlyCapability::S3ListBuckets,
            &secret,
        )
        .unwrap();
    assert!(
        matches!(issue_mcp_credentials(&request).await, Err(AwzarsError::AwsSts(message)) if message.contains("temporary credentials"))
    );
    let after = load_credentials(&args, &profile, false, false, false, false).await;
    assert!(matches!(after, Err(AwzarsError::AiContextBlocked { .. })));
    assert_eq!(
        cache
            .get_valid_credentials(3600, &identity)
            .unwrap()
            .unwrap()
            .access_key_id,
        "SOURCE-MARKER"
    );

    let source = source.with_session_token("SOURCE-TOKEN");
    cache.store(&source, &identity).unwrap();
    let mut configuration = Config::default();
    configuration.set_profile("work", profile.clone());
    configuration.save().unwrap();
    let original = std::fs::read(config::config_file().unwrap()).unwrap();
    for unlocked in [false, false, true, true, false] {
        if unlocked {
            crate::auth::lock::write_unlock(
                "work",
                3600,
                true,
                true,
                profile.lock_verifier.as_deref(),
            )
            .unwrap();
        } else {
            crate::auth::lock::remove_unlock("work").unwrap();
        }
        let request = profile
            .authenticate_mcp(
                "work",
                &client,
                &target,
                ReadOnlyCapability::S3ListBuckets,
                &secret,
            )
            .unwrap();
        let credentials = issue_mcp_credentials_with(&request, |request, source| {
            crate::auth::aws::read_only::issue_mock(request, source, || {})
        })
        .await
        .unwrap();
        let mut output = Vec::new();
        super::super::read_only::deliver_mcp_credentials(&request, &credentials, &mut output)
            .unwrap();
        let parsed: CredentialProcessOutput = serde_json::from_slice(&output).unwrap();
        assert_eq!(parsed.access_key_id, "FINAL-RESTRICTED-KEY");
        assert_eq!(parsed.session_token.as_deref(), Some("final-token"));
        assert_eq!(
            std::fs::read(config::config_file().unwrap()).unwrap(),
            original
        );
        assert_eq!(
            crate::auth::lock::read_valid_unlock("work").is_some(),
            unlocked
        );
    }

    let mut passwordless = profile.clone();
    passwordless.lock_verifier = None;
    passwordless
        .read_only
        .as_mut()
        .unwrap()
        .remove_client(&client);
    let (grant, passwordless_secret) = McpClientGrant::enroll(
        "work",
        &passwordless,
        target.clone(),
        [ReadOnlyCapability::S3ListBuckets].into(),
    )
    .unwrap();
    passwordless
        .read_only
        .as_mut()
        .unwrap()
        .insert_client(client.clone(), grant)
        .unwrap();
    let mut passwordless_configuration = Config::default();
    passwordless_configuration.set_profile("work", passwordless.clone());
    passwordless_configuration.save().unwrap();
    for _ in 0..2 {
        let request = passwordless
            .authenticate_mcp(
                "work",
                &client,
                &target,
                ReadOnlyCapability::S3ListBuckets,
                &passwordless_secret,
            )
            .unwrap();
        let credentials = issue_mcp_credentials_with(&request, |request, source| {
            crate::auth::aws::read_only::issue_mock(request, source, || {})
        })
        .await
        .unwrap();
        let mut output = Vec::new();
        super::super::read_only::deliver_mcp_credentials(&request, &credentials, &mut output)
            .unwrap();
        assert!(serde_json::from_slice::<CredentialProcessOutput>(&output).is_ok());
        assert!(crate::auth::lock::read_valid_unlock("work").is_none());
    }

    for change in [
        "disable",
        "revoke",
        "password",
        "target",
        "remove-profile",
        "corrupt-config",
    ] {
        configuration.save().unwrap();
        let request = profile
            .authenticate_mcp(
                "work",
                &client,
                &target,
                ReadOnlyCapability::S3ListBuckets,
                &secret,
            )
            .unwrap();
        let client = client.clone();
        let credentials = issue_mcp_credentials_with(&request, |request, source| {
            crate::auth::aws::read_only::issue_mock(request, source, move || {
                let mut current = Config::load().unwrap();
                match change {
                    "disable" => {
                        current
                            .get_profile_mut("work")
                            .unwrap()
                            .mcp_readonly_accessible = false
                    }
                    "revoke" => {
                        current
                            .get_profile_mut("work")
                            .unwrap()
                            .read_only
                            .as_mut()
                            .unwrap()
                            .remove_client(&client);
                    }
                    "password" => current.get_profile_mut("work").unwrap().lock_verifier = None,
                    "target" => {
                        let changed = toml::to_string(&current)
                            .unwrap()
                            .replace("ap-southeast-1", "us-east-1");
                        current = toml::from_str(&changed).unwrap();
                    }
                    "remove-profile" => {
                        current.remove_profile("work");
                    }
                    "corrupt-config" => {
                        std::fs::write(config::config_file().unwrap(), "invalid configuration")
                            .unwrap();
                        return;
                    }
                    _ => unreachable!(),
                }
                current.save().unwrap();
            })
        })
        .await
        .unwrap();
        let mut output = Vec::new();
        let result =
            super::super::read_only::deliver_mcp_credentials(&request, &credentials, &mut output);
        assert!(
            matches!(result, Err(AwzarsError::McpAuthentication)),
            "{change}"
        );
        assert!(output.is_empty(), "{change}");
        assert!(crate::auth::lock::read_valid_unlock("work").is_none());
    }
    assert_eq!(
        cache
            .get_valid_credentials(3600, &identity)
            .unwrap()
            .unwrap()
            .access_key_id,
        "SOURCE-MARKER"
    );
    cache.clear().unwrap();
}
