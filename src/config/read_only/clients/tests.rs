use super::*;

fn profile() -> Profile {
    let mut profile = Profile::new(crate::config::AzureConfig::new(
        "tenant",
        "https://signin.aws.amazon.com/saml",
    ));
    profile.mcp_readonly_accessible = true;
    profile.role_arn = Some("arn:aws:iam::111111111111:role/Source".into());
    profile.lock_verifier = Some("test-lock-binding".into());
    profile.read_only = Some(
        toml::from_str(
            r#"
        [targets.workload]
        role_arn = "arn:aws:iam::123456789012:role/Workload"
        region = "ap-southeast-1"
        capabilities = ["s3-list-buckets", "ec2-describe-instances"]
        [targets.other]
        role_arn = "arn:aws:iam::123456789012:role/Other"
        region = "ap-southeast-1"
        capabilities = ["s3-list-buckets"]
    "#,
        )
        .unwrap(),
    );
    profile
}

#[test]
fn grants_require_the_secret_and_reject_other_profiles_targets_capabilities_and_revocation() {
    let mut profile = profile();
    let client: McpClientName = "incident-agent".parse().unwrap();
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
        .insert_client(client.clone(), grant.clone())
        .unwrap();
    let serialized = toml::to_string(&profile).unwrap();
    assert!(!serialized.contains(secret.expose()));
    let profile: Profile = toml::from_str(&serialized).unwrap();
    let request = profile
        .authenticate_mcp(
            "work",
            &client,
            &target,
            ReadOnlyCapability::S3ListBuckets,
            &secret,
        )
        .unwrap();
    assert_eq!(
        request.request().scope().role().as_str(),
        "arn:aws:iam::123456789012:role/Workload"
    );
    for (profile_name, name, requested_target, capability) in [
        (
            "other-profile",
            client.clone(),
            target.clone(),
            ReadOnlyCapability::S3ListBuckets,
        ),
        (
            "work",
            "unknown".parse().unwrap(),
            target.clone(),
            ReadOnlyCapability::S3ListBuckets,
        ),
        (
            "work",
            client.clone(),
            "other".parse().unwrap(),
            ReadOnlyCapability::S3ListBuckets,
        ),
        (
            "work",
            client.clone(),
            target.clone(),
            ReadOnlyCapability::Ec2DescribeInstances,
        ),
    ] {
        assert!(profile
            .authenticate_mcp(profile_name, &name, &requested_target, capability, &secret)
            .is_err());
    }
    assert!(profile
        .authenticate_mcp(
            "work",
            &client,
            &target,
            ReadOnlyCapability::S3ListBuckets,
            &McpSecret::generate().unwrap()
        )
        .is_err());
    let mut profile = profile;
    assert!(profile
        .read_only
        .as_mut()
        .unwrap()
        .insert_client(client.clone(), grant)
        .is_err());
    assert!(profile.read_only.as_mut().unwrap().remove_client(&client));
    assert!(profile
        .authenticate_mcp(
            "work",
            &client,
            &target,
            ReadOnlyCapability::S3ListBuckets,
            &secret
        )
        .is_err());
}

#[test]
fn edits_to_source_lock_or_target_invalidate_the_enrollment() {
    let mut original = profile();
    let client: McpClientName = "incident-agent".parse().unwrap();
    let target: TargetName = "workload".parse().unwrap();
    let (grant, secret) = McpClientGrant::enroll(
        "work",
        &original,
        target.clone(),
        [ReadOnlyCapability::S3ListBuckets].into(),
    )
    .unwrap();
    original
        .read_only
        .as_mut()
        .unwrap()
        .insert_client(client.clone(), grant)
        .unwrap();
    let encoded = toml::to_string(&original).unwrap();
    for changed in [
        encoded.replace("111111111111", "222222222222"),
        encoded.replace("test-lock-binding", "changed-lock-binding"),
        encoded.replace("123456789012", "333333333333"),
        encoded.replace("ap-southeast-1", "us-east-1"),
        encoded.replace(
            "https://signin.aws.amazon.com/saml",
            "urn:amazon:webservices",
        ),
        encoded.replace("\"s3-list-buckets\",", ""),
    ] {
        let changed: Profile = toml::from_str(&changed).unwrap();
        assert!(changed
            .authenticate_mcp(
                "work",
                &client,
                &target,
                ReadOnlyCapability::S3ListBuckets,
                &secret
            )
            .is_err());
    }
}

#[test]
fn enrollment_rejects_empty_unknown_or_disabled_permissions() {
    let profile = profile();
    for (target, capabilities) in [
        ("workload", BTreeSet::new()),
        ("missing", [ReadOnlyCapability::S3ListBuckets].into()),
        ("workload", [ReadOnlyCapability::EksDescribeCluster].into()),
    ] {
        assert!(
            McpClientGrant::enroll("work", &profile, target.parse().unwrap(), capabilities)
                .is_err()
        );
    }
}

#[test]
fn generic_reads_require_the_new_grant_and_an_exact_catalog_operation() {
    let encoded = toml::to_string(&profile()).unwrap().replace(
        "\"ec2-describe-instances\"",
        "\"ec2-describe-instances\", \"aws-read\"",
    );
    let mut profile: Profile = toml::from_str(&encoded).unwrap();
    let target: TargetName = "workload".parse().unwrap();
    let operation = "dynamodb/Query".parse().unwrap();
    for (client_name, capability) in [
        ("old", ReadOnlyCapability::S3ListBuckets),
        ("new", ReadOnlyCapability::AwsRead),
    ] {
        let client: McpClientName = client_name.parse().unwrap();
        let (grant, secret) =
            McpClientGrant::enroll("work", &profile, target.clone(), [capability].into()).unwrap();
        profile
            .read_only
            .as_mut()
            .unwrap()
            .insert_client(client.clone(), grant)
            .unwrap();
        let result = profile.authenticate_mcp_operation(
            "work",
            &client,
            &target,
            ReadOnlyCapability::AwsRead,
            &secret,
            Some(&operation),
        );
        assert_eq!(result.is_ok(), capability == ReadOnlyCapability::AwsRead);
        if let Ok(approved) = result {
            approved.revalidate(&profile).unwrap();
            assert!(profile
                .authenticate_mcp_operation(
                    "work",
                    &client,
                    &target,
                    ReadOnlyCapability::AwsRead,
                    &secret,
                    None
                )
                .is_err());
            assert!(profile
                .authenticate_mcp_operation(
                    "work",
                    &client,
                    &target,
                    ReadOnlyCapability::S3ListBuckets,
                    &secret,
                    Some(&operation)
                )
                .is_err());
            let mut revoked = profile.clone();
            revoked.read_only.as_mut().unwrap().remove_client(&client);
            assert!(approved.revalidate(&revoked).is_err());
        }
    }
}

#[test]
fn profile_switch_blocks_grants_without_revoking_them_and_delivery_rechecks_authorization() {
    let mut original = profile();
    let client: McpClientName = "incident-agent".parse().unwrap();
    let target: TargetName = "workload".parse().unwrap();
    original.mcp_readonly_accessible = false;
    assert!(McpClientGrant::enroll(
        "work",
        &original,
        target.clone(),
        [ReadOnlyCapability::S3ListBuckets].into()
    )
    .is_err());
    original.mcp_readonly_accessible = true;
    let (grant, secret) = McpClientGrant::enroll(
        "work",
        &original,
        target.clone(),
        [ReadOnlyCapability::S3ListBuckets].into(),
    )
    .unwrap();
    original
        .read_only
        .as_mut()
        .unwrap()
        .insert_client(client.clone(), grant.clone())
        .unwrap();
    let request = original
        .authenticate_mcp(
            "work",
            &client,
            &target,
            ReadOnlyCapability::S3ListBuckets,
            &secret,
        )
        .unwrap();
    request.revalidate(&original).unwrap();
    let mut changed = original.clone();
    changed.mcp_readonly_accessible = false;
    assert!(changed
        .authenticate_mcp(
            "work",
            &client,
            &target,
            ReadOnlyCapability::S3ListBuckets,
            &secret
        )
        .is_err());
    assert!(request.revalidate(&changed).is_err());
    changed.mcp_readonly_accessible = true;
    request.revalidate(&changed).unwrap();
    changed
        .authenticate_mcp(
            "work",
            &client,
            &target,
            ReadOnlyCapability::S3ListBuckets,
            &secret,
        )
        .unwrap();
    changed.read_only.as_mut().unwrap().remove_client(&client);
    assert!(request.revalidate(&changed).is_err());
    changed.mcp_readonly_accessible = false;
    changed.mcp_readonly_accessible = true;
    assert!(changed
        .authenticate_mcp(
            "work",
            &client,
            &target,
            ReadOnlyCapability::S3ListBuckets,
            &secret
        )
        .is_err());
    let (replacement, _) = McpClientGrant::enroll(
        "work",
        &changed,
        target,
        [ReadOnlyCapability::S3ListBuckets].into(),
    )
    .unwrap();
    changed
        .read_only
        .as_mut()
        .unwrap()
        .insert_client(client, replacement)
        .unwrap();
    assert!(request.revalidate(&changed).is_err());
    let mut changed = original.clone();
    changed.role_arn = Some("arn:aws:iam::222222222222:role/Changed".into());
    assert!(request.revalidate(&changed).is_err());
    let mut changed = original.clone();
    changed.lock_verifier = None;
    assert!(request.revalidate(&changed).is_err());
}
