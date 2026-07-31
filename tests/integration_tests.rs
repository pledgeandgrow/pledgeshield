use pledgeshield::models::{Category, Finding, ScanResult, Severity};

#[test]
fn test_full_scan_result_pipeline() {
    let mut result = ScanResult::new();

    result.add_finding(
        Finding::new("win-uac-disabled", "UAC Disabled", Severity::High, Category::Config)
            .description("User Account Control is disabled")
            .recommendation("Enable UAC in Control Panel")
            .fixable(true)
            .metadata("setting", "EnableLUA")
            .metadata("value", "0"),
    );

    result.add_finding(
        Finding::new("win-rdp-exposed", "RDP Exposed to Internet", Severity::Critical, Category::Services)
            .description("RDP is listening on 0.0.0.0:3389")
            .recommendation("Restrict RDP to localhost or VPN")
            .metadata("port", "3389")
            .metadata("protocol", "tcp"),
    );

    result.add_finding(
        Finding::new("ssh-no-passphrase", "SSH Key Without Passphrase", Severity::Medium, Category::Credentials)
            .description("SSH key at ~/.ssh/id_rsa has no passphrase")
            .recommendation("Add a passphrase with ssh-keygen -p"),
    );

    result.finalize();

    assert_eq!(result.findings.len(), 3);
    assert_eq!(result.summary.critical, 1);
    assert_eq!(result.summary.high, 1);
    assert_eq!(result.summary.medium, 1);
    assert_eq!(result.summary.total, 3);
}

#[test]
fn test_severity_filtering_pipeline() {
    let mut result = ScanResult::new();

    for i in 0..10 {
        let sev = match i % 5 {
            0 => Severity::Critical,
            1 => Severity::High,
            2 => Severity::Medium,
            3 => Severity::Low,
            _ => Severity::Info,
        };
        result.add_finding(Finding::new(&format!("finding-{}", i), &format!("Finding {}", i), sev, Category::Config));
    }

    result.finalize();
    assert_eq!(result.findings.len(), 10);

    result.filter_by_severity(Severity::High);
    assert_eq!(result.findings.len(), 4);
    assert!(result.findings.iter().all(|f| f.severity <= Severity::High));
}

#[test]
fn test_finding_metadata_operations() {
    let f = Finding::new("test-1", "Test", Severity::High, Category::Config)
        .metadata("port", "22")
        .metadata("protocol", "tcp")
        .metadata("service", "ssh");

    assert_eq!(f.metadata.len(), 3);
    assert_eq!(f.metadata.get("port"), Some(&"22".to_string()));
    assert_eq!(f.metadata.get("protocol"), Some(&"tcp".to_string()));
    assert_eq!(f.metadata.get("service"), Some(&"ssh".to_string()));
    assert_eq!(f.metadata.get("nonexistent"), None);
}

#[test]
fn test_scan_result_serde_roundtrip() {
    let mut result = ScanResult::new();
    result.add_finding(
        Finding::new("test-1", "Test Finding", Severity::Critical, Category::Config)
            .description("A critical finding")
            .recommendation("Fix immediately")
            .fixable(true)
            .metadata("key", "value"),
    );
    result.finalize();

    let json = serde_json::to_string(&result).unwrap();
    let deserialized: ScanResult = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.findings.len(), 1);
    assert_eq!(deserialized.findings[0].id, "test-1");
    assert_eq!(deserialized.findings[0].severity, Severity::Critical);
    assert_eq!(deserialized.findings[0].title, "Test Finding");
    assert!(deserialized.findings[0].fixable);
}

#[test]
fn test_empty_scan_result() {
    let result = ScanResult::new();
    assert_eq!(result.findings.len(), 0);
    assert_eq!(result.summary.total, 0);
}

#[test]
fn test_all_categories() {
    let categories = vec![
        Category::Config,
        Category::Services,
        Category::Cve,
        Category::Privileges,
        Category::Persistence,
        Category::Credentials,
        Category::Shares,
        Category::Patches,
    ];

    let mut result = ScanResult::new();
    for (i, cat) in categories.iter().enumerate() {
        result.add_finding(Finding::new(
            &format!("cat-{}", i),
            &format!("Category test {}", i),
            Severity::Low,
            cat.clone(),
        ));
    }
    result.finalize();

    assert_eq!(result.findings.len(), 8);
    for (i, f) in result.findings.iter().enumerate() {
        assert_eq!(f.category, categories[i]);
    }
}

#[test]
fn test_finding_builder_chain() {
    let f = Finding::new("chain-1", "Chained", Severity::High, Category::Persistence)
        .description("desc")
        .recommendation("rec")
        .fixable(true)
        .metadata("a", "1")
        .metadata("b", "2")
        .metadata("c", "3");

    assert_eq!(f.id, "chain-1");
    assert_eq!(f.title, "Chained");
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.category, Category::Persistence);
    assert_eq!(f.description, "desc");
    assert_eq!(f.recommendation, "rec");
    assert!(f.fixable);
    assert_eq!(f.metadata.len(), 3);
}

#[test]
fn test_severity_priority_ordering() {
    let severities = vec![
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ];

    for i in 0..severities.len() - 1 {
        assert!(severities[i] < severities[i + 1]);
    }
}
