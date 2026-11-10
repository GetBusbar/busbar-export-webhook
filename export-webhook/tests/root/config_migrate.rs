// SPDX-License-Identifier: Apache-2.0

#[test]
fn current_export_declared_references_are_validated_without_inventing_migration_debt() {
    crate::dist_root_install::install();
    let directory = super::FetchedDir::create_in(&std::env::temp_dir()).unwrap();
    let url = directory.0.join("collector-url");
    let credential = directory.0.join("collector-token");
    std::fs::write(&url, "https://collector.example/requests").unwrap();
    std::fs::write(&credential, "Bearer private-migration-probe").unwrap();
    let settings = serde_json::json!({
        "url": {"file": url},
        "auth_header": {"name": "Authorization", "value": {"file": credential}},
    });
    let authored = serde_json::json!({
        "store": {"module": "memory"},
        "export": {"delivery": {
            "module": "request-log-webhook", "streams": ["logs"], "settings": settings,
        }},
    });
    let raw = serde_json::to_string(&authored).unwrap();
    let host = super::RootHost::for_document(&raw, &directory.0.join("config.yaml"));
    host.validate_migrated("export", "request-log-webhook", &settings)
        .expect("the actual current exporter validates resolved declared references");
    let out = busbar_migrations::config::normalize_authored(&raw, &host)
        .expect("an already current reference-bearing document normalizes");
    assert!(
        out.todos.is_empty(),
        "valid current settings require no historical decision: {:?}",
        out.todos
    );
    assert_eq!(
        out.yaml, raw,
        "validation never substitutes resolved secrets into the authored configuration"
    );
    assert_eq!(authored["export"]["delivery"]["settings"], settings);

    let mut undeclared = settings.clone();
    undeclared["undeclared"] = serde_json::json!({"file": directory.0.join("must-not-resolve")});
    assert_eq!(
        host.validate_migrated("export", "request-log-webhook", &undeclared),
        Err("migration validation contains an undeclared settings reference".into()),
        "the current Statement must authorize every reference before any resolution",
    );
}

#[test]
fn core_calls_the_real_webhook_migration_and_applies_its_settings_and_report() {
    crate::dist_root_install::install();
    let config = "\
store: { module: memory }
export:
  delivery:
    module: request-log-webhook
    settings:
      url: https://collector.example/requests
      auth_header: { name: 'Bad Name', value: 'Bearer private' }
";
    let directory = super::FetchedDir::create_in(&std::env::temp_dir()).unwrap();
    let host = super::RootHost::for_document(config, &directory.0.join("config.yaml"));
    let out = migrate_config_with(config, &host).expect("the real linked export migrates");
    let doc: serde_yaml::Value = serde_yaml::from_str(&out.yaml).expect("migrated YAML");
    assert_eq!(
        doc["export"]["delivery"]["settings"],
        serde_yaml::from_str::<serde_yaml::Value>("{ url: 'https://collector.example/requests' }")
            .unwrap(),
        "only the header the real plugin cannot send is removed: {}",
        out.yaml
    );
    assert!(
        out.changes
            .iter()
            .any(|line| line.starts_with("busbar-export-webhook:")
                && line.contains("settings.auth_header")),
        "the real plugin's report retains its name and reaches the operator: {:?}",
        out.changes
    );
    assert!(
        out.changes
            .iter()
            .all(|line| !line.contains("Bearer private")),
        "migration reports do not disclose the discarded credential"
    );
}
