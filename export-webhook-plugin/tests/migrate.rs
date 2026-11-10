// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#[path = "support/artifact.rs"]
mod artifact;

// Both doors migrate unsendable legacy auth headers and preserve sections requiring no migration.

use busbar_contract::abi::sdk::migrate::MigrationAnswer;
use busbar_plugin_loader::dispatch::load::raw;
use busbar_plugin_loader::dispatch::migrate::{migrate_door, migrate_library};
use serde_json::json;

fn settings(answer: &MigrationAnswer) -> serde_json::Value {
    let seal = busbar_contract::caps::KernelSeal::acquire_for_kernel();
    serde_json::to_value(answer.authoring(&seal)).expect("the authoring document serializes")
}

#[test]
fn the_door_migrates_an_auth_header_1_5_5_never_sent_both_ways() {
    let bytes = std::fs::read(artifact::cdylib_of()).expect("the cdylib reads");
    let bad = json!({
        "url": "https://siem.example/in",
        "auth_header": {"name": "Authorization", "value": "Bearer s3cret\r\nX-Injected: 1"}
    });
    let good = json!({
        "url": "https://siem.example/in",
        "auth_header": {"name": "Authorization", "value": "Bearer x"}
    });
    let linked = |s: &serde_json::Value| {
        migrate_door(raw(busbar_export_webhook::door), s, "1.5.5")
            .expect("migrates")
            .expect("the door states migrate")
    };
    let dropped = |s: &serde_json::Value| {
        migrate_library(&bytes, "busbar-export-webhook", s, "1.5.5")
            .expect("migrates")
            .expect("the door states migrate")
    };
    for m in [linked(&bad), dropped(&bad)] {
        assert_eq!(settings(&m), json!({"url": "https://siem.example/in"}));
        assert_eq!(
            m.report,
            vec!["removed settings.auth_header: 1.6.0 does not send it, as it cannot be sent as an HTTP header (its name or value is not a valid HTTP header), which 1.6.0 refuses at validation and open".to_string()]
        );
        assert!(m.needs.is_empty());
        assert!(!format!("{m:?}").contains("s3cret"), "{m:?}");
    }
    for m in [linked(&good), dropped(&good)] {
        assert_eq!(settings(&m), good);
        assert!(m.report.is_empty() && m.needs.is_empty(), "{m:?}");
    }
}

#[test]
fn the_door_migrates_zero_delivery_bounds_idempotently_both_ways() {
    let bytes = std::fs::read(artifact::cdylib_of()).expect("the cdylib reads");
    let before = json!({
        "url":{"env":"WEBHOOK_URL"},
        "auth_header":{"name":"Authorization", "value":{"env":"WEBHOOK_AUTHORIZATION"}},
        "max_inflight_deliveries":0,
        "delivery_timeout_secs":7
    });
    let mut expected = before.clone();
    expected["max_inflight_deliveries"] = json!(1);
    let linked = |s: &serde_json::Value| {
        migrate_door(raw(busbar_export_webhook::door), s, "1.5.5")
            .expect("migrates")
            .expect("the door states migrate")
    };
    let dropped = |s: &serde_json::Value| {
        migrate_library(&bytes, "busbar-export-webhook", s, "1.5.5")
            .expect("migrates")
            .expect("the door states migrate")
    };
    for migrated in [linked(&before), dropped(&before)] {
        assert_eq!(settings(&migrated), expected);
        assert_eq!(
            migrated.report,
            vec!["changed settings.max_inflight_deliveries: 0 -> 1 (preserves the historical effective per-instance limit)".to_string()]
        );
        assert!(migrated.needs.is_empty());
    }
    for unchanged in [linked(&expected), dropped(&expected)] {
        assert_eq!(settings(&unchanged), expected);
        assert!(unchanged.report.is_empty());
        assert!(unchanged.needs.is_empty());
    }
}
