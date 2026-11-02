// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE 1.5.5 UPGRADE THROUGH BOTH DOORS** (`busbar --migrate-config`, owner ruling 2026-10-27):

use busbar_plugin_loader::dispatch::load::raw;
use busbar_plugin_loader::dispatch::migrate::{migrate_door, migrate_library};
use serde_json::json;

#[test]
fn the_door_migrates_an_auth_header_1_5_5_never_sent_both_ways() {
    let bytes = std::fs::read(busbar_test_kit::conformance::cdylib_of(
        "busbar_export_webhook_plugin",
    ))
    .expect("the cdylib reads");
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
        assert_eq!(m.settings, json!({"url": "https://siem.example/in"}));
        assert_eq!(
            m.report,
            vec![busbar_export_webhook::REMOVED_AUTH_HEADER.to_string()]
        );
        assert!(m.needs.is_empty());
        assert!(!format!("{m:?}").contains("s3cret"), "{m:?}");
    }
    for m in [linked(&good), dropped(&good)] {
        assert_eq!(m.settings, good);
        assert!(m.report.is_empty() && m.needs.is_empty(), "{m:?}");
    }
}
