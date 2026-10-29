// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE 1.5.5 UPGRADE THROUGH BOTH DOORS** (`busbar --migrate-config`, owner ruling 2026-10-27):
//! the host calls the door's `migrate` with the section as the operator wrote it, LINKED and DROPPED
//! IN, over busbar's real loader. An `auth_header` 1.5.5 could not build (and so never sent) is
//! removed, in one report line; a section with nothing to migrate comes back as it went in.
//!
//! RED before: the door stated no `migrate`, so the host passed the section through unchanged.

use std::path::PathBuf;

use busbar_plugin_loader::dispatch::load::raw;
use busbar_plugin_loader::dispatch::migrate::{migrate_door, migrate_library};
use serde_json::json;

/// This crate's built cdylib (uplifted or under `deps`, newest wins). A missing artifact is a
/// failure, never a skip.
fn cdylib() -> PathBuf {
    let exe = std::env::current_exe().expect("the test binary has a path");
    let profile = exe
        .parent()
        .and_then(|d| d.parent())
        .expect("target/<profile>");
    let file = busbar_plugin_loader::plugin_library_filename("busbar_export_webhook_plugin");
    [profile.join(&file), profile.join("deps").join(&file)]
        .into_iter()
        .filter_map(|p| Some((std::fs::metadata(&p).ok()?.modified().ok()?, p)))
        .max()
        .map(|(_, p)| p)
        .unwrap_or_else(|| panic!("the built cdylib {file} is missing: build the workspace first"))
}

#[test]
fn the_door_migrates_an_auth_header_1_5_5_never_sent_both_ways() {
    let bytes = std::fs::read(cdylib()).expect("the cdylib reads");
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
