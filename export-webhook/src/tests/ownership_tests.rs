// SPDX-License-Identifier: Apache-2.0
use super::*;
use crate::wipe_probe::{watch, Probe};
pub(super) fn watch_value_as(label: &'static str, value: &serde_json::Value) {
    match value {
        serde_json::Value::String(text) => watch(label, text.as_bytes()),
        serde_json::Value::Array(values) => {
            for value in values {
                watch_value_as(label, value);
            }
        }
        serde_json::Value::Object(values) => {
            for (key, value) in values {
                watch(label, key.as_bytes());
                watch_value_as(label, value);
            }
        }
        _ => {}
    }
}

#[test]
fn migration_probes_wipe_owned_settings_on_success_and_refusal() {
    for settings in [
        serde_json::json!({"url":"https://receiver.example/private-probe","auth_header":{"name":"Authorization","value":"Bearer probe-canary"}}),
        serde_json::json!({"url":"https://receiver.example/private-probe","auth_header":{"name":"Bad Name","value":{"env":"HEADER_REFERENCE"}}}),
        serde_json::json!({"url":"https://receiver.example/private-probe","auth_header":{"name":"Authorization","value":"Bearer probe-canary"},"zz_unknown":"refusal-canary"}),
    ] {
        let probe = Probe::start();
        let _ = auth_header_unbuildable(&settings);
        probe
            .finish()
            .assert_wiped_on_linux(&["migration probe JSON"]);
    }
}

#[test]
fn migration_wipes_the_removed_header_without_changing_the_remaining_section() {
    let settings = serde_json::json!({
        "url":"https://receiver.example/private-kept",
        "auth_header":{"name":"Bad Name","value":"Bearer removed-canary"},
        "delivery_timeout_secs":7,
    });
    let probe = Probe::start();
    let migrated = Migration::migrate(settings, "1.5.5");
    assert_eq!(
        migrated.settings,
        serde_json::json!({"url":"https://receiver.example/private-kept","delivery_timeout_secs":7})
    );
    assert_eq!(migrated.report, vec![REMOVED_AUTH_HEADER.to_string()]);
    probe
        .finish()
        .assert_wiped_on_linux(&["removed migration header", "migration probe JSON"]);
}
