use super::*;
use crate::wipe_probe::{watch, Probe};

#[test]
fn prepared_settings_and_parse_copies_are_wiped_after_use() {
    let probe = Probe::start();
    let settings = parse(br#"{"url":"https://operator:password-canary@receiver.example/private-canary?key=query-canary","auth_header":{"name":"authorization","value":"Bearer header-canary"}}"#).unwrap();
    watch("settings url", settings.url.as_bytes());
    let prepared = Prepared::new(settings);
    watch("request target", &prepared.target);
    assert!(!prepared.sealed.is_empty());
    let text = scrub(
        "header-canary password-canary",
        &prepared.settings.url,
        prepared
            .settings
            .auth_header
            .as_ref()
            .map(|h| h.value.as_str()),
    );
    assert!(!text.contains("password-canary"));
    drop(prepared);
    probe.finish().assert_wiped_on_linux(&[
        "decoded settings url",
        "settings JSON",
        "request target",
        "settings credential copy",
        "parsed url",
        "Basic value",
        "redaction part",
    ]);
}

#[test]
fn a_partly_deserialized_url_is_wiped_when_a_later_field_is_refused() {
    let probe = Probe::start();
    let result =
        parse(br#"{"url":"https://operator:refused-canary@receiver.example/","zz_unknown":true}"#);
    assert!(result.is_err());
    drop(result);
    probe
        .finish()
        .assert_wiped_on_linux(&["decoded settings url"]);
}

#[test]
fn a_settings_refusal_wipes_its_redaction_copies() {
    let probe = Probe::start();
    let refusal =
        parse(br#"{"url":"https://receiver.example/","auth_header":"Bearer refused-canary"}"#)
            .unwrap_err();
    assert!(!format!("{refusal:?}").contains("refused-canary"));
    probe
        .finish()
        .assert_wiped_on_linux(&["settings credential copy", "settings JSON"]);
}

pub(super) fn watch_settings_value(value: &serde_json::Value) {
    watch_value_as("settings JSON", value);
}

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
