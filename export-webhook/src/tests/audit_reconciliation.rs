// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::tests::admission_host::AdmissionHost;
use serde_json::json;

#[test]
fn refusal_and_check_lines_hide_path_and_arbitrary_query_credentials() {
    let url =
        "https://hooks.example/services/path-credential-canary?opaque=query-credential-canary";
    let mut lines = check(
        CheckPhase::Instances,
        &[(
            "audit".into(),
            json!({
                "url": url, "delivery_timeout_secs": 0
            }),
        )],
    );
    lines.push(refusal_words(
        Some(url),
        &ConnFailure::Refused("destination refused".into()),
    ));
    assert_eq!(lines.len(), 2);
    for line in lines {
        assert!(line.contains("https://hooks.example/***?***"), "{line}");
        assert!(!line.contains("path-credential-canary"), "{line}");
        assert!(!line.contains("query-credential-canary"), "{line}");
    }
}

#[test]
fn a_receiver_echoing_only_the_authorization_credential_is_scrubbed() {
    for scheme in [
        "Bearer", "bearer", "Basic", "Bearer ", "Basic\t", " Bearer", "\tBasic",
    ] {
        let value = format!("{scheme} receiver-credential-canary");
        let words = scrub(
            "receiver rejected receiver-credential-canary",
            "https://hooks.example/",
            Some(&value),
        );
        assert_eq!(words, "receiver rejected ***");
    }
}

#[test]
fn an_admission_fault_does_not_permanently_disable_a_valid_target() {
    let broken = AdmissionHost::new(Outcome::Failed);
    let granted = AdmissionHost::new(Outcome::Ready);
    let hook = Webhook::open(br#"{"url":"https://hooks.example/"}"#, &[], 1).unwrap();
    assert!(!hook.admitted(Some(&broken.host())));
    assert!(hook.admitted(Some(&granted.host())));
}

#[test]
fn the_diagnostic_normalizes_embedded_whitespace_without_guessing_the_refusal() {
    let line = refusal_words(
        Some("ht\ttps://hooks.example/embedded-whitespace-path-canary"),
        &ConnFailure::Refused("destination refused".into()),
    );
    assert!(line.contains("destination refused"), "{line}");
    assert!(!line.contains("SSRF guard"), "{line}");
    assert!(line.contains("https://hooks.example/***"), "{line}");
    assert!(!line.contains("embedded-whitespace-path-canary"), "{line}");
}

#[test]
fn an_omitted_delivery_bound_retains_the_documented_default() {
    let parsed = parse(br#"{"url":"https://hooks.example/"}"#).unwrap();
    assert_eq!(parsed.max_inflight_deliveries, 64);
}

#[test]
fn checks_distinguish_named_instances_with_the_same_target() {
    let lines = check(
        CheckPhase::Instances,
        &[
            (
                "first".into(),
                json!({"url":"https://hooks.example/", "delivery_timeout_secs":0}),
            ),
            (
                "second".into(),
                json!({"url":"https://hooks.example/", "delivery_timeout_secs":0}),
            ),
        ],
    );
    assert_eq!(lines.len(), 2);
    assert!(lines[0].starts_with("export.first:"), "{}", lines[0]);
    assert!(lines[1].starts_with("export.second:"), "{}", lines[1]);
}
