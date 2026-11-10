// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

// Product assertions formerly exercised by core's export axis and conformance fixtures.
#[test]
fn loader_owned_webhook_shape_and_stream_contract() {
    assert!(Webhook::validate(br#"{"url":"https://collector.example/v1/logs"}"#).is_ok());
    assert!(
        refused(json!({"url":"https://collector.example", "bogus":1}))
            .starts_with("settings: unknown field `bogus`")
    );
    assert_eq!(STREAMS, &[ExportStream::Logs as u8]);
    let values = [(
        "audit".to_string(),
        json!({"url":"https://collector.example/in", "max_inflight_deliveries":0,"delivery_timeout_secs":0}),
    )];
    assert!(check(CheckPhase::Limits, &values)[0]
        .contains("settings.max_inflight_deliveries must be >= 1"));
    assert!(check(CheckPhase::Instances, &values)[0]
        .contains("sets settings.delivery_timeout_secs: 0 — it must be >= 1"));
}

#[test]
fn loader_owned_refused_target_is_reported_once_at_start_and_masked() {
    let host = AdmissionHost::new(Outcome::Refused).host();
    let mut at_open = usize::MAX;
    let capture = Capture::default();
    tracing::subscriber::with_default(capture.clone(), || {
        let sink = Webhook::open(br#"{"url":"http://127.0.0.1:1/said-once"}"#, &[], 1).unwrap();
        at_open = capture.0.lock().unwrap().len();
        assert!(matches!(
            sink.ready(
                &host,
                busbar_contract::abi::mechanism::ticket::Ticket {
                    slot: 0,
                    generation: 1
                }
            ),
            Poll::Ready(Ok(()))
        ));
        assert!(!sink.admitted(Some(&host)));
        assert!(!sink.admitted(Some(&host)));
    });
    let got = capture.0.lock().unwrap().clone();
    assert_eq!(at_open, 0);
    assert_eq!(got.len(), 1);
    assert!(field(&got[0], "message").contains("disabling this webhook exporter"));
    assert!(field(&got[0], "message").contains("http://127.0.0.1:1/***"));
    assert!(!field(&got[0], "message").contains("/said-once"));
}

#[test]
fn loader_owned_request_and_diagnostic_contract() {
    let s = settings(json!({"url":"https://collector.example/v1"}));
    let carried = request(&s, br#"{"n":2}"#);
    assert_eq!(carried.method, b"POST");
    assert_eq!(carried.target, b"/v1");
    assert_eq!(carried.body, br#"{"n":2}"#);
    let declared: serde_json::Value = serde_json::from_str(DECLARES).unwrap();
    assert!(declared["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .any(|d| d["code"] == 7072 && d["slug"] == "webhook-delivery-transport-error"));
}
