// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The webhook sink tests itself (DECISIONS #2): its settings refusals, word for word as the
//! compiled-in sink's (1.5.5); what it asks the host to carry; and what it reports.

use super::*;
use serde_json::json;
use std::sync::{Arc, Mutex};

fn refused(settings: serde_json::Value) -> String {
    let r = Webhook::validate(settings.to_string().as_bytes()).expect_err("refused");
    assert_eq!(r.outcome(), Outcome::Failed);
    r.text().expect("a refusal says why").to_string()
}

/// The shape refusals are serde's, under the `settings:` prefix — the same derive, field order and
/// `deny_unknown_fields` the compiled-in `WebhookSettings` had.
#[test]
fn a_settings_shape_refusal_is_the_compiled_in_sinks_line() {
    assert_eq!(
        refused(json!({"url": "https://a.example/", "bogus": 1})),
        "settings: unknown field `bogus`, expected one of `url`, `auth_header`, \
         `max_inflight_deliveries`, `delivery_timeout_secs`"
    );
    assert_eq!(refused(json!({})), "settings: missing field `url`");
    assert_eq!(
        refused(json!({"url": "https://a/", "auth_header": {"name": "A"}})),
        "settings: missing field `value`"
    );
    assert!(Webhook::validate(br#"{"url":"https://a/","max_inflight_deliveries":0}"#).is_ok());
}

/// BOOT-083a / BOOT-083b / BOOT-089f: the validation-phase lines, one in-flight bound over the
/// instances (the largest), then each instance's deadline by its position.
#[test]
fn the_validation_phase_checks_are_the_compiled_in_sinks_lines() {
    let one = |v: serde_json::Value| {
        let instances = [("w".to_string(), v)];
        let mut lines = check(CheckPhase::Limits, &instances);
        lines.extend(check(CheckPhase::Instances, &instances));
        lines
    };
    assert_eq!(
        one(json!({"url": "https://a/", "max_inflight_deliveries": 0})),
        vec![
            "export.request-log-webhook.settings.max_inflight_deliveries must be >= 1 (a 0-permit \
             semaphore admits nothing, silently dropping every webhook delivery)"
        ]
    );
    assert_eq!(
        one(json!({"url": "https://a/", "max_inflight_deliveries": 2305843009213693952u64})),
        vec![
            "export.request-log-webhook.settings.max_inflight_deliveries must be <= \
             2305843009213693951 (tokio::sync::Semaphore's hard permit ceiling — a value above \
             it panics at build time instead of failing validation)"
        ]
    );
    assert!(
        one(json!({"url": "https://a/", "max_inflight_deliveries": 2305843009213693951u64}))
            .is_empty()
    );
    assert_eq!(
        one(json!({"url": "https://a/b", "delivery_timeout_secs": 0})),
        vec![
            "the `module: request-log-webhook` export instance targeting 'https://a/b' (#0) sets \
             settings.delivery_timeout_secs: 0, which would abort every delivery — it must be >= 1"
        ]
    );
    assert_eq!(
        one(json!({"url": "https://a/b", "delivery_timeout_secs": u64::MAX})),
        vec![format!(
            "the `module: request-log-webhook` export instance targeting 'https://a/b' (#0) sets \
             settings.delivery_timeout_secs: {}, above the 946080000-second (30-year) ceiling \
             every duration is bounded by — a delivery deadline that far out overflows the clock",
            u64::MAX
        )]
    );
    // A stingy sibling is not refused beside a generous one: the bound is the largest.
    let two_instances = [
        (
            "a".into(),
            json!({"url": "https://a/", "max_inflight_deliveries": 0}),
        ),
        (
            "b".into(),
            json!({"url": "https://b/", "max_inflight_deliveries": 8, "delivery_timeout_secs": 0}),
        ),
    ];
    let mut two = check(CheckPhase::Limits, &two_instances);
    two.extend(check(CheckPhase::Instances, &two_instances));
    assert_eq!(two.len(), 1, "{two:?}");
    assert!(two[0].contains("'https://b/' (#1)"), "{two:?}");
    assert!(check(CheckPhase::Limits, &[]).is_empty());
    // Each phase answers only its own lines: the deadline is not a limit, the bound not an
    // instance's own.
    let both = [(
        "w".to_string(),
        json!({"url": "https://a/", "max_inflight_deliveries": 0, "delivery_timeout_secs": 0}),
    )];
    assert_eq!(check(CheckPhase::Limits, &both).len(), 1);
    assert!(check(CheckPhase::Limits, &both)[0].contains("max_inflight_deliveries"));
    assert_eq!(check(CheckPhase::Instances, &both).len(), 1);
    assert!(check(CheckPhase::Instances, &both)[0].contains("delivery_timeout_secs"));
}

/// One logged event: every field it carried, by name, and its message.
type Event = Vec<(String, String)>;

/// The `tracing` events captured, in order.
#[derive(Default, Clone)]
struct Capture(Arc<Mutex<Vec<Event>>>);

struct Fields(Event);

impl tracing::field::Visit for Fields {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0
            .push((field.name().to_string(), format!("{value:?}")));
    }
}

impl tracing::Subscriber for Capture {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        let mut v = Fields(Vec::new());
        event.record(&mut v);
        self.0.lock().unwrap().push(v.0);
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

/// Run `f` and return every event it logged, in order.
fn logged(f: impl FnOnce()) -> Vec<Event> {
    let cap = Capture::default();
    tracing::subscriber::with_default(cap.clone(), f);
    let got = cap.0.lock().unwrap().clone();
    got
}

fn field(e: &Event, name: &str) -> String {
    e.iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v.clone())
        .unwrap_or_else(|| panic!("no `{name}` in {e:?}"))
}

fn settings(v: serde_json::Value) -> Settings {
    serde_json::from_value(v).expect("settings parse")
}

fn reply(status: u16) -> Result<ExchangeResponse, ConnFailure> {
    Ok(ExchangeResponse {
        status,
        ..ExchangeResponse::default()
    })
}

/// A delivery POSTs the compact JSON line to the target's path and query with
/// `content-type: application/json` then the auth header, under the instance's deadline.
#[test]
fn a_delivery_posts_the_line() {
    let s = settings(json!({
        "url": "https://siem.example/in?k=v",
        "auth_header": {"name": "Authorization", "value": "Bearer x"},
        "delivery_timeout_secs": 9
    }));
    let line = br#"{"ts":7,"pool":"p","outcome":"ok"}"#;
    assert_eq!(
        request(&s, line),
        Request {
            method: b"POST".to_vec(),
            target: b"/in?k=v".to_vec(),
            fields: vec![
                (b"content-type".to_vec(), b"application/json".to_vec()),
                (b"Authorization".to_vec(), b"Bearer x".to_vec()),
            ],
            body: line.to_vec(),
            timeout_ms: 9000,
        }
    );
    let bare = settings(json!({"url": "https://siem.example"}));
    assert_eq!(request(&bare, b"{}").target, b"/".to_vec());
    assert_eq!(request(&bare, b"{}").fields.len(), 1);
    assert_eq!(request(&bare, b"{}").timeout_ms, 2000);
}

/// A non-2xx answer and a transport failure each drop the line and raise their code at debug,
/// with the fields in the compiled-in site's order, the target's userinfo masked.
#[test]
fn a_failed_delivery_raises_its_code_once() {
    let url = "https://user:pw@siem.example/in";
    let got = logged(|| {
        report(url, reply(204));
        report(url, reply(503));
        report(url, Err(ConnFailure::Failed("timed out".into())));
    });
    let names = |e: &Event| {
        e.iter()
            .map(|(n, _)| n.clone())
            .filter(|n| n != "message")
            .collect::<Vec<_>>()
    };
    assert_eq!(got.len(), 2, "{got:?}");
    assert_eq!(names(&got[0]), ["diag", "webhook_url", "status"]);
    assert_eq!(field(&got[0], "diag"), "BUSBAR-7071");
    assert_eq!(
        field(&got[0], "webhook_url"),
        "\"https://***@siem.example/in\""
    );
    assert_eq!(field(&got[0], "status"), "503");
    assert_eq!(names(&got[1]), ["diag", "webhook_url", "error_kind"]);
    assert_eq!(field(&got[1], "diag"), "BUSBAR-7072");
    assert_eq!(field(&got[1], "error_kind"), "timed out");
    assert_eq!(
        field(&got[1], "message"),
        "request-log webhook delivery failed (transport error); this log was dropped"
    );
}

/// The 2xx boundary is 200..=299 (1.5.5's `is_success()`): 199 and 300 are each one BUSBAR-7071.
#[test]
fn the_success_boundary_is_200_to_299() {
    for (status, raises) in [(199u16, true), (200, false), (299, false), (300, true)] {
        let got = logged(|| report("https://a.example/", reply(status)));
        assert_eq!(got.len(), usize::from(raises), "{status}: {got:?}");
    }
}

/// With no verdict to be had, the instance is disabled once, in BUSBAR-7070's words, and stays so
/// until a reload asks again.
#[test]
fn an_unadmitted_target_disables_the_instance_once() {
    let w = Webhook::open(br#"{"url":"https://a.example/"}"#, &[], 1).expect("opens");
    let got = logged(|| {
        assert!(!w.admitted(None));
        assert!(!w.admitted(None));
    });
    assert_eq!(got.len(), 1, "{got:?}");
    assert_eq!(field(&got[0], "diag"), "BUSBAR-7070");
    assert_eq!(
        field(&got[0], "message"),
        "the instance was handed no connector; disabling this webhook exporter"
    );
    w.refresh(br#"{"url":"https://b.example/"}"#, &[], 2)
        .expect("a refresh applies");
    assert_eq!(logged(|| assert!(!w.admitted(None))).len(), 1);
    assert_eq!(w.settings().expect("parsed").url, "https://b.example/");
}

/// The Statement: name, the default in-flight bound, the module alias, the `logs` stream, no
/// route, and ONE outbound open-web need targeted by the `url` setting.
#[test]
fn the_statement_states_the_sink() {
    assert_eq!(STATEMENT.name.len, NAME.len());
    assert_eq!(STATEMENT.max_inflight, u32::MAX);
    assert_eq!(REWRITES[0].class, REWRITE_ALIAS);
    assert_eq!(REWRITES[0].from.len, ALIAS.len());
    assert_eq!(STREAMS, &[ExportStream::Logs as u8]);
    assert_eq!(TAIL.routes_len, 0);
    assert_eq!(STATEMENT.needs_len, 1);
    assert_eq!(NEEDS[0].direction, DIRECTION_OUTBOUND);
    assert_eq!(NEEDS[0].egress_class, EGRESS_OPEN_WEB);
    assert_eq!(NEEDS[0].target_from.len, "settings.url".len());
    assert_eq!(TARGET_FROM, "settings.url");
}

/// The declaration both doors state: the shed counter and the three catalogue codes it raises.
#[test]
fn the_declaration_states_the_shed_counter_and_the_codes() {
    let d: serde_json::Value = serde_json::from_str(DECLARES).unwrap();
    assert_eq!(ALIAS, "request-log-webhook");
    assert_eq!(
        d["metrics"],
        json!([{"name": "busbar_webhook_logs_dropped_total", "type": "counter", "shed": true}])
    );
    let codes: Vec<u64> = d["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["code"].as_u64().unwrap())
        .collect();
    assert_eq!(codes, vec![7070, 7071, 7072]);
}

/// Every metric a catalogue action cites (a backticked `*_total` token) is a series the declaration
/// states, not a Rust constant's name (EHOOK-14).
#[test]
fn a_catalogue_action_cites_only_declared_metrics() {
    let d: serde_json::Value = serde_json::from_str(DECLARES).unwrap();
    let declared: Vec<&str> = d["metrics"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["name"].as_str().unwrap())
        .collect();
    for c in d["diagnostics"].as_array().unwrap() {
        let action = c["action"].as_str().unwrap();
        for cited in action.split('`').skip(1).step_by(2) {
            if cited.to_ascii_lowercase().ends_with("_total") {
                assert!(
                    declared.contains(&cited),
                    "BUSBAR-{} cites `{cited}`, which is not a declared metric {declared:?}",
                    c["code"]
                );
            }
        }
    }
}

/// A validation error names the target, never its userinfo (EHOOK-3): the deadline refusals echo
/// the URL through the one mask the diagnostics use.
#[test]
fn validation_errors_mask_the_targets_userinfo() {
    for (url, shown) in [
        ("https://u:s3cret@h.example/x", "https://***@h.example/x"),
        ("https://:s3cret@h.example/x", "https://***@h.example/x"),
        ("https://s3cret@h.example/x", "https://***@h.example/x"),
        ("https://u:s3cret@/x", "https://***@/x"),
    ] {
        let instances = [(
            "w".to_string(),
            json!({"url": url, "delivery_timeout_secs": 0}),
        )];
        let lines = check(CheckPhase::Instances, &instances);
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(
            lines[0].contains(&format!("targeting '{shown}' (#0)")),
            "{lines:?}"
        );
        assert!(!lines[0].contains("s3cret"), "{lines:?}");
        let instances = [(
            "w".to_string(),
            json!({"url": url, "delivery_timeout_secs": u64::MAX}),
        )];
        let lines = check(CheckPhase::Instances, &instances);
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(
            lines[0].contains(&format!("targeting '{shown}' (#0)")),
            "{lines:?}"
        );
        assert!(!lines[0].contains("s3cret"), "{lines:?}");
    }
    assert_eq!(mask_userinfo("https://u:p@/x"), "https://***@/x");
}
