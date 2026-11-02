// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Exercises webhook settings, delivery and compatibility behavior.

use super::*;
#[path = "tests/admission_host.rs"]
mod admission_host;
use admission_host::AdmissionHost;
use serde_json::json;
use std::sync::{Arc, Mutex};

/// The request one line is POSTed as, under `s`: its plain part (the credential-bearing fields ride
fn request(s: &Settings, line: &[u8]) -> Request {
    Prepared::new(s.clone()).parts(line).0
}

/// Asserts the fields one POST under `s` sends, in order: `want` is `(name, value)` as the far end
fn sent(s: &Settings, want: &[(&str, &str)]) {
    let p = Prepared::new(s.clone());
    let (request, sealed) = p.parts(b"{}");
    let ex = Exchange::request_sealed(request, sealed).expect("a request that frames");
    let framed = ex.framed_fields();
    assert_eq!(framed.len(), want.len(), "{framed:?} vs {want:?}");
    let mut held = p.sealed.iter();
    for ((name, value), (want_name, want_value)) in framed.iter().zip(want) {
        assert_eq!(*name, want_name.as_bytes(), "{framed:?}");
        if *value == b"<sealed>" {
            let (_, _, cred) = held.next().expect("a sealed field the instance holds");
            assert!(cred.verify_eq(want_value.as_bytes()), "{want_name}");
        } else {
            assert_eq!(*value, want_value.as_bytes(), "{want_name}");
        }
    }
    assert!(held.next().is_none(), "every sealed field was framed");
}

/// Every sealed credential (Basic userinfo, `auth_header` value) of an https target is marked
/// secure-required, so the host refuses to carry it over an unsecured connection.
#[test]
fn sealed_credentials_of_an_https_target_are_secure_required() {
    let s: Settings = serde_json::from_value(json!({
        "url": "https://u:p@siem.example/in",
        "auth_header": {"name": "Authorization", "value": "Bearer x"}
    }))
    .expect("settings parse");
    let p = Prepared::new(s);
    assert!(p.sealed.len() >= 2, "userinfo and header value are sealed");
    for (_, name, cred) in &p.sealed {
        assert!(cred.secure_required(), "{}", String::from_utf8_lossy(name));
    }
}

fn refused(settings: serde_json::Value) -> String {
    let r = Webhook::validate(settings.to_string().as_bytes()).expect_err("refused");
    assert_eq!(r.outcome(), Outcome::Failed);
    r.text().expect("a refusal says why").to_string()
}

/// The shape refusals are serde's, under the `settings:` prefix — the same derive, field order and
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
            "the largest settings.max_inflight_deliveries among `module: request-log-webhook` \
             export instances must be >= 1"
        ]
    );
    assert_eq!(
        one(json!({"url": "https://a/", "max_inflight_deliveries": 2305843009213693952u64})),
        vec![
            "the largest settings.max_inflight_deliveries among `module: request-log-webhook` \
             export instances must be <= 2305843009213693951"
        ]
    );
    assert!(
        one(json!({"url": "https://a/", "max_inflight_deliveries": 2305843009213693951u64}))
            .is_empty()
    );
    assert_eq!(
        one(json!({"url": "https://a/b", "delivery_timeout_secs": 0})),
        vec![
            "export.w: the `module: request-log-webhook` export instance targeting 'https://a/***' (#0) sets \
             settings.delivery_timeout_secs: 0 — it must be >= 1"
        ]
    );
    assert_eq!(
        one(json!({"url": "https://a/b", "delivery_timeout_secs": u64::MAX})),
        vec![format!(
            "export.w: the `module: request-log-webhook` export instance targeting 'https://a/***' (#0) sets \
             settings.delivery_timeout_secs: {}, above the 946080000-second (30-year) ceiling \
             every duration is bounded by — a delivery deadline that far out overflows the clock",
            u64::MAX
        )]
    );
    // The accepted edges of the deadline: 1 second and the 30-year ceiling pass, one past it is refused.
    assert!(one(json!({"url": "https://a/b", "delivery_timeout_secs": 1})).is_empty());
    assert!(
        one(json!({"url": "https://a/b", "delivery_timeout_secs": MAX_DURATION_SECS})).is_empty()
    );
    assert_eq!(
        one(json!({"url": "https://a/b", "delivery_timeout_secs": MAX_DURATION_SECS + 1})).len(),
        1
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
    assert!(two[0].contains("'https://b' (#1)"), "{two:?}");
    assert!(check(CheckPhase::Limits, &[]).is_empty());

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
        v.0.push(("level".to_string(), event.metadata().level().to_string()));
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
            fields: vec![(b"content-type".to_vec(), b"application/json".to_vec())],
            body: line.to_vec(),
            timeout_ms: 9000,
        }
    );
    sent(
        &s,
        &[
            ("content-type", "application/json"),
            ("authorization", "Bearer x"),
        ],
    );
    let bare = settings(json!({"url": "https://siem.example"}));
    assert_eq!(request(&bare, b"{}").target, b"/".to_vec());
    sent(&bare, &[("content-type", "application/json")]);
    assert_eq!(request(&bare, b"{}").timeout_ms, 2000);
}

#[test]
fn a_userinfo_in_the_url_is_sent_as_basic_as_1_5_5_sent_it() {
    for (url, sent) in [
        (
            "https://user:pass@siem.example/in",
            Some("Basic dXNlcjpwYXNz"),
        ),
        (
            "https://Aladdin:open%20sesame@siem.example/in",
            Some("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="),
        ),
        ("https://user@siem.example/in", Some("Basic dXNlcjo=")),
        ("https://user:@siem.example/in", Some("Basic dXNlcjo=")),
        ("https://:pass@siem.example/in", Some("Basic OnBhc3M=")),
        (
            "https://us%40er:p%3Ass%20w@siem.example/in",
            Some("Basic dXNAZXI6cDpzcyB3"),
        ),
        (
            "https://jos%C3%A9:pw@siem.example/in",
            Some("Basic am9zw6k6cHc="),
        ),
        (
            "https://jos\u{e9}:pw@siem.example/in",
            Some("Basic am9zw6k6cHc="),
        ),
        ("https://a%zz:b@siem.example/in", Some("Basic YSV6ejpi")),
        ("https://u:%FF@siem.example/in", Some("Basic dTo=")),
        ("https://%FF:pw@siem.example/in", None),
        ("https://siem.example/in", None),
        ("not a url", None),
    ] {
        assert_eq!(
            basic_authorization(url).as_deref(),
            sent.map(str::as_bytes),
            "{url}"
        );
    }

    for (userinfo, encoded) in [
        ("f", "Basic Zjo="),
        ("fo", "Basic Zm86"),
        ("foo", "Basic Zm9vOg=="),
        ("foob", "Basic Zm9vYjo="),
        ("fooba", "Basic Zm9vYmE6"),
        ("foobar", "Basic Zm9vYmFyOg=="),
        ("xx:%EF%BF%BF", "Basic eHg677+/"),
    ] {
        let url = format!("https://{userinfo}@siem.example/in");
        assert_eq!(
            basic_authorization(&url).as_deref(),
            Some(encoded.as_bytes()),
            "{userinfo}"
        );
    }
}

#[test]
fn the_userinfo_field_rides_beside_a_configured_auth_header_as_in_1_5_5() {
    let basic = ("authorization", "Basic dXNlcjpwYXNz");
    let json = ("content-type", "application/json");
    let both = settings(json!({
        "url": "https://user:pass@siem.example/in?k=v",
        "auth_header": {"name": "Authorization", "value": "Bearer x"}
    }));
    sent(&both, &[basic, ("authorization", "Bearer x"), json]);
    assert_eq!(request(&both, b"{}").target, b"/in?k=v".to_vec());
    let other = settings(json!({
        "url": "https://user:pass@siem.example/in",
        "auth_header": {"name": "X-Api-Key", "value": "k"}
    }));
    sent(&other, &[basic, json, ("x-api-key", "k")]);
    let alone = settings(json!({"url": "https://user:pass@siem.example/in"}));
    sent(&alone, &[basic, json]);
}

#[test]
fn a_configured_auth_header_name_goes_lower_case_as_1_5_5_sent_it() {
    for (name, lowered) in [
        ("Authorization", "authorization"),
        ("X-Api-Key", "x-api-key"),
    ] {
        let s = settings(json!({
            "url": "https://siem.example/in",
            "auth_header": {"name": name, "value": "k"}
        }));
        sent(&s, &[("content-type", "application/json"), (lowered, "k")]);
    }
}

/// A non-2xx answer and a transport failure each drop the line and raise their code at WARN (1.5.5's
#[test]
fn a_failed_delivery_raises_its_code_once() {
    let url = "https://user:pw@siem.example/in";
    let got = logged(|| {
        report(url, None, reply(204));
        report(url, None, reply(503));
        report(url, None, Err(ConnFailure::Failed("timed out".into())));
    });
    let names = |e: &Event| {
        e.iter()
            .map(|(n, _)| n.clone())
            .filter(|n| n != "message" && n != "level")
            .collect::<Vec<_>>()
    };
    assert_eq!(got.len(), 2, "{got:?}");
    assert_eq!(names(&got[0]), ["diag", "webhook_url", "status"]);
    assert_eq!(field(&got[0], "diag"), "BUSBAR-7071");

    assert_eq!(
        field(&got[0], "webhook_url"),
        "\"https://***@siem.example/***\""
    );
    assert_eq!(field(&got[0], "status"), "503");
    assert_eq!(names(&got[1]), ["diag", "webhook_url", "error_kind"]);
    assert_eq!(field(&got[1], "diag"), "BUSBAR-7072");
    assert_eq!(field(&got[1], "error_kind"), "timed out");
    assert_eq!(field(&got[0], "level"), "WARN");
    assert_eq!(field(&got[1], "level"), "WARN");
    assert_eq!(
        field(&got[1], "message"),
        "request-log webhook delivery failed (transport error); this log was dropped"
    );
}

/// The 2xx boundary is 200..=299 (1.5.5's `is_success()`): 199 and 300 are each one BUSBAR-7071.
#[test]
fn the_success_boundary_is_200_to_299() {
    for (status, raises) in [(199u16, true), (200, false), (299, false), (300, true)] {
        let got = logged(|| report("https://a.example/", None, reply(status)));
        assert_eq!(got.len(), usize::from(raises), "{status}: {got:?}");
    }
}

/// A target the host refused is named in 1.5.5's words, as 1.5.5's `validate_webhook_url` named it:
#[test]
fn a_refused_target_is_named_in_1_5_5_words_when_it_is_the_scheme() {
    let refused = ConnFailure::Refused("destination refused".into());
    assert_eq!(
        refusal_words(Some("http://127.0.0.1:4000/sidecar"), &refused),
        "observability.request_log_webhook_url must be an https:// URL (got 'http://127.0.0.1:4000/***')"
    );
    assert_eq!(
        refusal_words(Some("HTTP://u:p@siem.example/in"), &refused),
        "observability.request_log_webhook_url must be an https:// URL (got 'http://***@siem.example/***')"
    );

    assert_eq!(
        refusal_words(Some("https://u:p@/x"), &refused),
        "observability.request_log_webhook_url is not a valid URL: empty host"
    );
    assert_eq!(
        refusal_words(Some("HTTPS://u:p@169.254.169.254/in"), &refused),
        "observability.request_log_webhook_url must not target a loopback/link-local/private/CGNAT/\
         cloud-metadata host (SSRF guard); got 'https://***@169.254.169.254/***'"
    );
    assert_eq!(
        refusal_words(Some("http://siem.example/in"), &ConnFailure::Unarmed),
        "the instance was handed no connector"
    );
    assert_eq!(refusal_words(None, &refused), "destination refused");
}

/// With no verdict to be had, the instance is disabled once, in BUSBAR-7070's words, and stays so
#[test]
fn an_unadmitted_target_disables_the_instance_once() {
    let w = Webhook::open(br#"{"url":"https://a.example/"}"#, &[], 1).expect("opens");
    let got = logged(|| {
        assert!(!w.admitted(None));
        assert!(!w.admitted(None));
    });
    assert_eq!(got.len(), 1, "{got:?}");
    assert_eq!(field(&got[0], "diag"), "BUSBAR-7070");
    assert_eq!(field(&got[0], "level"), "ERROR");
    assert_eq!(
        field(&got[0], "message"),
        "the instance was handed no connector; disabling this webhook exporter"
    );
    w.refresh(br#"{"url":"https://b.example/"}"#, &[], 2)
        .expect("a refresh applies");
    assert_eq!(logged(|| assert!(!w.admitted(None))).len(), 1);
    assert_eq!(w.settings().url, "https://b.example/");
}

/// The Statement: name, NO in-flight ceiling of its own (`u32::MAX`: the operator's
#[test]
fn the_statement_states_the_sink() {
    assert_eq!(STATEMENT.name.len, NAME.len());
    assert_eq!(STATEMENT.max_inflight, u32::MAX);
    assert_eq!(
        REWRITES[0].class,
        busbar_contract::abi::mechanism::door::REWRITE_ALIAS
    );
    assert_eq!(REWRITES[0].from.len, ALIAS.len());
    assert_eq!(STREAMS, &[ExportStream::Logs as u8]);
    assert_eq!(TAIL.routes_len, 0);
    assert_eq!(STATEMENT.needs_len, 1);
    assert_eq!(NEEDS[0].direction, DIRECTION_OUTBOUND);
    assert_eq!(NEEDS[0].egress_class, EGRESS_OPEN_WEB);
    assert_eq!(NEEDS[0].target_from.len, "settings.url".len());
    assert_eq!(TARGET_FROM, "settings.url");
}

/// The declaration both doors state: the shed counter and the four catalogue codes it raises.
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
    assert_eq!(codes, vec![7070, 7071, 7072, 7109]);
}

/// Every metric a catalogue action cites (a backticked `*_total` token) is a series the declaration
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
#[test]
fn validation_errors_mask_the_targets_userinfo() {
    for (url, shown) in [
        ("https://u:s3cret@h.example/x", "https://***@h.example/***"),
        ("https://:s3cret@h.example/x", "https://***@h.example/***"),
        ("https://s3cret@h.example/x", "https://***@h.example/***"),
        ("https://u:s3cret@/x", "https:***"),
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
    assert_eq!(mask_url("https://u:p@/x"), "https://***@/x");
}

/// The lines naming a userinfo target hide its path and normalize its scheme: the BUSBAR-7070
#[test]
fn the_lines_naming_a_userinfo_target_read_exactly() {
    use busbar_contract::abi::mechanism::call::Outcome;
    use busbar_contract::abi::mechanism::ticket::Ticket;
    use busbar_contract::abi::sdk::conn::Host;
    use std::task::Poll;
    let fake_host = AdmissionHost::new(Outcome::Refused);
    let tables = fake_host.lent();
    let host = Host::of(tables);
    for (url, line) in [
        (
            "HTTP://u:s3cret@siem.example/in",
            "observability.request_log_webhook_url must be an https:// URL (got \
             'http://***@siem.example/***'); disabling this webhook exporter",
        ),
        (
            "https://u:s3cret@169.254.169.254/in",
            "observability.request_log_webhook_url must not target a loopback/link-local/private/\
             CGNAT/cloud-metadata host (SSRF guard); got 'https://***@169.254.169.254/***'; \
             disabling this webhook exporter",
        ),
    ] {
        let settings = json!({ "url": url }).to_string();
        let w = Webhook::open(settings.as_bytes(), &[], 1).expect("opens");
        let got = logged(|| assert!(matches!(w.ready(&host, Ticket::NONE), Poll::Ready(Ok(())))));
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(field(&got[0], "diag"), "BUSBAR-7070");
        assert_eq!(field(&got[0], "message"), line);
    }

    let url = "https://u:s3cret@siem.example/in";
    let lines =
        |settings: serde_json::Value| check(CheckPhase::Instances, &[("w".to_string(), settings)]);
    assert_eq!(
        lines(json!({"url": url, "auth_header": {"name": "Bad Name", "value": "Bearer s3cret"}})),
        vec![
            "export.w: the `module: request-log-webhook` export instance targeting \
             'https://***@siem.example/***' (#0) sets settings.auth_header with a name or value \
             that is not a valid HTTP header (name \"Bad Name\": the name must be a non-empty RFC \
             9110 token, and the value may hold no control byte other than tab); 1.5.5 left such a \
             header out and sent the log without it — fix or remove the header"
                .to_string()
        ]
    );
    assert_eq!(
        lines(json!({"url": url, "delivery_timeout_secs": 0})),
        vec![
            "export.w: the `module: request-log-webhook` export instance targeting \
             'https://***@siem.example/***' (#0) sets settings.delivery_timeout_secs: 0 — it must be >= 1"
                .to_string()
        ]
    );
    assert_eq!(
        lines(json!({"url": url, "delivery_timeout_secs": u64::MAX})),
        vec![
            "export.w: the `module: request-log-webhook` export instance targeting \
             'https://***@siem.example/***' (#0) sets settings.delivery_timeout_secs: \
             18446744073709551615, above the 946080000-second (30-year) ceiling every duration \
             is bounded by — a delivery deadline that far out overflows the clock"
                .to_string()
        ]
    );
}

/// DISCOVERY AT BOOT: `ready` asks the host's verdict once and never refuses the boot. Over host
#[test]
fn ready_asks_the_verdict_at_boot_and_never_refuses_it() {
    use busbar_contract::abi::mechanism::ticket::Ticket;
    use std::task::Poll;

    let fake_host = AdmissionHost::new(Outcome::Refused);
    let host = busbar_contract::abi::sdk::conn::Host::of(fake_host.lent());
    let w = Webhook::open(br#"{"url":"http://127.0.0.1:4000/sidecar"}"#, &[], 1).expect("opens");
    let got = logged(|| assert!(matches!(w.ready(&host, Ticket::NONE), Poll::Ready(Ok(())))));
    assert_eq!(got.len(), 1, "{got:?}");
    assert_eq!(field(&got[0], "diag"), "BUSBAR-7070");
    assert_eq!(field(&got[0], "level"), "ERROR");
    assert_eq!(
        logged(|| assert!(!w.admitted(Some(&host)))).len(),
        0,
        "asked once"
    );
}

#[test]
fn a_refresh_never_shows_new_settings_beside_the_old_verdict() {
    let w = Webhook::open(br#"{"url":"https://a.example/x"}"#, &[], 1).expect("opens");
    *w.live.lock().unwrap() = Some(false);
    std::thread::scope(|scope| {
        let guard = w.live.lock().unwrap();
        scope.spawn(|| {
            w.refresh(br#"{"url":"https://b.example/x"}"#, &[], 2)
                .expect("refreshes")
        });
        for _ in 0..30 {
            std::thread::sleep(std::time::Duration::from_millis(10));
            assert_eq!(
                w.settings().url,
                "https://a.example/x",
                "new settings visible while the old verdict is still held"
            );
        }
        drop(guard);
    });
    assert_eq!(w.settings().url, "https://b.example/x");
    assert_eq!(*w.live.lock().unwrap(), None);
}

/// `ready` reads the HOST's verdict, not "no host": over a fake host whose `need.admit` refuses, an
#[test]
fn ready_reads_the_hosts_refusal_and_names_the_scheme_rule() {
    use busbar_contract::abi::mechanism::call::Outcome;
    use busbar_contract::abi::mechanism::ticket::Ticket;
    use busbar_contract::abi::sdk::conn::Host;
    use std::task::Poll;
    let fake_host = AdmissionHost::new(Outcome::Refused);
    let tables = fake_host.lent();
    let host = Host::of(tables);
    let w = Webhook::open(br#"{"url":"http://127.0.0.1:4000/sidecar"}"#, &[], 1).expect("opens");
    let got = logged(|| assert!(matches!(w.ready(&host, Ticket::NONE), Poll::Ready(Ok(())))));
    assert_eq!(got.len(), 1, "{got:?}");
    assert_eq!(field(&got[0], "diag"), "BUSBAR-7070");
    assert!(
        field(&got[0], "message").contains("must be an https:// URL"),
        "{got:?}"
    );
}

/// THE CHECK SLOT THROUGH THE DOOR: the phase maps to its check (an instance whose
#[test]
fn the_check_slot_maps_its_phase_and_leases_the_findings() {
    let probe = crate::wipe_probe::Probe::start();
    use busbar_contract::abi::export::{
        CheckIn, CheckInstance, CheckOut, CHECK_PHASE_INSTANCES, CHECK_PHASE_LIMITS,
    };
    use busbar_contract::abi::mechanism::call::{AbiStr, Blob, Outcome};
    use busbar_contract::abi::mechanism::lifecycle::slot;
    use busbar_contract::abi::sdk::door::{blank_in, blank_out};
    use busbar_plugin_loader::dispatch::Frame;
    let settings = br#"{"url":"https://a.example/x","delivery_timeout_secs":0}"#;
    let (_dispatcher, plugin) = loaded_for_test(settings);
    let rows = [CheckInstance {
        name: AbiStr::of("w"),
        settings: Blob::json(settings),
    }];
    let check = |phase| {
        let mut input: CheckIn = blank_in();
        input.phase = phase;
        input.instances = rows.as_ptr();
        input.instances_len = rows.len();
        let mut frame = Frame::new(input, blank_out::<CheckOut>());
        let called = plugin.call(busbar_contract::abi::export::slot::CHECK, &mut frame);
        let owned = if frame.out.findings.len == 0 {
            Vec::new()
        } else {
            // SAFETY: the actual loader judged these findings and the result lease is live.
            unsafe { std::slice::from_raw_parts(frame.out.findings.ptr, frame.out.findings.len) }
                .to_vec()
        };
        if called.lease != 0 {
            let mut release: busbar_contract::abi::mechanism::lifecycle::ReleaseIn = blank_in();
            release.lease = called.lease;
            assert_eq!(
                plugin
                    .call(
                        slot::RELEASE,
                        &mut Frame::new(
                            release,
                            blank_out::<busbar_contract::abi::mechanism::call::OutHead>()
                        )
                    )
                    .outcome,
                Outcome::Ready
            );
        }
        (called, owned)
    };
    let expected = crate::check(
        CheckPhase::Instances,
        &[("w".to_string(), serde_json::from_slice(settings).unwrap())],
    );
    assert!(!expected.is_empty(), "a 0-second deadline is a finding");
    let (found, owned) = check(CHECK_PHASE_INSTANCES);
    assert_eq!(found.outcome, Outcome::Ready);
    let lines: Vec<String> = serde_json::from_slice(&owned).expect("a JSON array");
    assert_eq!(lines, expected);
    let (limits, owned) = check(CHECK_PHASE_LIMITS);
    assert_eq!(limits.outcome, Outcome::Ready);
    assert!(owned.is_empty(), "{owned:?}");
    let (unknown, _) = check(7);
    assert_eq!(unknown.outcome, Outcome::Refused);
    assert_eq!(
        unknown.error.as_deref(),
        Some(crate::UNKNOWN_PHASE.as_bytes())
    );
    let closed = plugin.call(
        slot::CLOSE,
        &mut Frame::new(
            blank_in::<busbar_contract::abi::mechanism::call::InHead>(),
            blank_out::<busbar_contract::abi::mechanism::call::OutHead>(),
        ),
    );
    assert_eq!(closed.outcome, Outcome::Ready);
    drop(plugin);
    drop(_dispatcher);
    probe
        .finish()
        .assert_wiped_on_linux(&["check settings JSON"]);
}

#[test]
fn an_auth_header_1_5_5_could_not_build_is_left_out_and_the_line_still_sent() {
    let json = ("content-type", "application/json");
    for (name, value) in [
        ("Bad Name", "Bearer x"),
        ("", "Bearer x"),
        ("X-K\u{e9}y", "k"),
        ("Authorization:", "k"),
        ("Authorization", "Bearer x\r\nX-Injected: 1"),
        ("Authorization", "Bearer \u{7f}"),
        ("Authorization", "Bearer \u{0}"),
    ] {
        let s = settings(json!({
            "url": "https://siem.example/in",
            "auth_header": {"name": name, "value": value}
        }));
        sent(&s, &[json]);
    }
    for (name, value) in [
        ("X-Api-Key", "k\tv"),
        ("x!#$%&'*+-.^_`|~1", "caf\u{e9} \"ok\""),
        ("Authorization", ""),
    ] {
        let s = settings(json!({
            "url": "https://siem.example/in",
            "auth_header": {"name": name, "value": value}
        }));
        sent(&s, &[json, (&name.to_ascii_lowercase(), value)]);
    }
}

#[test]
fn the_settings_schema_marks_no_nested_secret() {
    let schema: serde_json::Value = serde_json::from_str(include_str!("../settings.schema.json"))
        .expect("the settings schema is JSON");
    let props = schema["properties"].as_object().expect("root properties");
    let mut keys: Vec<&str> = props.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "auth_header",
            "delivery_timeout_secs",
            "max_inflight_deliveries",
            "url"
        ]
    );
    fn marked_below_root(v: &serde_json::Value, depth: u32) -> bool {
        match v {
            serde_json::Value::Object(o) => {
                (depth > 1 && o.get("x-busbar-secret").is_some())
                    || o.iter().any(|(k, child)| {
                        let deeper = if k == "properties" { depth + 1 } else { depth };
                        match child {
                            serde_json::Value::Object(m) if k == "properties" => {
                                m.values().any(|f| marked_below_root(f, deeper))
                            }
                            _ => marked_below_root(child, depth),
                        }
                    })
            }
            serde_json::Value::Array(a) => a.iter().any(|x| marked_below_root(x, depth)),
            _ => false,
        }
    }
    assert!(
        !marked_below_root(&schema, 0),
        "no secret marker below the root"
    );
    let header_values = schema["properties"]["auth_header"]["properties"]["value"]["oneOf"]
        .as_array()
        .expect("header values accept literals and resolved references");
    assert!(header_values.iter().any(|v| v["type"] == "string"));
    assert!(header_values
        .iter()
        .any(|v| v["$ref"] == "#/$defs/reference"));
    let description = schema["properties"]["auth_header"]["properties"]["value"]["description"]
        .as_str()
        .expect("a description");
    assert!(!description.contains("${"), "{description}");
    assert!(description.contains("reference"), "{description}");
}

#[test]
fn the_auth_header_value_is_redacted_from_debug() {
    let header = ExportAuthHeader {
        name: "Authorization".into(),
        value: String::from("Bearer s3cret-token").into(),
    };
    let settings = WebhookSettings {
        url: "https://siem.example/in".into(),
        auth_header: Some(header.clone()),
        max_inflight_deliveries: 1,
        delivery_timeout_secs: 1,
    };
    for text in [
        format!("{header:?}"),
        format!("{header:#?}"),
        format!("{settings:?}"),
        format!("{settings:#?}"),
    ] {
        assert!(!text.contains("s3cret"), "the value leaked: {text}");
        assert!(text.contains("Authorization"), "the name is kept: {text}");
        assert!(
            text.contains("<redacted>"),
            "the value is marked redacted: {text}"
        );
    }
}

/// THE TARGET URL'S USERINFO NEVER RENDERS THROUGH `Debug` (§11.13): a `user:password@` in the url is
#[test]
fn the_url_userinfo_is_masked_in_debug() {
    let settings = WebhookSettings {
        url: "https://ops:hunter2@siem.example/in".into(),
        auth_header: None,
        max_inflight_deliveries: 1,
        delivery_timeout_secs: 1,
    };
    for text in [format!("{settings:?}"), format!("{settings:#?}")] {
        assert!(!text.contains("hunter2"), "the password leaked: {text}");
        assert!(text.contains("siem.example"), "the host is kept: {text}");
    }
}

const CANARY: &str = "CANARY7f2a9e";

/// Every string any captured event carries, flattened, for a canary search.
fn all_text(events: &[Event]) -> String {
    events
        .iter()
        .flat_map(|e| e.iter().map(|(n, v)| format!("{n}={v}\n")))
        .collect()
}

#[test]
fn a_mistyped_auth_header_never_reaches_the_refusal() {
    let r =
        refused(json!({"url": "https://a.example/", "auth_header": format!("Bearer {CANARY}")}));
    assert!(
        !r.contains(CANARY),
        "the refusal carried the credential: {r}"
    );

    assert!(r.starts_with("settings: invalid type: string "), "{r}");
    assert!(r.contains("expected struct ExportAuthHeader"), "{r}");

    let r = refused(
        json!({"url": "https://a.example/", "auth_header": {"name": "Authorization", "value": [format!("Bearer {CANARY}")]}}),
    );
    assert!(
        !r.contains(CANARY),
        "the refusal carried the credential: {r}"
    );
}

#[test]
fn a_failed_delivery_never_logs_the_targets_path_query_or_the_hosts_echo_of_them() {
    let url = format!("https://hooks.example/services/T000/B000/{CANARY}?api_key={CANARY}x");
    let got = logged(|| {
        report(&url, None, reply(503));
        report(
            &url,
            None,
            Err(ConnFailure::Failed(format!(
                "error sending request for url ({url}): connection reset"
            ))),
        );
    });
    assert_eq!(got.len(), 2, "{got:?}");
    let text = all_text(&got);
    assert!(
        !text.contains(CANARY),
        "a delivery log carried the credential:\n{text}"
    );

    assert!(text.contains("hooks.example"), "{text}");
}

/// The scrub also covers the percent-decoded forms: a host that echoes the URL decoded (`p@ss`,
/// `/hook/T/X`) must not leak what the encoded URL hid.
#[test]
fn a_failed_delivery_never_logs_the_percent_decoded_credential_or_path() {
    let url = format!("https://u:p%40ss-{CANARY}@hooks.example/hook/T%2F{CANARY}");
    let got = logged(|| {
        report(
            &url,
            None,
            Err(ConnFailure::Failed(format!(
                "error sending request for https://u:p@ss-{CANARY}@hooks.example/hook/T/{CANARY}: reset"
            ))),
        );
    });
    assert_eq!(got.len(), 1, "{got:?}");
    let text = all_text(&got);
    assert!(
        !text.contains(CANARY),
        "a delivery log carried the decoded credential:\n{text}"
    );
    assert!(text.contains("hooks.example"), "{text}");
}

/// The log target keeps scheme, host and port; everything that can carry a secret is `***`.
#[test]
fn the_log_target_names_only_scheme_host_and_port() {
    assert_eq!(log_target("https://a.example/"), "https://a.example");
    assert_eq!(
        log_target("https://a.example:8443"),
        "https://a.example:8443"
    );
    assert_eq!(
        log_target("https://u:p@a.example/s/T/B/X?k=v#f"),
        "https://***@a.example/***?***"
    );
    assert_eq!(log_target("https://u:p@/x"), "https:***");
    assert_eq!(log_target("not a url"), "***");
}

#[test]
fn open_and_refresh_refuse_settings_that_do_not_parse() {
    let bad = br#"{"url":"https://a.example/","bogus":1}"#;
    let want = Webhook::validate(bad).expect_err("refused");
    let opened = Webhook::open(bad, &[], 1).expect_err("open refuses");
    assert_eq!(opened, want);
    let w = Webhook::open(br#"{"url":"https://a.example/"}"#, &[], 1).expect("opens");
    assert_eq!(w.refresh(bad, &[], 2).expect_err("refresh refuses"), want);
    assert_eq!(
        w.settings().url,
        "https://a.example/",
        "a refused refresh keeps the old settings"
    );
}

#[test]
fn an_ambiguous_url_is_refused_without_its_credential() {
    for (url, secret) in [
        ("https://tok/en@siem.example/in", "tok/en"),
        ("https://u:123/x@siem.example/in", "u:123/x"),
        ("https://siem.example/in?k=a@b", "k=a"),
    ] {
        let settings = json!({ "url": url }).to_string();
        let refusal = Webhook::validate(settings.as_bytes()).expect_err(url);
        let text = refusal.text().expect("a refusal says why");
        assert!(text.contains("is ambiguous"), "{text}");
        assert!(text.contains("%2F"), "{text}");
        assert!(!text.contains(secret), "{url}: {text}");
        assert!(Webhook::open(settings.as_bytes(), &[], 1).is_err(), "{url}");
        // A reload to the ambiguous url is refused the same way, the old settings staying.
        let w = Webhook::open(br#"{"url":"https://a.example/"}"#, &[], 1).expect("opens");
        let refusal = w.refresh(settings.as_bytes(), &[], 2).expect_err(url);
        let text = refusal.text().expect("a refusal says why");
        assert!(text.contains("is ambiguous"), "{url}: {text}");
        assert!(!text.contains(secret), "{url}: {text}");
    }
    for url in [
        "https://u:p@siem.example/in",
        "https://tok%2Fen@siem.example/in",
        "https://siem.example/%40in",
    ] {
        let settings = json!({ "url": url }).to_string();
        assert!(Webhook::validate(settings.as_bytes()).is_ok(), "{url}");
    }
}

#[test]
fn serve_is_refused_saying_why_through_the_door() {
    use busbar_contract::abi::export::{ServeIn, ServeOut};
    use busbar_contract::abi::mechanism::call::{InHead, OutHead, Outcome};
    use busbar_contract::abi::mechanism::lifecycle::slot;
    use busbar_contract::abi::sdk::door::{blank_in, blank_out};
    use busbar_plugin_loader::dispatch::Frame;
    let (_dispatcher, plugin) = loaded_for_test(br#"{"url":"https://a.example/x"}"#);
    let c = plugin.call(
        busbar_contract::abi::export::slot::SERVE,
        &mut Frame::new(blank_in::<ServeIn>(), blank_out::<ServeOut>()),
    );
    assert_eq!(c.outcome, Outcome::Refused);
    assert_eq!(c.error.as_deref(), Some(crate::NO_ROUTE.as_bytes()));
    let closed = plugin.call(
        slot::CLOSE,
        &mut Frame::new(blank_in::<InHead>(), blank_out::<OutHead>()),
    );
    assert_eq!(closed.outcome, Outcome::Ready);
}

#[test]
fn an_auth_header_that_cannot_be_built_is_refused_at_validation() {
    for (name, value) in [
        (":authority", "k"),
        ("Bad Name", "k"),
        ("Authorization", "Bearer s3cret\r\nX-Injected: 1"),
        ("Authorization", "Bearer s3cret\n"),
    ] {
        let instances = [(
            "w".to_string(),
            json!({"url": "https://a.example/", "auth_header": {"name": name, "value": value}}),
        )];
        let lines = check(CheckPhase::Instances, &instances);
        assert_eq!(lines.len(), 1, "{name:?}: {lines:?}");
        assert!(lines[0].contains("settings.auth_header"), "{}", lines[0]);
        assert!(
            lines[0].contains("targeting 'https://a.example' (#0)"),
            "{}",
            lines[0]
        );
        assert!(
            !lines[0].contains("s3cret"),
            "the value leaked: {}",
            lines[0]
        );
    }
    let ok = [(
        "w".to_string(),
        json!({"url": "https://a.example/", "auth_header": {"name": "Authorization", "value": "Bearer x"}}),
    )];
    assert!(check(CheckPhase::Instances, &ok).is_empty());
}

/// A reload that lands back on the settings a batch started under (A -> B -> A) is no reload for
#[test]
fn a_reload_back_to_the_same_settings_does_not_cut_the_batch() {
    let w = Webhook::open(br#"{"url":"https://a.example/"}"#, &[], 1).expect("opens");
    let (settings, generation) = w.current();
    let mut at = Posting {
        settings,
        generation,
        offset: 0,
        issued: 0,
        exchange: None,
        bindings_pinned: false,
        host: None,
    };
    assert!(!w.reloaded_since(&mut at));
    w.refresh(br#"{"url":"https://b.example/"}"#, &[], 2)
        .expect("B");
    w.refresh(br#"{"url":"https://a.example/"}"#, &[], 3)
        .expect("A");
    assert!(
        !w.reloaded_since(&mut at),
        "A -> B -> A continues the batch"
    );
    w.refresh(br#"{"url":"https://b.example/"}"#, &[], 4)
        .expect("B");
    assert!(w.reloaded_since(&mut at), "a different target cuts it");
}

/// The section `Migration` answers for `settings`, from 1.5.5.
fn migrated(settings: serde_json::Value) -> Migrated {
    Migration::migrate(settings, "1.5.5")
}

/// Whether 1.6.0's validation refuses `settings` for their auth header.
fn auth_header_refused(settings: &serde_json::Value) -> bool {
    check(
        CheckPhase::Instances,
        &[("w".to_string(), settings.clone())],
    )
    .iter()
    .any(|l| l.contains("settings.auth_header"))
}

#[test]
fn an_auth_header_1_5_5_never_sent_is_removed_by_the_migration() {
    for (name, value) in [
        (":authority", "k"),
        ("Bad Name", "Bearer s3cret"),
        ("", "Bearer s3cret"),
        ("X-K\u{e9}y", "k"),
        ("Authorization:", "k"),
        ("Authorization", "Bearer s3cret\r\nX-Injected: 1"),
        ("Authorization", "Bearer s3cret\n"),
        ("Authorization", "Bearer \u{7f}"),
        ("Authorization", "Bearer \u{0}"),
        ("Host", "other.example"),
        ("content-length", "0"),
        ("Connection", "close"),
    ] {
        let before = json!({
            "url": "https://u:p@siem.example/in",
            "auth_header": {"name": name, "value": value},
            "delivery_timeout_secs": 5
        });
        assert!(auth_header_refused(&before), "{name:?}: {value:?}");
        let m = migrated(before);
        assert_eq!(
            m.settings,
            json!({"url": "https://u:p@siem.example/in", "delivery_timeout_secs": 5}),
            "{name:?}: {value:?}"
        );
        let want = if is_framing(name) {
            let literal = format!(
                "removed settings.auth_header.name `{name}` is a framing/connection field the \
                 http framer states itself; 1.6.0 does not send it, which 1.6.0 refuses at \
                 validation and open"
            );
            assert_eq!(removed_framing_header(name), literal);
            literal
        } else {
            REMOVED_AUTH_HEADER.to_string()
        };
        assert_eq!(m.report, vec![want]);
        assert!(m.needs.is_empty());
        assert!(!auth_header_refused(&m.settings));
        assert!(Webhook::validate(m.settings.to_string().as_bytes()).is_ok());
        assert!(Webhook::open(m.settings.to_string().as_bytes(), &[], 1).is_ok());
    }
    assert!(REMOVED_AUTH_HEADER.starts_with("removed settings.auth_header"));
    assert!(REMOVED_AUTH_HEADER.ends_with("which 1.6.0 refuses at validation and open"));
}

/// The header's value may be a reference the kernel resolves (`auth_header.value` is a declared
#[test]
fn a_referenced_value_is_judged_by_the_headers_name_alone() {
    let m = migrated(json!({
        "url": "https://siem.example/in",
        "auth_header": {"name": "Bad Name", "value": {"env": "WEBHOOK_TOKEN"}}
    }));
    assert_eq!(m.settings, json!({"url": "https://siem.example/in"}));
    assert_eq!(m.report, vec![REMOVED_AUTH_HEADER.to_string()]);
    let kept = json!({
        "url": "https://siem.example/in",
        "auth_header": {"name": "Authorization", "value": {"env": "WEBHOOK_TOKEN"}}
    });
    assert_eq!(migrated(kept.clone()), Migrated::unchanged(kept));
}

/// Everything 1.6.0 does not refuse for its auth header passes through unchanged, with nothing to
#[test]
fn a_section_1_6_0_does_not_refuse_for_its_header_is_unchanged() {
    for settings in [
        json!({"url": "https://siem.example/in", "auth_header": {"name": "Authorization", "value": "Bearer x"}}),
        json!({"url": "https://siem.example/in", "auth_header": {"name": "X-Api-Key", "value": "k\tv"}}),
        json!({"url": "https://siem.example/in", "auth_header": {"name": "x!#$%&'*+-.^_`|~1", "value": "caf\u{e9}"}}),
        json!({"url": "https://siem.example/in", "auth_header": {"name": "Authorization", "value": ""}}),
        json!({"url": "https://siem.example/in"}),
        json!({"url": "https://siem.example/in", "auth_header": null}),
        serde_json::Value::Null,
        json!("not a section"),
        json!({"url": "https://siem.example/in", "auth_header": {"name": "Bad Name", "value": "k"}, "bogus": 1}),
        json!({"auth_header": {"name": "Bad Name", "value": "k"}}),
        json!({"url": "https://siem.example/in", "auth_header": "Bearer s3cret"}),
    ] {
        assert!(!auth_header_refused(&settings), "{settings}");
        assert_eq!(
            migrated(settings.clone()),
            Migrated::unchanged(settings.clone()),
            "{settings}"
        );
    }
}

/// NO DECLARED CODE IS ONE THE CORE'S CATALOGUE HOLDS: the core at `.busbar-ref` (`BUSBAR_CHECKOUT`,
#[test]
fn no_declared_code_is_one_the_core_catalogue_holds() {
    let busbar = std::env::var_os("BUSBAR_CHECKOUT").expect(
        "BUSBAR_CHECKOUT is unset: the core catalogue is busbar's at .busbar-ref (plugin-ci exports it)",
    );
    let path =
        std::path::PathBuf::from(busbar).join("crates/busbar-kernel/src/diagnostics/catalog.toml");
    let catalog = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("the core catalogue at {}: {e}", path.display()));
    let held: std::collections::BTreeSet<u64> = catalog
        .lines()
        .filter_map(|l| l.trim().strip_prefix("code"))
        .filter_map(|rest| rest.trim().strip_prefix('='))
        .filter_map(|n| n.trim().parse().ok())
        .collect();
    assert!(
        !held.is_empty(),
        "no `code = N` row read from {}",
        path.display()
    );
    let declares: serde_json::Value = serde_json::from_str(DECLARES).unwrap();
    for d in declares["diagnostics"].as_array().unwrap() {
        let code = d["code"].as_u64().unwrap();
        assert!(
            !held.contains(&code),
            "BUSBAR-{code:04} ({}) is a code the core catalogue at {} already holds",
            d["slug"],
            path.display()
        );
    }
}

#[test]
fn a_formatted_prepared_or_webhook_carries_no_secret() {
    let w = Webhook::open(
        json!({
            "url": "https://ops:hunter2@siem.example/services/PATHSECRET?api_key=QUERYSECRET",
            "auth_header": {"name": "X-Api-Key", "value": "HEADERSECRET"}
        })
        .to_string()
        .as_bytes(),
        &[],
        1,
    )
    .expect("opens");
    let p = w.settings();

    let basic = "b3BzOmh1bnRlcjI=";
    for text in [
        format!("{p:?}"),
        format!("{p:#?}"),
        format!("{w:?}"),
        format!("{w:#?}"),
    ] {
        for secret in [
            "hunter2",
            "PATHSECRET",
            "QUERYSECRET",
            "HEADERSECRET",
            basic,
        ] {
            assert!(!text.contains(secret), "`{secret}` leaked: {text}");
        }
        assert!(text.contains("siem.example"), "the host is kept: {text}");
        assert!(
            text.contains("X-Api-Key"),
            "the header name is kept: {text}"
        );
    }

    let settings: &Settings = &p;
    for text in [format!("{settings:?}"), format!("{settings:#?}")] {
        for secret in ["hunter2", "PATHSECRET", "QUERYSECRET", "HEADERSECRET"] {
            assert!(!text.contains(secret), "`{secret}` leaked: {text}");
        }
    }
    let (request, _) = p.parts(b"{}");
    let text = format!("{request:?}");
    for secret in ["hunter2", "HEADERSECRET", basic] {
        assert!(!text.contains(secret), "`{secret}` leaked: {text}");
    }
}

#[test]
fn open_and_refresh_refuse_an_auth_header_that_cannot_be_sent() {
    let words = "settings: `auth_header` cannot be sent as an HTTP header";
    let bad = json!({"url": "https://a.example/", "auth_header": {"name": "A", "value": "tok\n"}});
    let bytes = bad.to_string();
    let r = Webhook::open(bytes.as_bytes(), &[], 1).expect_err("open refuses");
    assert_eq!(r.outcome(), Outcome::Failed);
    assert_eq!(r.text(), Some(words));
    let w = Webhook::open(br#"{"url":"https://a.example/"}"#, &[], 1).expect("opens");
    let r = w
        .refresh(bytes.as_bytes(), &[], 2)
        .expect_err("refresh refuses");
    assert_eq!(r.text(), Some(words));
    assert_eq!(w.settings().auth_header, None, "the old settings stay");

    assert_eq!(
        Webhook::validate(bytes.as_bytes())
            .expect_err("refused")
            .text(),
        Some(words)
    );
}

#[test]
fn a_framing_or_connection_header_is_refused() {
    for name in [
        "content-length",
        "Transfer-Encoding",
        "HOST",
        "connection",
        "te",
        "upgrade",
        "trailer",
        "keep-alive",
        "proxy-connection",
    ] {
        let words = format!(
            "settings.auth_header.name `{name}` is a framing/connection field the http framer \
             states itself; 1.6.0 does not send it"
        );
        assert_eq!(words, framing_words(name));
        let s = json!({"url": "https://a.example/", "auth_header": {"name": name, "value": "1"}});
        let lines = check(CheckPhase::Instances, &[("w".to_string(), s.clone())]);
        assert_eq!(lines.len(), 1, "{name}: {lines:?}");
        assert!(lines[0].contains("settings.auth_header"), "{}", lines[0]);
        let r = Webhook::open(s.to_string().as_bytes(), &[], 1).expect_err(name);
        assert_eq!(r.text(), Some(words.as_str()), "{name}");
    }
}

#[test]
fn a_reload_of_only_the_deadline_or_bound_does_not_cut_the_batch() {
    let w = Webhook::open(
        br#"{"url":"https://a.example/","auth_header":{"name":"K","value":"one"}}"#,
        &[],
        1,
    )
    .expect("opens");
    let (settings, generation) = w.current();
    let mut at = Posting {
        settings,
        generation,
        offset: 0,
        issued: 0,
        exchange: None,
        bindings_pinned: false,
        host: None,
    };
    w.refresh(
        br#"{"url":"https://a.example/","auth_header":{"name":"K","value":"one"},
             "delivery_timeout_secs":9,"max_inflight_deliveries":3}"#,
        &[],
        2,
    )
    .expect("timeout and bound only");
    assert!(
        !w.reloaded_since(&mut at),
        "a deadline/bound change cut the batch"
    );
    assert_eq!(
        w.settings().delivery_timeout_secs,
        9,
        "new deliveries use it"
    );
    assert_eq!(w.settings().parts(b"{}").0.timeout_ms, 9000);
    w.refresh(
        br#"{"url":"https://a.example/","auth_header":{"name":"K","value":"two"}}"#,
        &[],
        3,
    )
    .expect("credential");
    assert!(w.reloaded_since(&mut at), "a credential change cuts it");
}

#[test]
fn a_finding_is_numbered_by_the_configured_position() {
    let instances = [
        ("a".to_string(), json!({"bogus": 1})),
        (
            "b".to_string(),
            json!({"url": "https://b.example/", "delivery_timeout_secs": 0}),
        ),
    ];
    let lines = check(CheckPhase::Instances, &instances);
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(lines[0].contains("(#1)"), "{lines:?}");
}

#[test]
fn leading_controls_and_spaces_do_not_hide_the_scheme() {
    let refused = ConnFailure::Refused("destination refused".into());
    for url in [
        " https://10.0.0.5/hook",
        "\u{1}\u{1f}  HTTPS://10.0.0.5/hook",
    ] {
        let words = refusal_words(Some(url), &refused);
        assert!(words.contains("(SSRF guard)"), "{url:?}: {words}");
        assert!(
            !words.contains("must be an https:// URL"),
            "{url:?}: {words}"
        );
    }
    let words = refusal_words(Some(" http://10.0.0.5/hook"), &refused);
    assert!(words.contains("must be an https:// URL"), "{words}");
}

#[test]
fn only_an_undeclared_need_keeps_the_hosts_own_words() {
    use busbar_contract::conn::ConnError;
    let url = "https://ops:hunter2@siem.example/services/PATHSECRET?k=QUERYSECRET";
    let undeclared =
        ConnFailure::Refused(format!("{} (for {url})", ConnError::UndeclaredNeed.text()));
    let exact = ConnFailure::Refused(ConnError::UndeclaredNeed.text().to_string());
    for refused in [&undeclared, &exact] {
        let words = refusal_words(Some(url), refused);
        assert!(
            words.starts_with(ConnError::UndeclaredNeed.text()),
            "{words}"
        );
        assert!(!words.contains("SSRF"), "{words}");
        for secret in ["hunter2", "PATHSECRET", "QUERYSECRET"] {
            assert!(!words.contains(secret), "`{secret}` leaked: {words}");
        }
    }

    let connection = ConnFailure::Refused(ConnError::Refused.text().to_string());
    assert!(refusal_words(Some("https://10.0.0.5/in"), &connection).contains("(SSRF guard)"));

    assert!(refusal_words(Some("http://10.0.0.5/in"), &connection).contains("must be an https://"));
}

#[test]
fn a_reload_of_the_target_mid_batch_drops_the_rest_once() {
    let batch = b"{\"n\":1}\n{\"n\":2}\n\n{\"n\":3}\n";
    let w = Webhook::open(br#"{"url":"https://a.example/"}"#, &[], 1).expect("opens");
    let (settings, generation) = w.current();
    let mut at = Posting {
        settings,
        generation,
        offset: 0,
        issued: 0,
        exchange: None,
        bindings_pinned: false,
        host: None,
    };

    let (first, next) = next_line(batch, at.offset).expect("line 1");
    assert_eq!(first, b"{\"n\":1}");
    w.refresh(br#"{"url":"https://b.example/"}"#, &[], 2)
        .expect("the reload");

    assert_eq!(at.settings.url, "https://a.example/");

    let got = logged(|| assert!(w.cut_by_reload(&mut at, &batch[next..])));
    assert_eq!(got.len(), 1, "{got:?}");
    assert_eq!(field(&got[0], "diag"), "BUSBAR-7109");
    assert_eq!(field(&got[0], "level"), "WARN");
    assert_eq!(field(&got[0], "dropped"), "2");
    assert_eq!(field(&got[0], "webhook_url"), "\"https://a.example\"");
    // The last line never raises it, reload or not: put the posting back on the pre-reload
    // generation so the reload is still news to it, and nothing remains to drop.
    at.generation = generation;
    let (_, after_two) = next_line(batch, next).expect("line 2");
    let (_, end) = next_line(batch, after_two).expect("line 3");
    let got = logged(|| assert!(!w.cut_by_reload(&mut at, &batch[end..])));
    assert_eq!(got.len(), 0, "{got:?}");
}

#[test]
fn only_an_explicit_ticket_binding_capability_preserves_a_reloaded_batch() {
    use busbar_contract::abi::mechanism::extensions;

    for capability in [
        None,
        Some(&b""[..]),
        Some(&b"0"[..]),
        Some(&b"1"[..]),
        Some(&b"2"[..]),
    ] {
        let encoded = capability
            .map(|value| extensions::encode(&[(TICKET_BINDINGS, value)]))
            .unwrap_or_default();
        let w = Webhook::open(
            br#"{"url":"https://a.example/","auth_header":{"name":"X-Api-Key","value":"old"}}"#,
            &[],
            1,
        )
        .unwrap();
        let (settings, generation) = w.current();
        let mut at = Posting {
            settings,
            generation,
            offset: 0,
            issued: 0,
            exchange: None,
            bindings_pinned: pinned_ticket_bindings(&encoded),
            host: None,
        };
        w.refresh(
            br#"{"url":"https://b.example/","auth_header":{"name":"X-Api-Key","value":"new"}}"#,
            &[],
            2,
        )
        .unwrap();
        let pinned = capability == Some(&b"1"[..]);
        assert_eq!(w.cut_by_reload(&mut at, b"{\"line\":2}\n"), !pinned);
        assert_eq!(at.settings.url, "https://a.example/");
        assert_eq!(
            at.settings.auth_header.as_ref().unwrap().value.as_str(),
            "old"
        );
        assert_eq!(w.settings().url, "https://b.example/");
    }
}

/// `next_line` skips blank lines and answers the offset past the line it returns.
#[test]
fn next_line_skips_blank_lines_and_keeps_the_offset() {
    let batch = b"\n\na\n\nbc\n";
    assert_eq!(next_line(batch, 0), Some((&b"a"[..], 4)));
    assert_eq!(next_line(batch, 4), Some((&b"bc"[..], 8)));
    assert_eq!(next_line(batch, 8), None);
    assert_eq!(next_line(b"tail", 0), Some((&b"tail"[..], 5)));
    assert_eq!(next_line(b"", 0), None);
}

#[test]
fn a_credential_looking_key_in_auth_header_never_reaches_the_refusal_or_the_log() {
    let settings = json!({
        "url": "https://a.example/",
        "auth_header": {"name": "A", "value": "v", "Bearer tok": 1}
    });
    let bytes = settings.to_string();
    let got = logged(|| {
        let r = refused(settings.clone());
        assert!(
            !r.contains("Bearer tok"),
            "the key reached the refusal: {r}"
        );
        assert!(r.starts_with("settings: unknown field "), "{r}");
        for r in [
            Webhook::open(bytes.as_bytes(), &[], 1).expect_err("open refuses"),
            Webhook::open(br#"{"url":"https://a.example/"}"#, &[], 1)
                .expect("opens")
                .refresh(bytes.as_bytes(), &[], 2)
                .expect_err("refresh refuses"),
        ] {
            let text = r.text().expect("says why");
            assert!(!text.contains("Bearer tok"), "{text}");
        }
    });
    assert!(!all_text(&got).contains("Bearer tok"), "{got:?}");
}

#[test]
fn the_settings_schema_bounds_are_the_ones_check_enforces() {
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../settings.schema.json")).expect("JSON");
    let p = &schema["properties"];
    assert_eq!(p["delivery_timeout_secs"]["minimum"], 1);
    assert_eq!(p["delivery_timeout_secs"]["maximum"], MAX_DURATION_SECS);
    assert_eq!(p["max_inflight_deliveries"]["minimum"], 0);
    assert_eq!(p["max_inflight_deliveries"]["maximum"], MAX_PERMITS as u64);
}

/// KIND 1: `validate` refuses exactly what `open` refuses: an `auth_header` that cannot be sent as
#[test]
fn validate_refuses_an_auth_header_that_open_refuses() {
    let settings =
        json!({"url": "https://a.example/", "auth_header": {"name": "Authorization", "value": "tok\n"}})
            .to_string();
    let opened = Webhook::open(settings.as_bytes(), &[], 1).expect_err("open refuses");
    let validated = Webhook::validate(settings.as_bytes()).expect_err("validate refuses");
    assert_eq!(validated.text(), opened.text());
    assert!(!validated.text().unwrap().contains("tok"));
}

/// KIND 2: a host failure text echoing the request's credentials (the Basic value, its token, the
#[test]
fn a_failure_echoing_the_requests_credentials_logs_none_of_them() {
    let url = "https://alice:s3cret@hooks.example/in";
    let token = "YWxpY2U6czNjcmV0";
    let header = "HDRSECRET9c1";
    let got = logged(|| {
        report(
            url,
            Some(header),
            Err(ConnFailure::Failed(format!(
                "echoed Authorization: Basic {token} and x-key: {header}"
            ))),
        );
    });
    let text = all_text(&got);
    assert_eq!(got.len(), 1, "{got:?}");
    for secret in [token, "Basic ", header, "s3cret"] {
        assert!(!text.contains(secret), "{secret}: {text}");
    }
}

/// KIND 3 (D1): a URL that does not parse is read by hand: an `@` after its host is refused.
#[test]
fn an_unparsable_url_with_an_at_after_its_host_is_ambiguous() {
    let url = "https://svc:pa/ss@siem.example/in";
    assert!(url::Url::parse(url).is_err());
    let refusal = ambiguous_url(url).expect("ambiguous");
    assert!(refusal.contains("is ambiguous"), "{refusal}");
    assert!(!refusal.contains("pa/ss"), "{refusal}");
    let settings = json!({ "url": url }).to_string();
    assert!(Webhook::validate(settings.as_bytes()).is_err());
    assert!(ambiguous_url("https://svc:pa/ss/siem.example/in").is_none());
}

/// The ambiguous-url refusal shows only `<scheme>:***`: the parser's host of an ambiguous url is the
#[test]
fn the_ambiguous_url_refusal_never_echoes_the_path_or_query() {
    for url in [
        "https://tok/en@siem.example/services/CANARYPATH?key=CANARYQUERY",
        "https://svc:pa/ss@siem.example:8443/services/CANARYPATH?key=CANARYQUERY",
    ] {
        let refusal = ambiguous_url(url).expect(url);
        for canary in ["CANARYPATH", "CANARYQUERY", "tok", "pa/ss"] {
            assert!(!refusal.contains(canary), "{canary}: {refusal}");
        }
        assert!(
            refusal.contains("url `https:***` is ambiguous"),
            "{refusal}"
        );
        assert!(refusal.contains("is ambiguous"), "{refusal}");
    }
}

#[test]
fn a_slashless_or_unparsed_url_never_echoes_a_credential() {
    let refused = ConnFailure::Refused("destination refused".into());
    for (url, secrets) in [
        (
            "https:user:pass@host/x?k=SECRET",
            &["user", "pass", "SECRET"][..],
        ),
        ("https:svc-token/abc@host/x", &["svc-token", "abc"][..]),
        ("https:svc:pa/ss@host/x", &["svc:", "pa/ss"][..]),
        (
            "https:svc:hunter2@siem.example/hook?next=https://x",
            &["hunter2"][..],
        ),
        (
            "https://h/hook?to=ops@corp.com&key=SECRET",
            &["ops", "corp", "SECRET"][..],
        ),
        ("https://svc:pa/ss@host/x", &["svc:", "pa/ss"][..]),
        ("http:svc-token/abc@host/x", &["svc-token", "abc"][..]),
        (
            "ftp:svc-token@host/x?k=SECRET",
            &["svc-token", "SECRET"][..],
        ),
        (
            "https://bad host:99999/x@y?k=SECRET",
            &["SECRET", "bad host"][..],
        ),
    ] {
        let mut lines = vec![refusal_words(Some(url), &refused), log_target(url)];
        let settings = json!({ "url": url }).to_string();
        let verdict = Webhook::validate(settings.as_bytes());
        if let Err(r) = &verdict {
            lines.push(r.text().expect("a refusal says why").to_string());
        }
        if url::Url::parse(url).is_err() {
            let text = ambiguous_url(url).expect(url);
            assert!(
                text.contains("url `https:***` is ambiguous")
                    || text.contains("url `***` is ambiguous"),
                "{url}: {text}"
            );
            assert!(verdict.is_err(), "{url} is refused");
        }
        let instance = json!({ "url": url, "delivery_timeout_secs": 0,
            "auth_header": {"name": "Bad Name", "value": "x"} });
        lines.extend(check(CheckPhase::Instances, &[("w".to_string(), instance)]));
        for line in &lines {
            for s in secrets {
                assert!(!line.contains(s), "{url}: `{s}` in {line}");
            }
        }
    }
}

#[test]
fn a_framing_auth_header_name_is_refused_in_true_words() {
    for name in [
        "Host",
        "content-length",
        "Transfer-Encoding",
        "proxy-connection",
    ] {
        let say = format!(
            "settings.auth_header.name `{name}` is a framing/connection field the http framer \
             states itself; 1.6.0 does not send it"
        );
        let s = json!({"url": "https://a.example/", "auth_header": {"name": name, "value": "1"}});
        let bytes = s.to_string();
        assert_eq!(
            Webhook::open(bytes.as_bytes(), &[], 1)
                .expect_err(name)
                .text(),
            Some(say.as_str()),
            "{name}"
        );
        assert_eq!(
            Webhook::validate(bytes.as_bytes()).expect_err(name).text(),
            Some(say.as_str()),
            "{name}"
        );
        let lines = check(CheckPhase::Instances, &[("w".to_string(), s.clone())]);
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].contains(&say), "{name}: {}", lines[0]);
        assert!(!lines[0].contains("not a valid"), "{name}: {}", lines[0]);
        let m = migrated(s);
        assert_eq!(m.report.len(), 1, "{name}");
        assert!(m.report[0].contains(&say), "{name}: {}", m.report[0]);
        assert!(
            !m.report[0].contains("not a valid"),
            "{name}: {}",
            m.report[0]
        );
    }

    let bad =
        json!({"url": "https://a.example/", "auth_header": {"name": "Bad Name", "value": "1"}});
    let m = migrated(bad);
    assert_eq!(m.report, vec![REMOVED_AUTH_HEADER.to_string()]);
}

#[test]
fn an_ambiguous_echo_shows_only_an_http_or_https_scheme() {
    for url in ["admin:secret@host/x", "ftp:svc/tok@host/x?k=SECRET"] {
        let refusal = ambiguous_url(url).expect(url);
        assert!(
            refusal.contains("url `***` is ambiguous"),
            "{url}: {refusal}"
        );
        assert!(
            !refusal.contains("admin") && !refusal.contains("ftp"),
            "{refusal}"
        );
        assert_eq!(log_target(url), "***", "{url}");
    }
    assert!(ambiguous_url("HTTP:tok/en@host/x")
        .expect("ambiguous")
        .contains("url `HTTP:***` is ambiguous"));
}

/// Load the actual webhook through the production dispatcher for ABI operation tests.
fn loaded_for_test(
    settings: &[u8],
) -> (
    Arc<busbar_plugin_loader::dispatch::Dispatcher>,
    busbar_plugin_loader::dispatch::Plugin<busbar_plugin_loader::dispatch::kinds::export::Export>,
) {
    use busbar_contract::abi::{
        mechanism::{
            call::Blob,
            lifecycle::{self, OpenIn, OpenOut},
        },
        sdk::door::{blank_in, blank_out},
    };
    use busbar_plugin_loader::dispatch::{
        self, Bind, ConnTable, DispatchConfig, Dispatcher, Frame, LinkedRow, NoSink,
    };
    let d = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let row = LinkedRow::of(crate::door).expect("actual webhook statement");
    let p = dispatch::load_linked(
        &row,
        Bind {
            instance: Arc::from("unit-door"),
            max_inflight_cap: 64,
            sink: Arc::new(NoSink),
            dispatcher: d.adopter(),
            conns: ConnTable::Probe,
        },
    )
    .expect("load webhook");
    let mut input: OpenIn = blank_in();
    input.settings = Blob {
        ptr: settings.as_ptr(),
        len: settings.len(),
        fmt: busbar_contract::abi::mechanism::call::BLOB_JSON,
        flags: 0,
    };
    input.generation = 1;
    assert_eq!(
        p.call(
            lifecycle::slot::OPEN,
            &mut Frame::new(input, blank_out::<OpenOut>())
        )
        .outcome,
        Outcome::Ready
    );
    (d, p)
}
