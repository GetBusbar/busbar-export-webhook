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
                (b"authorization".to_vec(), b"Bearer x".to_vec()),
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

/// RED (audit export-webhook #1, ARCHITECT ruling (c)): PARITY WITH 1.5.5. A target URL carrying a
/// userinfo is sent as 1.5.5's reqwest 0.12 sent it (`RequestBuilder::new` -> `extract_authority`
/// -> `basic_auth`; reqwest-0.12.28 src/async_impl/request.rs:169-183, :581-605, src/util.rs:4-25):
/// `authorization: Basic` and the padded standard base64 of `{user}:{password}`, each half
/// percent-decoded; a user alone as `{user}:`, a password alone as `:{password}`; a username that
/// does not decode to UTF-8 sends no field, and a password that does not is left out.
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
    // The base64 is the padded standard alphabet (RFC 4648 section 10's vectors).
    for (plain, encoded) in [
        ("", ""),
        ("f", "Zg=="),
        ("fo", "Zm8="),
        ("foo", "Zm9v"),
        ("foob", "Zm9vYg=="),
        ("fooba", "Zm9vYmE="),
        ("foobar", "Zm9vYmFy"),
    ] {
        assert_eq!(base64(plain.as_bytes()), encoded, "{plain}");
    }
    assert_eq!(base64(&[0xfb, 0xff, 0xbf]), "+/+/");
}

/// RED (audit export-webhook #1, ARCHITECT ruling (c)): the userinfo's field rides every POST
/// first, then `content-type`, then a configured auth header, as 1.5.5's `HeaderMap` held them —
/// a configured header ALSO named `Authorization` (any case) is sent too, right after the
/// userinfo's, so the receiver reads both, the userinfo's first, as it did from 1.5.5. The target
/// is the path and query, never the userinfo.
#[test]
fn the_userinfo_field_rides_beside_a_configured_auth_header_as_in_1_5_5() {
    let basic = (b"authorization".to_vec(), b"Basic dXNlcjpwYXNz".to_vec());
    let json = (b"content-type".to_vec(), b"application/json".to_vec());
    let both = settings(json!({
        "url": "https://user:pass@siem.example/in?k=v",
        "auth_header": {"name": "Authorization", "value": "Bearer x"}
    }));
    let r = request(&both, b"{}");
    assert_eq!(
        r.fields,
        vec![
            basic.clone(),
            (b"authorization".to_vec(), b"Bearer x".to_vec()),
            json.clone(),
        ]
    );
    assert_eq!(r.target, b"/in?k=v".to_vec());
    let other = settings(json!({
        "url": "https://user:pass@siem.example/in",
        "auth_header": {"name": "X-Api-Key", "value": "k"}
    }));
    assert_eq!(
        request(&other, b"{}").fields,
        vec![
            basic.clone(),
            json.clone(),
            (b"x-api-key".to_vec(), b"k".to_vec()),
        ]
    );
    let alone = settings(json!({"url": "https://user:pass@siem.example/in"}));
    assert_eq!(request(&alone, b"{}").fields, vec![basic, json]);
}

/// RED (audit export-webhook round 1): the contract's field block carries lower-case names, and
/// 1.5.5's `HeaderName::from_bytes` lower-cased the configured name, so 1.5.5 sent
/// `authorization` / `x-api-key` whatever the operator's spelling.
#[test]
fn a_configured_auth_header_name_goes_lower_case_as_1_5_5_sent_it() {
    for (name, sent) in [
        ("Authorization", "authorization"),
        ("X-Api-Key", "x-api-key"),
    ] {
        let s = settings(json!({
            "url": "https://siem.example/in",
            "auth_header": {"name": name, "value": "k"}
        }));
        assert!(
            request(&s, b"{}")
                .fields
                .contains(&(sent.as_bytes().to_vec(), b"k".to_vec())),
            "{name}"
        );
    }
}

/// A non-2xx answer and a transport failure each drop the line and raise their code at WARN (1.5.5's
/// `warn_webhook_delivery_failed`), with the fields in the compiled-in site's order, the target
/// named by scheme and host only.
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
            .filter(|n| n != "message" && n != "level")
            .collect::<Vec<_>>()
    };
    assert_eq!(got.len(), 2, "{got:?}");
    assert_eq!(names(&got[0]), ["diag", "webhook_url", "status"]);
    assert_eq!(field(&got[0], "diag"), "BUSBAR-7071");
    // The target by scheme and host: its userinfo, path and query can each carry the secret (H3).
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
        let got = logged(|| report("https://a.example/", reply(status)));
        assert_eq!(got.len(), usize::from(raises), "{status}: {got:?}");
    }
}

/// A target the host refused is named in 1.5.5's words, as 1.5.5's `validate_webhook_url` named it:
/// the `https://` scheme rule (the scheme read without case), a URL that does not parse, or the
/// destination guard, the userinfo masked as 1.5.5 masked it; a host that gave no verdict is named
/// as such.
#[test]
fn a_refused_target_is_named_in_1_5_5_words_when_it_is_the_scheme() {
    let refused = ConnFailure::Refused("destination refused".into());
    assert_eq!(
        refusal_words(Some("http://127.0.0.1:4000/sidecar"), &refused),
        "observability.request_log_webhook_url must be an https:// URL (got 'http://127.0.0.1:4000/sidecar')"
    );
    assert_eq!(
        refusal_words(Some("HTTP://u:p@siem.example/in"), &refused),
        "observability.request_log_webhook_url must be an https:// URL (got 'http://***@siem.example/in')"
    );
    // RED (Q128 export-webhook LOW, src/lib.rs:391-403): 1.5.5 named the other two refusals on this
    // path in its own words too (v1.5.5 observability.rs validate_webhook_url): a URL that does not
    // parse, and a parseable https target the destination guard refused.
    assert_eq!(
        refusal_words(Some("https://u:p@/x"), &refused),
        "observability.request_log_webhook_url is not a valid URL: empty host"
    );
    assert_eq!(
        refusal_words(Some("HTTPS://u:p@169.254.169.254/in"), &refused),
        "observability.request_log_webhook_url must not target a loopback/link-local/private/CGNAT/\
         cloud-metadata host (SSRF guard); got 'https://***@169.254.169.254/in'"
    );
    assert_eq!(
        refusal_words(Some("http://siem.example/in"), &ConnFailure::Unarmed),
        "the instance was handed no connector"
    );
    assert_eq!(refusal_words(None, &refused), "destination refused");
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
    assert_eq!(field(&got[0], "level"), "ERROR");
    assert_eq!(
        field(&got[0], "message"),
        "the instance was handed no connector; disabling this webhook exporter"
    );
    w.refresh(br#"{"url":"https://b.example/"}"#, &[], 2)
        .expect("a refresh applies");
    assert_eq!(logged(|| assert!(!w.admitted(None))).len(), 1);
    assert_eq!(w.settings().expect("parsed").url, "https://b.example/");
}

/// The Statement: name, NO in-flight ceiling of its own (`u32::MAX`: the operator's
/// `max_inflight_deliveries` is the bound), the module alias, the `logs` stream, no route, and ONE
/// outbound open-web need targeted by the `url` setting.
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
    assert_eq!(codes, vec![7070, 7071, 7072, 7107]);
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

/// DISCOVERY AT BOOT: `ready` asks the host's verdict once and never refuses the boot. Over host
/// tables with no connector the target is unadmitted, so BUSBAR-7070 is raised there, at ERROR, and
/// the instance stays disabled; the first delivery asks nothing again.
#[test]
fn ready_asks_the_verdict_at_boot_and_never_refuses_it() {
    use busbar_contract::abi::mechanism::ticket::{HostTables, Ticket};
    use std::task::Poll;
    let tables = HostTables {
        size: std::mem::size_of::<HostTables>() as u32,
        _reserved: 0,
        ctx: busbar_contract::abi::mechanism::ticket::HostCtx::NONE,
        wake: None,
        conns: std::ptr::null(),
        services: std::ptr::null(),
        io: std::ptr::null(),
    };
    let host = busbar_contract::abi::sdk::conn::Host::of(&tables);
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

/// RED (audit export-webhook round 1): a reload publishes the new settings and clears the cached
/// verdict as ONE step, so a delivery never reads the new target's settings paired with the old
/// target's verdict. While the verdict is held, the settings still name the old target.
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
                w.settings().expect("parsed").url,
                "https://a.example/x",
                "new settings visible while the old verdict is still held"
            );
        }
        drop(guard);
    });
    assert_eq!(w.settings().expect("parsed").url, "https://b.example/x");
    assert_eq!(*w.live.lock().unwrap(), None);
}

/// `ready` reads the HOST's verdict, not "no host": over a fake host whose `need.admit` refuses, an
/// `http://` target is named in the scheme rule's 1.5.5 words, which only a Refused verdict from
/// the host yields (no host to ask says its own words). Mutation proof: with `ready` calling
/// `self.admitted(None)` this test fails on the message.
#[test]
fn ready_reads_the_hosts_refusal_and_names_the_scheme_rule() {
    use busbar_contract::abi::mechanism::call::Outcome;
    use busbar_contract::abi::mechanism::ticket::Ticket;
    use busbar_contract::abi::sdk::conn::Host;
    use busbar_contract::abi::sdk::test_support::fake::{self, FakeHost, FakeService, ServiceCall};
    use std::task::Poll;
    struct Refuses;
    impl FakeService for Refuses {
        type In = busbar_contract::abi::host::service::NeedAdmitIn;
        fn serve(call: &mut ServiceCall<Self::In>) -> Outcome {
            call.set_error("destination refused");
            Outcome::Refused
        }
    }
    let fake_host = FakeHost::new().serve(fake::host::NEED_ADMIT, Refuses);
    let tables = fake_host.lent();
    let host = Host::of(&tables);
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
/// `delivery_timeout_secs` is 0 is found at `CHECK_PHASE_INSTANCES` and not at
/// `CHECK_PHASE_LIMITS`), the findings are leased as a JSON array, and a phase the sink does not
/// know is refused. Mutation proof: swapping the two phase arms turns it red.
#[test]
fn the_check_slot_maps_its_phase_and_leases_the_findings() {
    use busbar_contract::abi::export::{
        CheckIn, CheckInstance, CheckOut, Ops, CHECK_PHASE_INSTANCES, CHECK_PHASE_LIMITS,
    };
    use busbar_contract::abi::mechanism::call::{AbiStr, Blob, Outcome};
    use busbar_contract::abi::mechanism::lifecycle::{slot, OpenIn, OpenOut};
    use busbar_contract::abi::sdk::test_support::reply::{call_in, close_in};
    use busbar_contract::abi::sdk::test_support::test_in::TestIn;
    use busbar_contract::abi::sdk::test_support::{zeroed, DoorView};

    let settings = br#"{"url":"https://a.example/x","delivery_timeout_secs":0}"#;
    let view = DoorView::of(crate::table::MACRO_DOOR);
    let open = view.op::<Ops>(|t| &t.head.open).expect("open");
    let close = view.op::<Ops>(|t| &t.head.close).expect("close");
    let check_op = view.op::<Ops>(|t| &t.check).expect("check");
    let mut opened = call_in(
        open,
        None,
        &TestIn::<OpenIn>::new()
            .set(|i| &i.head.op, slot::OPEN)
            .settings(settings),
        zeroed::<OpenOut>(),
    );
    assert_eq!(opened.outcome, Outcome::Ready);
    let instance = opened.take_instance().expect("an instance");

    let rows = [CheckInstance {
        name: AbiStr::of("w"),
        settings: Blob::json(settings),
    }];
    let check = |phase: u32| {
        call_in(
            check_op,
            Some(&instance),
            &TestIn::<CheckIn>::new()
                .set(|i| &i.head.op, check_op.index())
                .set(|i| &i.phase, phase)
                .list(|i| &i.instances, |i| &i.instances_len, &rows),
            zeroed::<CheckOut>(),
        )
    };
    let expected = crate::check(
        CheckPhase::Instances,
        &[("w".to_string(), serde_json::from_slice(settings).unwrap())],
    );
    assert!(!expected.is_empty(), "a 0-second deadline is a finding");
    let found = check(CHECK_PHASE_INSTANCES);
    assert_eq!(found.outcome, Outcome::Ready);
    let lines: Vec<String> = serde_json::from_slice(&found.owned).expect("a JSON array");
    assert_eq!(lines, expected);
    let limits = check(CHECK_PHASE_LIMITS);
    assert_eq!(limits.outcome, Outcome::Ready);
    assert!(limits.owned.is_empty(), "{:?}", limits.owned);
    let unknown = check(7);
    assert_eq!(unknown.outcome, Outcome::Refused);
    assert_eq!(unknown.error.as_deref(), Some(crate::UNKNOWN_PHASE));

    let closed = close_in(
        close,
        instance,
        &TestIn::<busbar_contract::abi::mechanism::call::InHead>::new().set(|i| &i.op, slot::CLOSE),
        zeroed::<busbar_contract::abi::mechanism::call::OutHead>(),
    );
    assert_eq!(closed.outcome, Outcome::Ready);
}

/// RED (audit export-webhook #4): PARITY WITH 1.5.5, which added the configured auth header only
/// when `HeaderName::from_bytes` and `HeaderValue::from_str` both took it and otherwise POSTed the
/// line without it (v1.5.5 `crates/busbar/src/export/webhook.rs` `deliver_logs`). A name that is not
/// an RFC 9110 token, or a value with a control byte, leaves the header out, and the line is still
/// sent; a value with a tab or a non-ASCII byte is kept, as `HeaderValue::from_str` kept it.
#[test]
fn an_auth_header_1_5_5_could_not_build_is_left_out_and_the_line_still_sent() {
    let json = (b"content-type".to_vec(), b"application/json".to_vec());
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
        assert_eq!(
            request(&s, b"{}").fields,
            vec![json.clone()],
            "{name:?}: {value:?}"
        );
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
        assert_eq!(
            request(&s, b"{}").fields,
            vec![
                json.clone(),
                (
                    name.to_ascii_lowercase().into_bytes(),
                    value.as_bytes().to_vec()
                )
            ],
            "{name:?}: {value:?}"
        );
    }
}

/// THE SETTINGS SCHEMA MARKS NO FIELD SECRET BELOW THE ROOT (coordinator ruling (B), 2026-10-19:
/// pack keeps 1.5.5's refusal of a nested `x-busbar-secret` marker, v1.5.5
/// `crates/plugin-pack/src/main.rs:298-304`). `auth_header.value` is a plain string, as 1.5.5's
/// `ExportAuthHeader { name, value: String }` read it (v1.5.5 `crates/busbar/src/config/mod.rs`),
/// its `${VAR}` filled by the config's env interpolation. The schema names exactly the settings
/// grammar's keys. RED before the fix: `auth_header.value` carried a nested marker the packer
/// refuses.
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
    assert_eq!(
        schema["properties"]["auth_header"]["properties"]["value"]["type"],
        "string"
    );
}

/// THE AUTH HEADER'S VALUE NEVER RENDERS THROUGH `Debug` (Q128 export-webhook M2: "the secret
/// handled as a secret ... never shown through Debug"): formatting the settings, the header or an
/// instance holding them names the header and redacts its value. RED before the fix: `Debug` was
/// derived over `ExportAuthHeader::value`.
#[test]
fn the_auth_header_value_is_redacted_from_debug() {
    let header = ExportAuthHeader {
        name: "Authorization".into(),
        value: "Bearer s3cret-token".into(),
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
/// sent as Basic credentials, so formatting the settings masks it as every line this sink writes
/// does ([`mask_userinfo`]). RED before the fix: `Debug` was derived over `WebhookSettings::url`.
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

// ── Credential-echo canaries (CREDENTIAL-LOCKDOWN H2, H3) ────────────────────────────────────────

const CANARY: &str = "CANARY7f2a9e";

/// Every string any captured event carries, flattened, for a canary search.
fn all_text(events: &[Event]) -> String {
    events
        .iter()
        .flat_map(|e| e.iter().map(|(n, v)| format!("{n}={v}\n")))
        .collect()
}

/// H2: an `auth_header` written as a bare string (`auth_header: "Bearer …"`, where a `{name, value}`
/// map is expected) used to be quoted back by serde into the refusal and so into the log.
#[test]
fn a_mistyped_auth_header_never_reaches_the_refusal() {
    let r =
        refused(json!({"url": "https://a.example/", "auth_header": format!("Bearer {CANARY}")}));
    assert!(
        !r.contains(CANARY),
        "the refusal carried the credential: {r}"
    );
    // The words are serde's otherwise: only the credential bytes are gone.
    assert!(r.starts_with("settings: invalid type: string "), "{r}");
    assert!(r.contains("expected struct ExportAuthHeader"), "{r}");

    // The same through `value` given the wrong type alongside a credential-bearing sibling.
    let r = refused(
        json!({"url": "https://a.example/", "auth_header": {"name": "Authorization", "value": [format!("Bearer {CANARY}")]}}),
    );
    assert!(
        !r.contains(CANARY),
        "the refusal carried the credential: {r}"
    );
}

/// H3: a delivery failure logged the target's path and query (where Slack-style and `?api_key=`
/// webhooks carry their secret) and the host's failure text verbatim (which may quote the URL).
#[test]
fn a_failed_delivery_never_logs_the_targets_path_query_or_the_hosts_echo_of_them() {
    let url = format!("https://hooks.example/services/T000/B000/{CANARY}?api_key={CANARY}x");
    let got = logged(|| {
        report(&url, reply(503));
        report(
            &url,
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
    // The host stays named, so the operator can still tell which target failed.
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
    assert_eq!(log_target("https://u:p@/x"), "https://***@/***");
    assert_eq!(log_target("not a url"), "***");
}

// ── SIBLING ALIGNMENT (export kind) ─────────────────────────────────────────────────────────────

/// RED before: `open` took settings that do not parse and opened a dead instance whose every
/// delivery returned READY without a word; `refresh` replaced good settings with none the same way.
/// Both now refuse in `validate`'s words, and a refused refresh keeps the old settings — as every
/// export sibling does.
#[test]
fn open_and_refresh_refuse_settings_that_do_not_parse() {
    let bad = br#"{"url":"https://a.example/","bogus":1}"#;
    let want = Webhook::validate(bad).expect_err("refused");
    let opened = Webhook::open(bad, &[], 1).expect_err("open refuses");
    assert_eq!(opened, want);
    let w = Webhook::open(br#"{"url":"https://a.example/"}"#, &[], 1).expect("opens");
    assert_eq!(w.refresh(bad, &[], 2).expect_err("refresh refuses"), want);
    assert_eq!(
        w.settings().map(|s| s.url).as_deref(),
        Some("https://a.example/"),
        "a refused refresh keeps the old settings"
    );
}

/// OWNER RULING 2026-10-24, RED before: a url that parses but reads its credential as host and
/// path (`https://tok/en@host`, `https://u:123/x@host`) was taken. It is refused at validate, open
/// and refresh, naming the problem, the credential cut from the url it shows.
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

/// RED before: `serve` answered READY `404` for a sink that declares no route, a silent "nothing".
/// It is now REFUSED, saying why, in the words every export sibling uses (`scrape`: the plugin
/// crate's `tests/refusals.rs`, as the test kit copies no `ScrapeOut`).
#[test]
fn serve_is_refused_saying_why_through_the_door() {
    use busbar_contract::abi::export::{Ops, ServeIn, ServeOut};
    use busbar_contract::abi::mechanism::call::{InHead, OutHead, Outcome};
    use busbar_contract::abi::mechanism::lifecycle::{slot, OpenIn, OpenOut};
    use busbar_contract::abi::sdk::test_support::reply::{call_in, close_in};
    use busbar_contract::abi::sdk::test_support::test_in::TestIn;
    use busbar_contract::abi::sdk::test_support::{zeroed, DoorView};

    let view = DoorView::of(crate::table::MACRO_DOOR);
    let open = view.op::<Ops>(|t| &t.head.open).expect("open");
    let close = view.op::<Ops>(|t| &t.head.close).expect("close");
    let serve = view.op::<Ops>(|t| &t.serve).expect("serve");
    let mut opened = call_in(
        open,
        None,
        &TestIn::<OpenIn>::new()
            .set(|i| &i.head.op, slot::OPEN)
            .settings(br#"{"url":"https://a.example/x"}"#),
        zeroed::<OpenOut>(),
    );
    assert_eq!(opened.outcome, Outcome::Ready);
    let instance = opened.take_instance().expect("an instance");
    let c = call_in(
        serve,
        Some(&instance),
        &TestIn::<ServeIn>::new().set(|i| &i.head.op, busbar_contract::abi::export::slot::SERVE),
        zeroed::<ServeOut>(),
    );
    assert_eq!(c.outcome, Outcome::Refused);
    assert_eq!(c.error.as_deref(), Some(crate::NO_ROUTE));
    let closed = close_in(
        close,
        instance,
        &TestIn::<InHead>::new().set(|i| &i.op, slot::CLOSE),
        zeroed::<OutHead>(),
    );
    assert_eq!(closed.outcome, Outcome::Ready);
}
