// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Exercises ticketed delivery through the real loader, host connector and local HTTPS receiver.

use std::net::TcpListener;
use std::sync::{mpsc, Arc, Mutex, OnceLock, PoisonError};
use std::time::Duration;

use busbar_contract::abi::export::{self, DeliverIn};
use busbar_contract::abi::mechanism::call::{Blob, DeadlineClass, OutHead, BLOB_JSONL};
use busbar_plugin_loader::dispatch::kinds::export::Export;
use busbar_plugin_loader::dispatch::{
    load_dropped, load_linked, Bind, ConnTable, Diagnostic, Dispatcher, Dropped, EnvelopeSink,
    Frame, LinkedRow, Metric, Plugin,
};
#[path = "support/artifact.rs"]
mod artifact;
#[path = "support/calls.rs"]
mod calls;
use artifact::cdylib_of;
use calls::{bind, called, dispatcher, input, on_ticket, open_resumed, refresh};
#[path = "support/connector.rs"]
mod connector;
#[path = "support/receiver.rs"]
mod receiver;
use connector::host;
use receiver::{anchors, far_end_on};

struct Targets {
    first: String,
    next: String,
    failed: String,
}

fn targets() -> &'static Targets {
    static TARGETS: OnceLock<Targets> = OnceLock::new();
    TARGETS.get_or_init(|| {
        let secured = || {
            let listener = TcpListener::bind("localhost:0").expect("bind a private TLS listener");
            let address = far_end_on(listener, answer).expect("start the owned TLS listener");
            format!("localhost:{}", address.port())
        };
        let first = secured();
        let next = secured();
        let failed = TcpListener::bind("localhost:0").expect("bind a private failing peer");
        let failed_address = failed.local_addr().expect("the owned peer's address");
        std::thread::spawn(move || {
            for peer in failed.incoming() {
                let Ok(peer) = peer else { break };

                drop(peer);
            }
        });
        Targets {
            first,
            next,
            failed: format!("localhost:{}", failed_address.port()),
        }
    })
}

fn far_end() -> &'static str {
    &targets().first
}

fn next_far_end() -> &'static str {
    &targets().next
}

fn failing_peer() -> &'static str {
    &targets().failed
}

/// The body the far end answers `/big` with: past the SDK's 16 MiB reply cap.
const BIG: usize = 17 << 20;

/// Every whole request the far end read, in order.
static SEEN: Mutex<Vec<Vec<u8>>> = Mutex::new(Vec::new());
static DELIVERY_LOCK: Mutex<()> = Mutex::new(());

struct Pause {
    reached: mpsc::SyncSender<()>,
    release: mpsc::Receiver<()>,
}

static PAUSE: Mutex<Option<Pause>> = Mutex::new(None);

/// The far end's answer once a whole request (its head, then the `content-length` body it states)
fn answer(seen: &[u8]) -> Option<Vec<u8>> {
    let end = seen.windows(4).position(|w| w == b"\r\n\r\n")? + 4;
    let head = String::from_utf8_lossy(&seen[..end]).to_ascii_lowercase();
    let body = head
        .lines()
        .find_map(|l| l.strip_prefix("content-length:"))
        .and_then(|n| n.trim().parse::<usize>().ok())
        .unwrap_or(0);
    if seen.len() < end + body {
        return None;
    }
    SEEN.lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(seen.to_vec());
    let pause = head
        .starts_with("post /pending-old?")
        .then(|| PAUSE.lock().unwrap_or_else(PoisonError::into_inner).take())
        .flatten();
    if let Some(pause) = pause {
        let _ = pause.reached.send(());

        let _ = pause.release.recv_timeout(Duration::from_secs(10));
    }
    Some(if head.starts_with("post /big") {
        let mut r = format!("HTTP/1.1 200 OK\r\ncontent-length: {BIG}\r\n\r\n").into_bytes();
        r.resize(r.len() + BIG, b'x');
        r
    } else if head.starts_with("post /fail-big") {
        let mut r = format!("HTTP/1.1 503 Service Unavailable\r\ncontent-length: {BIG}\r\n\r\n")
            .into_bytes();
        r.resize(r.len() + BIG, b'x');
        r
    } else if head.starts_with("post /no-content ") {
        b"HTTP/1.1 204 No Content\r\n\r\n".to_vec()
    } else if head.starts_with("post /redirect ") {
        b"HTTP/1.1 302 Found\r\nlocation: /in?redirected=1\r\ncontent-length: 0\r\n\r\n".to_vec()
    } else if head.starts_with("post /fail") {
        b"HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\n\r\n".to_vec()
    } else {
        b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n".to_vec()
    })
}

/// THE HOST'S SINK, recorded: every envelope entry the host ingested, as text.
#[derive(Default)]
struct Tape(Mutex<Vec<String>>);

impl Tape {
    fn push(&self, line: String) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(line);
    }
    /// What the host observed since the last read.
    fn take(&self) -> Vec<String> {
        std::mem::take(&mut *self.0.lock().unwrap_or_else(PoisonError::into_inner))
    }
}

impl EnvelopeSink for Tape {
    fn metric(&self, m: Metric<'_>) {
        self.push(format!("metric {} {}", m.family, m.value));
    }
    fn diag(&self, d: Diagnostic<'_>) {
        self.push(format!(
            "diag {} {} {}",
            String::from_utf8_lossy(d.name),
            d.severity,
            String::from_utf8_lossy(d.text)
        ));
    }
    fn dropped(&self, why: Dropped) {
        self.push(format!("dropped {why:?}"));
    }
}

/// The linked door, bound to the host connector and `tape`, opened over `settings` on a ticket.
fn opened(settings: &serde_json::Value) -> (Plugin<Export>, Arc<Dispatcher>, Arc<Tape>) {
    opened_door(settings, false)
}

fn opened_door(
    settings: &serde_json::Value,
    dropped: bool,
) -> (Plugin<Export>, Arc<Dispatcher>, Arc<Tape>) {
    let _ = targets();
    let d = dispatcher();
    let tape = Arc::new(Tape::default());
    let b = Bind {
        sink: tape.clone(),
        conns: ConnTable::Host(host(d.conn_waker(), Some(anchors()))),
        ..bind(&d, "deliver")
    };
    let row = LinkedRow::of(busbar_export_webhook::door).expect("the linked door renders");
    let p = if dropped {
        load_dropped::<Export>(
            &cdylib_of("busbar_export_webhook_plugin"),
            &row.statement,
            b,
        )
        .expect("the dropped door loads")
    } else {
        load_linked::<Export>(&row, b).expect("the linked door loads")
    };
    let open = called(&open_resumed(&p, &d, settings.to_string().as_bytes()));
    assert!(open.starts_with("Ready "), "open: {open}");
    tape.take();
    (p, d, tape)
}

/// ONE `deliver` of `batch` on the logs stream, as the kernel's export flusher offers it: on a
fn deliver(p: &Plugin<Export>, d: &Dispatcher, batch: &str) -> String {
    let batch: Arc<Vec<u8>> = Arc::new(batch.as_bytes().to_vec());
    let mut f: Frame<DeliverIn, OutHead> = Frame::new(input(), calls::output());
    f.input.op_id = [1; 16];
    f.input.stream = export::ExportStream::Logs as u8;
    f.input.batch = Blob {
        ptr: batch.as_ptr(),
        len: batch.len(),
        fmt: BLOB_JSONL,
        flags: 0,
    };
    called(&on_ticket(
        p,
        d,
        export::slot::DELIVER,
        f,
        DeadlineClass::WriteBehind,
        0,
        batch,
    ))
}

/// The requests the far end read since the last call.
fn seen() -> Vec<String> {
    std::mem::take(&mut *SEEN.lock().unwrap_or_else(PoisonError::into_inner))
        .iter()
        .map(|r| String::from_utf8_lossy(r).into_owned())
        .collect()
}

/// The host-observed lines naming `code`.
fn naming<'a>(lines: &'a [String], code: &str) -> Vec<&'a String> {
    lines.iter().filter(|l| l.contains(code)).collect()
}

/// These scenarios share the far end and its record, so they run under one delivery lock.
#[test]
fn deliver_through_the_harness() {
    let _guard = DELIVERY_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
    for dropped in [false, true] {
        records_in_one_post_per_line_out(dropped);
        a_bodiless_204_is_delivered_and_a_redirect_is_not_followed(dropped);
    }
    a_non_2xx_answer_drops_the_line_as_busbar_7071();
    a_transport_error_drops_the_line_as_busbar_7072();
    the_first_line_after_a_refresh_goes_on_the_new_settings();
    a_200_with_a_huge_body_is_still_a_delivered_line();
    a_non_2xx_with_a_huge_body_still_logs_its_status();
    a_disabled_instance_posts_nothing();
    blank_lines_are_not_posted();
}

#[test]
fn a_pending_multiline_batch_keeps_its_binding_across_a_successful_refresh() {
    let _guard = DELIVERY_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
    for dropped in [false, true] {
        a_pending_batch_keeps_its_original_destination_and_credentials(false, dropped);
    }
}

#[test]
fn a_refused_refresh_keeps_both_the_pending_batch_and_the_next_batch_on_the_old_binding() {
    let _guard = DELIVERY_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
    for dropped in [false, true] {
        a_pending_batch_keeps_its_original_destination_and_credentials(true, dropped);
    }
}

/// Records in -> one HTTPS POST per line out, in order: the target's path and query, the
fn records_in_one_post_per_line_out(dropped: bool) {
    seen();
    let (p, d, tape) = opened_door(
        &serde_json::json!({
            "url": format!("https://us%40er:p4ss@{}/in?k=v", far_end()),
            "auth_header": {"name": "X-Api-Key", "value": "k3Y-VaLuE"}
        }),
        dropped,
    );
    let batch = "{\"outcome\":\"ok\",\"ts\":1}\n{\"outcome\":\"ok\",\"ts\":2}\n";
    let answer = deliver(&p, &d, batch);
    assert!(answer.starts_with("Ready "), "deliver: {answer}");
    let got = seen();
    assert_eq!(got.len(), 2, "one POST per line: {got:?}");
    for (req, body) in got.iter().zip([
        "{\"outcome\":\"ok\",\"ts\":1}",
        "{\"outcome\":\"ok\",\"ts\":2}",
    ]) {
        let (head, sent) = req.split_once("\r\n\r\n").expect("a whole request");
        let mut lines = head.split("\r\n");
        assert_eq!(lines.next(), Some("POST /in?k=v HTTP/1.1"), "{req}");
        let fields = header_fields(lines);
        let at = |name: &str| {
            fields
                .iter()
                .position(|f| f.starts_with(&format!("{name}:")))
                .unwrap_or_else(|| panic!("no `{name}` field in {fields:?}"))
        };

        assert!(
            fields.contains(&"authorization: Basic dXNAZXI6cDRzcw==".to_string()),
            "{fields:?}"
        );
        assert!(
            fields.contains(&"content-type: application/json".to_string()),
            "{fields:?}"
        );
        assert!(
            fields.contains(&"x-api-key: k3Y-VaLuE".to_string()),
            "{fields:?}"
        );
        assert!(at("authorization") < at("content-type") && at("content-type") < at("x-api-key"));
        assert!(
            fields.contains(&format!("content-length: {}", body.len())),
            "{fields:?}"
        );
        assert_eq!(sent, body);
    }
    let host = tape.take();
    assert!(
        naming(&host, "BUSBAR-70").is_empty(),
        "nothing dropped: {host:?}"
    );
}

/// A non-2xx answer drops the line: ONE BUSBAR-7071 line, at WARN, naming the status and only the
fn a_non_2xx_answer_drops_the_line_as_busbar_7071() {
    seen();
    let (p, d, tape) = opened(&serde_json::json!({
        "url": format!("https://u53r:s3cr3t-pw@{}/fail/T0KEN-PATH?api_key=s3cr3t-q", far_end()),
        "auth_header": {"name": "Authorization", "value": "Bearer s3cr3t-h"}
    }));
    let answer = deliver(&p, &d, "{\"outcome\":\"ok\"}\n");
    assert!(answer.starts_with("Ready "), "deliver: {answer}");
    assert_eq!(seen().len(), 1, "the line was POSTed once");
    let host = tape.take();
    let dropped = naming(&host, "BUSBAR-7071");
    assert_eq!(dropped.len(), 1, "{host:?}");
    assert!(dropped[0].contains("503"), "{}", dropped[0]);
    assert!(
        dropped[0].contains(&format!("https://***@{}/***?***", far_end())),
        "{}",
        dropped[0]
    );
    assert!(naming(&host, "BUSBAR-7072").is_empty(), "{host:?}");
    no_secret(&host);
}

/// A transport error (the target closes before TLS completes) drops the line: ONE BUSBAR-7072 line, the
fn a_transport_error_drops_the_line_as_busbar_7072() {
    let (p, d, tape) = opened(&serde_json::json!({
        "url": format!("https://u53r:s3cr3t-pw@{}/T0KEN-PATH?api_key=s3cr3t-q", failing_peer()),
        "auth_header": {"name": "Authorization", "value": "Bearer s3cr3t-h"}
    }));
    let answer = deliver(&p, &d, "{\"outcome\":\"ok\"}\n");
    assert!(answer.starts_with("Ready "), "deliver: {answer}");
    let host = tape.take();
    let dropped = naming(&host, "BUSBAR-7072");
    assert_eq!(dropped.len(), 1, "{host:?}");
    assert!(
        dropped[0].contains(&format!("https://***@{}/***?***", failing_peer())),
        "{}",
        dropped[0]
    );
    assert!(naming(&host, "BUSBAR-7071").is_empty(), "{host:?}");
    no_secret(&host);
}

/// No host-observed line carries the url's credential, path or query, or the auth header's value.
fn no_secret(host: &[String]) {
    for secret in ["u53r", "s3cr3t", "T0KEN"] {
        assert!(
            host.iter().all(|l| !l.contains(secret)),
            "`{secret}` reached the host: {host:?}"
        );
    }
}

/// A delivery started after refresh uses the new settings from its first line.
fn the_first_line_after_a_refresh_goes_on_the_new_settings() {
    seen();
    let (p, d, tape) = opened(&serde_json::json!({
        "url": format!("https://old-user:old-pw@{}/old?o=1", far_end()),
        "auth_header": {"name": "X-Api-Key", "value": "old-key"}
    }));
    let new = serde_json::json!({
        "url": format!("https://new-user:new-pw@{}/new?n=2", far_end()),
        "auth_header": {"name": "X-Api-Key", "value": "new-key"}
    });
    let refreshed = called(&refresh(&p, new.to_string().as_bytes()));
    assert!(refreshed.starts_with("Ready "), "refresh: {refreshed}");
    let answer = deliver(&p, &d, "{\"line\":0}\n{\"line\":1}\n");
    assert!(answer.starts_with("Ready "), "deliver: {answer}");
    let got = seen();
    assert_eq!(got.len(), 2, "{got:?}");
    for req in &got {
        assert!(req.starts_with("POST /new?n=2 HTTP/1.1\r\n"), "{req}");
        let (head, _) = req.split_once("\r\n\r\n").expect("a whole request");
        let fields = header_fields(head.split("\r\n").skip(1));

        assert!(
            fields.contains(&"authorization: Basic bmV3LXVzZXI6bmV3LXB3".to_string()),
            "{req}"
        );
        assert!(fields.contains(&"x-api-key: new-key".to_string()), "{req}");
        assert!(!req.contains("old"), "{req}");
    }
    let host = tape.take();
    assert!(naming(&host, "BUSBAR-7").is_empty(), "{host:?}");
}

/// The first POST has reached A while DELIVER waits for its response. A successful REFRESH moves
fn a_pending_batch_keeps_its_original_destination_and_credentials(refuse: bool, dropped: bool) {
    seen();
    assert_ne!(
        far_end(),
        next_far_end(),
        "the two bindings are distinct receivers"
    );
    let old = serde_json::json!({
        "url": format!("https://old-user:old-pw@{}/pending-old?old=1", far_end()),
        "auth_header": {"name": "X-Api-Key", "value": "old-key"},
        "delivery_timeout_secs": 30,
    });
    let new = serde_json::json!({
        "url": format!("https://new-user:new-pw@{}/pending-new?new=1", next_far_end()),
        "auth_header": {
            "name": if refuse { "Content-Length" } else { "X-Api-Key" },
            "value": "new-key",
        },
        "delivery_timeout_secs": 30,
    });
    let (p, d, tape) = opened_door(&old, dropped);
    let (reached, waiting) = mpsc::sync_channel(1);
    let (release, held) = mpsc::sync_channel(1);
    *PAUSE.lock().unwrap_or_else(PoisonError::into_inner) = Some(Pause {
        reached,
        release: held,
    });
    let old_batch = "{\"old\":0}\n{\"old\":1}\n\n{\"old\":2}\n";
    let (reached, refreshed, delivered) = std::thread::scope(|scope| {
        let delivery = scope.spawn(|| deliver(&p, &d, old_batch));
        let reached = waiting.recv_timeout(Duration::from_secs(5));
        let refreshed = called(&refresh(&p, new.to_string().as_bytes()));

        let _ = release.send(());
        let delivered = delivery.join();
        (reached, refreshed, delivered)
    });
    PAUSE.lock().unwrap_or_else(PoisonError::into_inner).take();
    reached.expect("the first old POST arrived before REFRESH");
    assert_eq!(
        refreshed.starts_with("Ready "),
        !refuse,
        "refresh: {refreshed}"
    );
    assert!(delivered.unwrap().starts_with("Ready "));
    let old_requests = seen();
    assert_eq!(
        old_requests.len(),
        3,
        "all old batch lines must finish on A"
    );
    for (request, body) in old_requests
        .iter()
        .zip(["{\"old\":0}", "{\"old\":1}", "{\"old\":2}"])
    {
        assert_binding(request, far_end(), "/pending-old?old=1", "old-key", true);
        assert_eq!(request.split_once("\r\n\r\n").unwrap().1, body);
    }
    let next = deliver(&p, &d, "{\"next\":0}\n{\"next\":1}\n");
    assert!(next.starts_with("Ready "), "next delivery: {next}");
    let new_requests = seen();
    assert_eq!(new_requests.len(), 2);
    for request in &new_requests {
        if refuse {
            assert_binding(request, far_end(), "/pending-old?old=1", "old-key", true);
        } else {
            assert_binding(
                request,
                next_far_end(),
                "/pending-new?new=1",
                "new-key",
                false,
            );
        }
    }
    let host = tape.take();
    assert!(
        naming(&host, "BUSBAR-7109").is_empty(),
        "a pinned batch was cut: {host:?}"
    );
    assert!(
        naming(&host, "BUSBAR-7072").is_empty(),
        "a batch lost its destination: {host:?}"
    );
}

fn assert_binding(request: &str, destination: &str, path: &str, key: &str, old: bool) {
    let (head, _) = request.split_once("\r\n\r\n").unwrap();
    let fields = header_fields(head.split("\r\n").skip(1));
    assert!(head.starts_with(&format!("POST {path} HTTP/1.1\r\n")));
    assert!(fields.contains(&format!("host: {destination}")));
    assert!(fields.contains(&format!("x-api-key: {key}")));
    let basic = if old {
        "b2xkLXVzZXI6b2xkLXB3"
    } else {
        "bmV3LXVzZXI6bmV3LXB3"
    };
    assert!(
        fields.contains(&format!("authorization: Basic {basic}")),
        "the userinfo credential belongs to this destination"
    );
    assert!(!head.contains(if old { "new-key" } else { "old-key" }));
}

/// A 200 with a huge body is still a delivered line.
fn a_200_with_a_huge_body_is_still_a_delivered_line() {
    seen();
    let (p, d, tape) = opened(&serde_json::json!({"url": format!("https://{}/big", far_end())}));
    let answer = deliver(&p, &d, "{\"line\":0}\n{\"line\":1}\n");
    assert!(answer.starts_with("Ready "), "deliver: {answer}");
    assert_eq!(seen().len(), 2, "both lines POSTed");
    let host = tape.take();
    assert!(
        naming(&host, "BUSBAR-70").is_empty(),
        "a 200 is a delivered line: {host:?}"
    );
}

/// A disabled instance posts nothing.
fn a_disabled_instance_posts_nothing() {
    seen();
    let (p, d, tape) = opened(&serde_json::json!({"url": format!("http://{}/in", far_end())}));
    let answer = deliver(&p, &d, "{\"line\":0}\n{\"line\":1}\n");
    assert!(answer.starts_with("Ready "), "deliver: {answer}");
    assert!(seen().is_empty(), "a disabled instance posted");
    let host = tape.take();

    assert_eq!(naming(&host, "BUSBAR-7070").len(), 1, "{host:?}");
    assert!(naming(&host, "BUSBAR-7071").is_empty(), "{host:?}");
    assert!(naming(&host, "BUSBAR-7072").is_empty(), "{host:?}");
}

/// Blank lines are not posted.
fn blank_lines_are_not_posted() {
    seen();
    let (p, d, _tape) = opened(&serde_json::json!({"url": format!("https://{}/in", far_end())}));
    let answer = deliver(&p, &d, "\n{\"line\":0}\n\n\n{\"line\":1}\n\n");
    assert!(answer.starts_with("Ready "), "deliver: {answer}");
    let got = seen();
    assert_eq!(got.len(), 2, "{got:?}");
    assert!(
        got[0].ends_with("{\"line\":0}") && got[1].ends_with("{\"line\":1}"),
        "{got:?}"
    );
}

/// A non 2xx with a huge body still logs its status.
fn a_non_2xx_with_a_huge_body_still_logs_its_status() {
    seen();
    let (p, d, tape) =
        opened(&serde_json::json!({"url": format!("https://{}/fail-big", far_end())}));
    let answer = deliver(&p, &d, "{\"line\":0}\n");
    assert!(answer.starts_with("Ready "), "deliver: {answer}");
    assert_eq!(seen().len(), 1);
    let host = tape.take();
    let dropped = naming(&host, "BUSBAR-7071");
    assert_eq!(dropped.len(), 1, "{host:?}");
    assert!(dropped[0].contains("503"), "{}", dropped[0]);
    assert!(naming(&host, "BUSBAR-7072").is_empty(), "{host:?}");
}

/// HTTP field names ignore case; credential values are opaque bytes.
fn header_fields<'a>(lines: impl Iterator<Item = &'a str>) -> Vec<String> {
    lines
        .map(|line| {
            let (name, value) = line.split_once(':').expect("an HTTP field");
            format!("{}:{value}", name.to_ascii_lowercase())
        })
        .collect()
}

fn a_bodiless_204_is_delivered_and_a_redirect_is_not_followed(dropped: bool) {
    for (path, status) in [("/no-content", None), ("/redirect", Some("302"))] {
        seen();
        let (p, d, tape) = opened_door(
            &serde_json::json!({"url": format!("https://{}{path}", far_end())}),
            dropped,
        );
        let answer = deliver(&p, &d, "{\"line\":0}\n");
        assert!(answer.starts_with("Ready "), "deliver: {answer}");
        let got = seen();
        assert_eq!(got.len(), 1, "one POST with no redirect follow: {got:?}");
        assert!(
            got[0].starts_with(&format!("POST {path} HTTP/1.1\r\n")),
            "{}",
            got[0]
        );
        let host = tape.take();
        let non_2xx = naming(&host, "BUSBAR-7071");
        match status {
            Some(status) => {
                assert_eq!(non_2xx.len(), 1, "{host:?}");
                assert!(non_2xx[0].contains(status), "{host:?}");
            }
            None => assert!(non_2xx.is_empty(), "a 204 is delivered: {host:?}"),
        }
        assert!(naming(&host, "BUSBAR-7072").is_empty(), "{host:?}");
    }
}
