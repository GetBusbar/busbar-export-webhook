// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DELIVER SLOT, DRIVEN AS THE KERNEL'S EXPORT FLUSHER DRIVES IT (audit XW1): the linked door
//! loaded over the real loader, opened and delivered to on a dispatcher ticket in the write-behind
//! class (busbar-test-kit's `conformance::{open_resumed, on_ticket}`), its `http` need served by
//! busbar's own connector over the transport doors this plugin names (the test kit's
//! `conformance_host::host`), every POST reaching a REAL local HTTPS far end (the kit's
//! `conformance_host::far_end`, its certificate chained to the suite's test anchors).
//!
//! What the far end receives is asserted byte for byte where the sink owns the bytes (the request
//! line, its fields, the body), and what the HOST observes (the envelope the reply carried, the
//! sink's own log lines among it) is asserted for the two drop paths: a non-2xx answer is ONE
//! BUSBAR-7071 line, a transport error ONE BUSBAR-7072 line, neither naming the url's userinfo,
//! path or query, nor the auth header's value.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use busbar_contract::abi::export::{self, DeliverIn};
use busbar_contract::abi::mechanism::call::{Blob, DeadlineClass, OutHead, BLOB_JSONL};
use busbar_contract::abi::mechanism::rendering::ReadNeed;
use busbar_contract::conn::{
    ConnAuth, ConnCause, ConnError, ConnId, Conns, DeclaredConns, HeadDefaults, InstanceId, NeedId,
    OpenDesc, Piece, Program, Ticket as ConnTicket,
};
use busbar_contract::transport::ConnFacts;
use busbar_plugin_loader::dispatch::kinds::export::Export;
use busbar_plugin_loader::dispatch::{
    load_linked, Bind, ConnTable, Diagnostic, Dispatcher, Dropped, EnvelopeSink, Frame, LinkedRow,
    Metric, Plugin,
};
use busbar_test_kit::conformance::{
    bind, called, dispatcher, input, on_ticket, open_resumed, refresh,
};
use busbar_test_kit::conformance_host::{anchors, far_end, host, Doors};

/// The transport doors the host serves, as `tests/support/conformance_host.rs` names them.
const DOORS: Doors = &[
    ("tcp", busbar_transport_tcp::door::MACRO_DOOR),
    ("http", busbar_transport_http::door::MACRO_DOOR),
];

/// This test's far end: loopback, a port of its own (the conformance suite's is 51655).
const FAR_END: &str = "localhost:51656";

/// A loopback port nothing listens on: a dial there is refused (the transport-error path).
const NOBODY: &str = "localhost:51657";

/// The body the far end answers `/big` with: past the SDK's 16 MiB reply cap.
const BIG: usize = 17 << 20;

/// Every whole request the far end read, in order.
static SEEN: Mutex<Vec<Vec<u8>>> = Mutex::new(Vec::new());

/// The far end's answer once a whole request (its head, then the `content-length` body it states)
/// has been read: `503` to a request for `/fail…`, else `200`. Each request is recorded.
fn answer(seen: &[u8]) -> Option<Vec<u8>> {
    let end = seen.windows(4).position(|w| w == b"\r\n\r\n")? + 4;
    let head = String::from_utf8_lossy(&seen[..end]).to_ascii_lowercase();
    let body = head
        .lines()
        .find_map(|l| l.strip_prefix("content-length:"))
        .and_then(|n| n.trim().parse::<usize>().ok())
        .unwrap_or(0);
    if seen.len() < end + body || head.starts_with("post /hang") {
        return None;
    }
    SEEN.lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(seen.to_vec());
    Some(if head.starts_with("post /big") {
        // A 200 whose body is past the SDK's 16 MiB reply cap: the sink judges the head alone.
        let mut r = format!("HTTP/1.1 200 OK\r\ncontent-length: {BIG}\r\n\r\n").into_bytes();
        r.resize(r.len() + BIG, b'x');
        r
    } else if head.starts_with("post /fail-big") {
        // A 503 with a body past the cap: the status is still what the sink reports.
        let mut r = format!("HTTP/1.1 503 Service Unavailable\r\ncontent-length: {BIG}\r\n\r\n")
            .into_bytes();
        r.resize(r.len() + BIG, b'x');
        r
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
    opened_on(settings, |conns| conns)
}

/// [`opened`], the host's connection table passed through `wrap` first.
fn opened_on(
    settings: &serde_json::Value,
    wrap: impl FnOnce(Arc<dyn DeclaredConns>) -> Arc<dyn DeclaredConns>,
) -> (Plugin<Export>, Arc<Dispatcher>, Arc<Tape>) {
    far_end(FAR_END, answer);
    let d = dispatcher();
    let tape = Arc::new(Tape::default());
    let b = Bind {
        sink: tape.clone(),
        conns: ConnTable::Host(wrap(host(DOORS, d.conn_waker(), Some(anchors())))),
        ..bind(&d, "deliver")
    };
    let p = load_linked::<Export>(
        &LinkedRow::of(busbar_export_webhook::door).expect("the linked door renders"),
        b,
    )
    .expect("the linked door loads");
    let open = called(&open_resumed(&p, &d, settings.to_string().as_bytes()));
    assert!(open.starts_with("Ready "), "open: {open}");
    tape.take();
    (p, d, tape)
}

/// ONE `deliver` of `batch` on the logs stream, as the kernel's export flusher offers it: on a
/// ticket, write-behind, resumed on its wake until it answers.
fn deliver(p: &Plugin<Export>, d: &Dispatcher, batch: &str) -> String {
    let (f, batch) = deliver_frame(batch);
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

/// The `deliver` frame for `batch`, and the memory it lends the op.
fn deliver_frame(batch: &str) -> (Frame<DeliverIn, OutHead>, Arc<Vec<u8>>) {
    let batch: Arc<Vec<u8>> = Arc::new(batch.as_bytes().to_vec());
    let mut f: Frame<DeliverIn, OutHead> =
        Frame::new(input(), busbar_test_kit::conformance::output());
    f.input.op_id = [1; 16];
    f.input.stream = export::ExportStream::Logs as u8;
    f.input.batch = Blob {
        ptr: batch.as_ptr(),
        len: batch.len(),
        fmt: BLOB_JSONL,
        flags: 0,
    };
    (f, batch)
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

/// The three tests share the one far end and its record, so they run as one.
#[test]
fn deliver_through_the_harness() {
    records_in_one_post_per_line_out();
    a_non_2xx_answer_drops_the_line_as_busbar_7071();
    a_transport_error_drops_the_line_as_busbar_7072();
    a_failed_line_leaves_the_rest_of_the_batch_to_go();
    an_abandoned_delivery_closes_its_host_connection();
    the_first_line_after_a_refresh_goes_on_the_new_settings();
    a_200_with_a_huge_body_is_still_a_delivered_line();
    a_non_2xx_with_a_huge_body_still_logs_its_status();
    a_disabled_instance_posts_nothing();
    blank_lines_are_not_posted();
}

/// Records in -> one HTTPS POST per line out, in order: the target's path and query, the
/// userinfo's Basic `authorization` first, then `content-type: application/json`, then the
/// configured auth header (lower-cased), and the line as the body; READY, and nothing dropped.
fn records_in_one_post_per_line_out() {
    seen();
    let (p, d, tape) = opened(&serde_json::json!({
        "url": format!("https://us%40er:p4ss@{FAR_END}/in?k=v"),
        "auth_header": {"name": "X-Api-Key", "value": "k3y-value"}
    }));
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
        let fields: Vec<String> = lines.map(str::to_ascii_lowercase).collect();
        let at = |name: &str| {
            fields
                .iter()
                .position(|f| f.starts_with(&format!("{name}:")))
                .unwrap_or_else(|| panic!("no `{name}` field in {fields:?}"))
        };
        // `us@er:p4ss`, padded standard base64.
        assert!(
            fields.contains(&"authorization: basic dxnazxi6cdrzcw==".to_string()),
            "{fields:?}"
        );
        assert!(
            fields.contains(&"content-type: application/json".to_string()),
            "{fields:?}"
        );
        assert!(
            fields.contains(&"x-api-key: k3y-value".to_string()),
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
/// target's scheme, masked userinfo, host and port; the delivery is still READY (fire-and-forget).
fn a_non_2xx_answer_drops_the_line_as_busbar_7071() {
    seen();
    let (p, d, tape) = opened(&serde_json::json!({
        "url": format!("https://u53r:s3cr3t-pw@{FAR_END}/fail/T0KEN-PATH?api_key=s3cr3t-q"),
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
        dropped[0].contains(&format!("https://***@{FAR_END}/***?***")),
        "{}",
        dropped[0]
    );
    assert!(naming(&host, "BUSBAR-7072").is_empty(), "{host:?}");
    no_secret(&host);
}

/// A transport error (the target refuses the connection) drops the line: ONE BUSBAR-7072 line, the
/// host's error scrubbed of the target's parts; READY.
fn a_transport_error_drops_the_line_as_busbar_7072() {
    let (p, d, tape) = opened(&serde_json::json!({
        "url": format!("https://u53r:s3cr3t-pw@{NOBODY}/T0KEN-PATH?api_key=s3cr3t-q"),
        "auth_header": {"name": "Authorization", "value": "Bearer s3cr3t-h"}
    }));
    let answer = deliver(&p, &d, "{\"outcome\":\"ok\"}\n");
    assert!(answer.starts_with("Ready "), "deliver: {answer}");
    let host = tape.take();
    let dropped = naming(&host, "BUSBAR-7072");
    assert_eq!(dropped.len(), 1, "{host:?}");
    assert!(
        dropped[0].contains(&format!("https://***@{NOBODY}/***?***")),
        "{}",
        dropped[0]
    );
    assert!(naming(&host, "BUSBAR-7071").is_empty(), "{host:?}");
    no_secret(&host);
}

/// A failed line does not end the batch: a two-line batch against the 503 target POSTs both
/// lines, drops each as its own BUSBAR-7071, and is still READY.
fn a_failed_line_leaves_the_rest_of_the_batch_to_go() {
    seen();
    let (p, d, tape) = opened(&serde_json::json!({
        "url": format!("https://{FAR_END}/fail"),
    }));
    let answer = deliver(
        &p,
        &d,
        "{\"outcome\":\"ok\",\"ts\":1}\n{\"outcome\":\"ok\",\"ts\":2}\n",
    );
    assert!(answer.starts_with("Ready "), "deliver: {answer}");
    assert_eq!(seen().len(), 2, "both lines were POSTed");
    let host = tape.take();
    assert_eq!(naming(&host, "BUSBAR-7071").len(), 2, "{host:?}");
}

/// THE HOST'S CONNECTION TABLE, watched: every call passes to `inner`, and each `close` is counted.
struct Watched {
    inner: Arc<dyn DeclaredConns>,
    closes: AtomicUsize,
}

impl Conns for Watched {
    fn open(&self, c: InstanceId, n: NeedId, d: &OpenDesc<'_>) -> Result<ConnId, ConnError> {
        self.inner.open(c, n, d)
    }
    fn write(
        &self,
        c: InstanceId,
        conn: ConnId,
        b: &[u8],
        end: bool,
        text: bool,
    ) -> Result<usize, ConnError> {
        self.inner.write(c, conn, b, end, text)
    }
    fn read(
        &self,
        c: InstanceId,
        conn: ConnId,
        t: ConnTicket,
        buf: &mut [u8],
    ) -> Result<Piece, ConnError> {
        self.inner.read(c, conn, t, buf)
    }
    fn wait(&self, c: InstanceId, set: &[ConnId], t: ConnTicket) -> Result<usize, ConnError> {
        self.inner.wait(c, set, t)
    }
    fn facts(&self, c: InstanceId, conn: ConnId) -> Result<ConnFacts, ConnError> {
        self.inner.facts(c, conn)
    }
    fn close(&self, c: InstanceId, conn: ConnId) -> Result<(), ConnError> {
        self.closes.fetch_add(1, Ordering::SeqCst);
        self.inner.close(c, conn)
    }
}

impl DeclaredConns for Watched {
    fn declare(
        &self,
        owner: InstanceId,
        need: NeedId,
        spec: &ReadNeed,
        target: Option<&str>,
        trust: Option<&str>,
    ) -> Result<(), ConnError> {
        self.inner.declare(owner, need, spec, target, trust)
    }
    fn declared(&self, owner: InstanceId, need: NeedId) -> Option<Result<(), ConnError>> {
        self.inner.declared(owner, need)
    }
    fn upgrade_secure(
        &self,
        c: InstanceId,
        conn: ConnId,
        name: Option<&str>,
        trust: Option<&str>,
        verify_off: bool,
        t: ConnTicket,
    ) -> Result<(), ConnError> {
        self.inner
            .upgrade_secure(c, conn, name, trust, verify_off, t)
    }
    fn landed(&self, c: InstanceId, conn: ConnId, t: ConnTicket) -> Result<(), ConnError> {
        self.inner.landed(c, conn, t)
    }
    fn framed(&self, owner: InstanceId, need: NeedId) -> bool {
        self.inner.framed(owner, need)
    }
    fn serves_scheme(&self, transport: &str) -> bool {
        self.inner.serves_scheme(transport)
    }
    fn declare_program(
        &self,
        owner: InstanceId,
        need: NeedId,
        spec: &ReadNeed,
        program: &Program,
    ) -> Result<(), ConnError> {
        self.inner.declare_program(owner, need, spec, program)
    }
    fn cause(&self, owner: InstanceId, conn: ConnId) -> Option<ConnCause> {
        self.inner.cause(owner, conn)
    }
    fn hold_authority(&self, owner: InstanceId) {
        self.inner.hold_authority(owner);
    }
    fn request_head(&self, owner: InstanceId, need: NeedId, target: &str) -> HeadDefaults {
        self.inner.request_head(owner, need, target)
    }
    fn bind_auth(&self, owner: InstanceId, need: NeedId, member: &str, origin: &str, b: ConnAuth) {
        self.inner.bind_auth(owner, need, member, origin, b);
    }
    fn auth_of(
        &self,
        owner: InstanceId,
        need: NeedId,
        member: &str,
        target: &str,
    ) -> Option<ConnAuth> {
        self.inner.auth_of(owner, need, member, target)
    }
    fn declare_member_programs(
        &self,
        owner: InstanceId,
        need: NeedId,
        spec: &ReadNeed,
        programs: &[(String, Program)],
    ) -> Result<(), ConnError> {
        self.inner
            .declare_member_programs(owner, need, spec, programs)
    }
    fn forget(&self, owner: InstanceId) {
        self.inner.forget(owner);
    }
}

/// AN ABANDONED DELIVERY CLOSES ITS HOST CONNECTION (audit r2-prod0-1): the far end reads the
/// request and never answers, so the line's exchange is PENDING; the dispatcher cancels the op at
/// its deadline and drops what the delivery parked. The host reclaims a connection only on a
/// CLOSE, so the parked delivery must issue one as it is dropped, or the connection leaks.
fn an_abandoned_delivery_closes_its_host_connection() {
    seen();
    let watched: Arc<Mutex<Option<Arc<Watched>>>> = Arc::default();
    let hold = watched.clone();
    let (p, d, _tape) = opened_on(
        &serde_json::json!({"url": format!("https://{FAR_END}/hang")}),
        move |inner| {
            let w = Arc::new(Watched {
                inner,
                closes: AtomicUsize::new(0),
            });
            *hold.lock().unwrap() = Some(w.clone());
            w
        },
    );
    let w = watched
        .lock()
        .unwrap()
        .clone()
        .expect("the table was wrapped");
    let before = w.closes.load(Ordering::SeqCst);
    // A request-class op (the host may give it up), submitted on a ticket; the far end holds the
    // request, so it stays PENDING.
    let ticket = d.mint(0).expect("a ticket");
    let (f, batch) = deliver_frame("{\"outcome\":\"ok\"}\n");
    let reply = d.submit_lent(
        &p,
        ticket,
        export::slot::DELIVER,
        f,
        DeadlineClass::Call,
        0,
        batch,
    );
    assert!(
        reply.wait(Duration::from_millis(700)).is_none(),
        "the delivery is still pending"
    );
    assert_eq!(
        w.closes.load(Ordering::SeqCst),
        before,
        "nothing closed yet"
    );
    // The host gives the delivery up: the client went away, so the op is cancelled.
    d.drop_client(ticket);
    let done = reply.wait_done();
    assert_ne!(
        done.outcome,
        busbar_contract::abi::mechanism::call::Outcome::Ready
    );
    d.recycle(ticket);
    let until = Instant::now() + Duration::from_secs(5);
    while w.closes.load(Ordering::SeqCst) == before && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        w.closes.load(Ordering::SeqCst) > before,
        "the abandoned delivery's host connection was never closed"
    );
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

/// LINE 0 AFTER A RELOAD (audit XW2), as the plugin and the loader answer it today: a delivery that
/// STARTS after a `refresh` reads the instance's settings at its start, so its first line (and
/// every other) is POSTed on the NEW settings: the new path and query, the new userinfo's Basic
/// value, the new auth header; nothing of the old settings rides it, and nothing is dropped (no
/// BUSBAR-7109: that cut is only for a batch a reload overtook mid-delivery). The host re-declares
/// the need from the refreshed settings before the plugin sees them, so the pin and the request
/// agree. NOTE: the kernel at this pin never refreshes an export instance (it opens each once, at
/// boot); this pins the plugin's side for when it does.
fn the_first_line_after_a_refresh_goes_on_the_new_settings() {
    seen();
    let (p, d, tape) = opened(&serde_json::json!({
        "url": format!("https://old-user:old-pw@{FAR_END}/old?o=1"),
        "auth_header": {"name": "X-Api-Key", "value": "old-key"}
    }));
    let new = serde_json::json!({
        "url": format!("https://new-user:new-pw@{FAR_END}/new?n=2"),
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
        let lower = req.to_ascii_lowercase();
        // `new-user:new-pw`, padded standard base64.
        assert!(
            lower.contains("\r\nauthorization: basic bmv3lxvzzxi6bmv3lxb3\r\n"),
            "{req}"
        );
        assert!(lower.contains("\r\nx-api-key: new-key\r\n"), "{req}");
        assert!(!req.contains("old"), "{req}");
    }
    let host = tape.take();
    assert!(naming(&host, "BUSBAR-7").is_empty(), "{host:?}");
}

/// W2: the sink judges a delivery on the reply's HEAD (1.5.5 dropped the body unread): a 200 whose
/// body is past the SDK's reply cap is a delivered line, not a BUSBAR-7072.
fn a_200_with_a_huge_body_is_still_a_delivered_line() {
    seen();
    let (p, d, tape) = opened(&serde_json::json!({"url": format!("https://{FAR_END}/big")}));
    let answer = deliver(&p, &d, "{\"line\":0}\n{\"line\":1}\n");
    assert!(answer.starts_with("Ready "), "deliver: {answer}");
    assert_eq!(seen().len(), 2, "both lines POSTed");
    let host = tape.take();
    assert!(
        naming(&host, "BUSBAR-70").is_empty(),
        "a 200 is a delivered line: {host:?}"
    );
}

/// T2: an instance whose target the host refused (an `http://` target, refused by the open-web
/// class) is disabled at boot, and its `deliver` posts nothing and answers READY.
fn a_disabled_instance_posts_nothing() {
    seen();
    let (p, d, tape) = opened(&serde_json::json!({"url": format!("http://{FAR_END}/in")}));
    let answer = deliver(&p, &d, "{\"line\":0}\n{\"line\":1}\n");
    assert!(answer.starts_with("Ready "), "deliver: {answer}");
    assert!(seen().is_empty(), "a disabled instance posted");
    let host = tape.take();
    // The refusal is raised once, at the first ask; nothing was attempted, so nothing was dropped.
    assert_eq!(naming(&host, "BUSBAR-7070").len(), 1, "{host:?}");
    assert!(naming(&host, "BUSBAR-7071").is_empty(), "{host:?}");
    assert!(naming(&host, "BUSBAR-7072").is_empty(), "{host:?}");
}

/// T2: blank lines in a batch are not POSTed (1.5.5 skipped empty lines).
fn blank_lines_are_not_posted() {
    seen();
    let (p, d, _tape) = opened(&serde_json::json!({"url": format!("https://{FAR_END}/in")}));
    let answer = deliver(&p, &d, "\n{\"line\":0}\n\n\n{\"line\":1}\n\n");
    assert!(answer.starts_with("Ready "), "deliver: {answer}");
    let got = seen();
    assert_eq!(got.len(), 2, "{got:?}");
    assert!(
        got[0].ends_with("{\"line\":0}") && got[1].ends_with("{\"line\":1}"),
        "{got:?}"
    );
}

/// W2: a non-2xx reply with a body past the reply cap is still ONE BUSBAR-7071 line naming its
/// status (the head is judged; the body is never read).
fn a_non_2xx_with_a_huge_body_still_logs_its_status() {
    seen();
    let (p, d, tape) = opened(&serde_json::json!({"url": format!("https://{FAR_END}/fail-big")}));
    let answer = deliver(&p, &d, "{\"line\":0}\n");
    assert!(answer.starts_with("Ready "), "deliver: {answer}");
    assert_eq!(seen().len(), 1);
    let host = tape.take();
    let dropped = naming(&host, "BUSBAR-7071");
    assert_eq!(dropped.len(), 1, "{host:?}");
    assert!(dropped[0].contains("503"), "{}", dropped[0]);
    assert!(naming(&host, "BUSBAR-7072").is_empty(), "{host:?}");
}
