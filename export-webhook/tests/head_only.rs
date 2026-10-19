// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A DELIVERY IS JUDGED ON THE REPLY'S HEAD (Q128 ruling A; `BUSBAR-1.6.0.md` §2 l.359-365, a port
//! keeps 1.5.5's surface). 1.5.5 judged a request-log webhook delivery on the response head and
//! dropped the body unread (v1.5.5 `crates/busbar/src/export/webhook.rs` `deliver_logs`). A 2xx head
//! followed by a body that is huge, or slow, is a delivery the receiver accepted: it raises no
//! BUSBAR-7072 and reports success.
//!
//! The host is scripted here, through the connector table the SDK crosses (the sink itself holds
//! no `unsafe`; this host writes the reply pieces into the sink's lent buffers, as a host does).
//! Every service answers READY at once; a slow body's read never completes.

use std::ffi::c_void;
use std::sync::{Arc, Mutex};
use std::task::Poll;

use busbar_contract::abi::host::conn::connector::{
    ConnectorSlots, ReplyIn, ReplyPiece, RequestIn, REPLY_BODY, REPLY_HEAD, SERVICES,
};
use busbar_contract::abi::host::service::ServiceOut;
use busbar_contract::abi::mechanism::call::{Outcome, RawOutcome};
use busbar_contract::abi::mechanism::ticket::{HostCtx, HostTables, Ticket};
use busbar_contract::abi::sdk::conn::Host;
use busbar_contract::abi::transport::FrameSpan;
use busbar_export_webhook::{delivery, post, report, Settings};

/// What follows the 2xx head.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Body {
    /// Body pieces, one whole read buffer each, with no end: the body passes the exchange's bound.
    Huge,
    /// A body that never arrives: every read after the head pends.
    Slow,
}

/// The scripted far end: what follows the head, how many reply pieces were read, whether the
/// stream was closed.
struct Script {
    body: Body,
    reads: usize,
    closed: bool,
}

static SCRIPT: Mutex<Option<Script>> = Mutex::new(None);
/// One test at a time: the script is process-wide.
static SERIAL: Mutex<()> = Mutex::new(());

/// The head's reason phrase.
const REASON: &[u8] = b"OK";

fn answer(out: *mut ServiceOut, o: Outcome, value: u64, len: u64) -> RawOutcome {
    // SAFETY: the SDK's `out`, live for the call.
    let out = unsafe { &mut *out };
    out.outcome = RawOutcome::of(o);
    out.value = value;
    out.len = len;
    RawOutcome::of(o)
}

extern "C" fn establish(_: HostCtx, _: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    answer(out, Outcome::Ready, 7, 0)
}

extern "C" fn write_request(_: HostCtx, i: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: a `RequestIn`, the SDK's.
    let io = unsafe { *i.cast::<RequestIn>() };
    answer(out, Outcome::Ready, 0, io.len as u64)
}

extern "C" fn read_reply(_: HostCtx, i: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: a `ReplyIn`, the SDK's.
    let io = unsafe { *i.cast::<ReplyIn>() };
    let mut g = SCRIPT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let s = g.as_mut().expect("a script");
    let first = s.reads == 0;
    if !first && s.body == Body::Slow {
        return answer(out, Outcome::Pending, 0, 0);
    }
    s.reads += 1;
    let (piece, len) = if first {
        let piece = ReplyPiece {
            kind: REPLY_HEAD,
            code: 200,
            reason: FrameSpan {
                offset: 0,
                len: REASON.len() as u64,
            },
            ..ReplyPiece::default()
        };
        // SAFETY: `io.buf` holds `io.len` writable bytes, the SDK's read buffer.
        unsafe { std::ptr::copy_nonoverlapping(REASON.as_ptr(), io.buf, REASON.len()) };
        (piece, REASON.len())
    } else {
        let piece = ReplyPiece {
            kind: REPLY_BODY,
            ..ReplyPiece::default()
        };
        // SAFETY: as above.
        unsafe { std::ptr::write_bytes(io.buf, b'x', io.len) };
        (piece, io.len)
    };
    // SAFETY: `io.piece` is the SDK's writable descriptor slot.
    unsafe { io.piece.write(piece) };
    answer(out, Outcome::Ready, 0, len as u64)
}

extern "C" fn close(_: HostCtx, _: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    if let Some(s) = SCRIPT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_mut()
    {
        s.closed = true;
    }
    answer(out, Outcome::Ready, 0, 0)
}

static SLOTS: ConnectorSlots = ConnectorSlots {
    size: std::mem::size_of::<ConnectorSlots>() as u32,
    slots: SERVICES,
    establish: Some(establish),
    reject_endpoint: None,
    side_stream: None,
    read: None,
    write: None,
    upgrade_secure: None,
    facts: None,
    checkout: None,
    checkin: None,
    close: Some(close),
    random: None,
    identity: None,
    read_reply: Some(read_reply),
    write_request: Some(write_request),
};

const TICKET: Ticket = Ticket {
    slot: 1,
    generation: 1,
};

/// One logged event: every field it carried, by name.
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

/// What one delivery of a line came to under `body`: the status it was judged on (`None` while it
/// pends, a deadline the host would fail as a transport failure), the codes it raised, how many
/// reply pieces it read, and whether it closed the stream.
struct Delivered {
    status: Option<u16>,
    codes: Vec<String>,
    reads: usize,
    closed: bool,
}

fn deliver(body: Body) -> Delivered {
    let _g = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *SCRIPT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Script {
        body,
        reads: 0,
        closed: false,
    });
    let tables = HostTables {
        size: std::mem::size_of::<HostTables>() as u32,
        _reserved: 0,
        ctx: HostCtx::NONE,
        wake: None,
        conns: &SLOTS,
        services: std::ptr::null(),
        io: std::ptr::null(),
    };
    let host = Host::of(&tables);
    let s: Settings = serde_json::from_value(serde_json::json!({"url": "https://siem.example/in"}))
        .expect("settings parse");
    let mut ex = delivery(&s, br#"{"ts":7,"outcome":"ok"}"#).expect("the line frames");
    let mut status = None;
    let cap = Capture::default();
    tracing::subscriber::with_default(cap.clone(), || {
        match post(&mut host.connector(TICKET), &mut ex) {
            Poll::Pending => {}
            Poll::Ready(answered) => {
                status = answered.as_ref().ok().map(|r| r.status);
                report(&s.url, answered);
            }
        }
    });
    let codes = cap
        .0
        .lock()
        .unwrap()
        .iter()
        .flat_map(|e| {
            e.iter()
                .filter(|(n, _)| n == "diag")
                .map(|(_, v)| v.clone())
        })
        .collect();
    let script = SCRIPT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take()
        .expect("a script");
    Delivered {
        status,
        codes,
        reads: script.reads,
        closed: script.closed,
    }
}

/// RED: a 2xx head followed by a HUGE body (past the exchange's 16 MiB bound) is a delivery the
/// receiver accepted: no BUSBAR-7072, judged 200 on the head, the body never read, the stream
/// closed.
#[test]
fn a_huge_body_after_a_2xx_head_raises_no_transport_error() {
    let d = deliver(Body::Huge);
    assert!(
        !d.codes.iter().any(|c| c == "BUSBAR-7072"),
        "a 2xx the receiver accepted was logged as a transport failure: {:?}",
        d.codes
    );
    assert!(d.codes.is_empty(), "{:?}", d.codes);
    assert_eq!(d.status, Some(200), "the delivery reports success");
    assert_eq!(d.reads, 1, "the head is the only piece read");
    assert!(d.closed, "the stream is closed");
}

/// RED: a 2xx head followed by a SLOW body (it never arrives) is judged at once on the head: the
/// delivery does not wait for the body and run into its deadline, which fails as BUSBAR-7072.
#[test]
fn a_slow_body_after_a_2xx_head_is_judged_on_the_head() {
    let d = deliver(Body::Slow);
    assert_eq!(
        d.status,
        Some(200),
        "the delivery waited on the body (its deadline would raise BUSBAR-7072)"
    );
    assert!(d.codes.is_empty(), "{:?}", d.codes);
    assert_eq!(d.reads, 1);
    assert!(d.closed, "the stream is closed");
}
