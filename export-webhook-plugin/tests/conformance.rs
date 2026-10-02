// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **ONE WEBHOOK SINK, BOTH DOORS, ONE TABLE** — the webhook sink's linked + dropped-in conformance
//! on the export kind's memory ABI (THE DESIGN §11.4), run against the busbar rev this repo pins
//! (`.busbar-ref`).
//!
//! The sink is held two ways at once: LINKED (the logic crate's `door`, through the loader's
//! `load_linked`) and DROPPED IN (this crate's built cdylib, `dlopen`ed by the loader's
//! `load_dropped`, which resolves `busbar_plugin_door`, validates the door and compares its
//! Statement with the stated one byte for byte). Each is bound to a real dispatcher and driven over
//! the same script through the export kind's table: `validate` over good and refused settings,
//! `open`, `check` at both phases across two instances (the findings under a lease, then released),
//! `deliver`, `scrape`, `status`, `serve`, `close`, with every envelope entry the host ingested.
//! The two transcripts must be equal.
//!
//! NOT HELD HERE: a delivery that reaches a far end. The script's calls are ticket-less and the
//! bind lends no connection table, so each line's exchange answers the transport failure (or the
//! target's admission refuses it) — the same through both doors.
//!
//! THE RED ARMS, same file: the door asked for as another kind is refused; a stated Statement that
//! is not the door's is refused; the same door opened over unparsed settings answers a different
//! transcript. A missing cdylib PANICS — this test IS the dropped-in door's proof, and never skips.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use busbar_contract::abi::export::{
    slot, CheckIn, CheckInstance, CheckOut, DeliverIn, ScrapeIn, ScrapeOut, ServeIn, ServeOut,
    StatusOut, CHECK_PHASE_INSTANCES, CHECK_PHASE_LIMITS,
};
use busbar_contract::abi::mechanism::call::{AbiStr, Blob, InHead, OutHead, BLOB_JSON, BLOB_JSONL};
use busbar_contract::abi::mechanism::lifecycle::{
    slot as lc, OpenIn, OpenOut, ReleaseIn, ValidateIn,
};
use busbar_plugin_loader::dispatch::kinds::export::Export;
use busbar_plugin_loader::dispatch::kinds::hook::Hook;
use busbar_plugin_loader::dispatch::{
    in_head, load_dropped, load_linked, out_head, rendering_of_library, Bind, Called, Diagnostic,
    DispatchConfig, Dispatcher, Dropped, EnvelopeSink, Frame, LinkedRow, LoadError, Metric, Plugin,
    NO_BLOB,
};

/// This crate's built cdylib (uplifted or under `deps`, newest wins). A missing artifact is a
/// failure, never a skip.
fn cdylib() -> PathBuf {
    let exe = std::env::current_exe().expect("the test binary has a path");
    let profile = exe
        .parent()
        .and_then(|d| d.parent())
        .expect("target/<profile>");
    let file = busbar_plugin_loader::plugin_library_filename("busbar_export_webhook_plugin");
    [profile.join(&file), profile.join("deps").join(&file)]
        .into_iter()
        .filter_map(|p| Some((std::fs::metadata(&p).ok()?.modified().ok()?, p)))
        .max()
        .map(|(_, p)| p)
        .unwrap_or_else(|| panic!("the busbar-export-webhook-plugin cdylib ({file}) is not built"))
}

/// Every envelope entry the host ingested, as text.
#[derive(Default)]
struct Recorder(Mutex<Vec<String>>);

impl EnvelopeSink for Recorder {
    fn metric(&self, m: Metric<'_>) {
        self.0
            .lock()
            .unwrap()
            .push(format!("metric {} {} {}", m.family, m.kind, m.value));
    }
    fn diag(&self, d: Diagnostic<'_>) {
        self.0.lock().unwrap().push(format!(
            "diag {} {} {}",
            String::from_utf8_lossy(d.name),
            d.severity,
            String::from_utf8_lossy(d.text)
        ));
    }
    fn dropped(&self, why: Dropped) {
        self.0.lock().unwrap().push(format!("dropped {why:?}"));
    }
}

fn bind(d: &Dispatcher, sink: Arc<Recorder>) -> Bind {
    Bind {
        instance: Arc::from("tail"),
        max_inflight_cap: 64,
        sink,
        dispatcher: d.adopter(),
        conns: None,
    }
}

/// A blank head stating `I`'s size (the host states the `in` it wrote).
fn head<I>() -> InHead {
    InHead {
        size: std::mem::size_of::<I>() as u32,
        ..in_head()
    }
}

const fn blob(bytes: &'static [u8], fmt: u32) -> Blob {
    Blob {
        ptr: bytes.as_ptr(),
        len: bytes.len(),
        fmt,
        flags: 0,
    }
}

fn answered(c: &Called) -> String {
    let error = c
        .error
        .as_deref()
        .map(String::from_utf8_lossy)
        .unwrap_or_default();
    format!("{:?} {error:?} lease={}", c.outcome, c.lease)
}

/// One door's transcript over `settings`: every op's answer, then every envelope entry.
fn transcript(p: &Plugin<Export>, rec: &Recorder, settings: &'static [u8]) -> Vec<String> {
    let mut t = Vec::new();
    for s in [
        &br#"{"url":"https://a.example/"}"#[..],
        b"{}",
        br#"{"url":"https://a/","bogus":1}"#,
        br#"{"url":"https://a/","auth_header":{"name":"A"}}"#,
    ] {
        let mut err = vec![0_u8; 512];
        let input = ValidateIn {
            head: head::<ValidateIn>(),
            settings: Blob {
                ptr: s.as_ptr(),
                len: s.len(),
                fmt: BLOB_JSON,
                flags: 0,
            },
            err_buf: err.as_mut_ptr(),
            err_cap: err.len(),
        };
        let mut f = Frame::new(input, out_head());
        t.push(format!(
            "validate {}",
            answered(&p.call(lc::VALIDATE, &mut f))
        ));
    }

    let mut err = vec![0_u8; 512];
    let mut f = Frame::new(
        OpenIn {
            head: head::<OpenIn>(),
            host: std::ptr::null(),
            settings: Blob {
                ptr: settings.as_ptr(),
                len: settings.len(),
                fmt: BLOB_JSON,
                flags: 0,
            },
            secrets: std::ptr::null(),
            secrets_len: 0,
            generation: 1,
            err_buf: err.as_mut_ptr(),
            err_cap: err.len(),
        },
        OpenOut {
            head: out_head(),
            instance: std::ptr::null_mut(),
            err_len: 0,
        },
    );
    t.push(format!("open {}", answered(&p.call(lc::OPEN, &mut f))));

    let mut f = Frame::new(
        DeliverIn {
            head: head::<DeliverIn>(),
            op_id: [7; 16],
            stream: 1,
            _reserved: [0; 7],
            batch: blob(b"{\"outcome\":\"ok\",\"ts\":1}\n", BLOB_JSONL),
        },
        out_head(),
    );
    t.push(format!(
        "deliver {}",
        answered(&p.call(slot::DELIVER, &mut f))
    ));

    let mut buf = vec![0_u8; 64];
    let mut f = Frame::new(
        ScrapeIn {
            head: head::<ScrapeIn>(),
            families: std::ptr::null(),
            families_len: 0,
            buf: buf.as_mut_ptr(),
            cap: buf.len(),
        },
        ScrapeOut {
            head: out_head(),
            written: 0,
            needed: 0,
        },
    );
    let c = p.call(slot::SCRAPE, &mut f);
    t.push(format!("scrape {} written={}", answered(&c), f.out.written));

    let mut f = Frame::new(
        in_head(),
        StatusOut {
            head: out_head(),
            status: NO_BLOB,
        },
    );
    let c = p.call(slot::STATUS, &mut f);
    t.push(format!("status {} len={}", answered(&c), f.out.status.len));

    let names = [b"a".as_slice(), b"b"];
    let settings_of: [&[u8]; 2] = [
        br#"{"url":"https://u:s3cret@a.example/","max_inflight_deliveries":0}"#,
        br#"{"url":"https://b.example/","max_inflight_deliveries":8,"delivery_timeout_secs":0}"#,
    ];
    let instances: Vec<CheckInstance> = (0..2)
        .map(|i| CheckInstance {
            name: AbiStr {
                ptr: names[i].as_ptr(),
                len: names[i].len(),
            },
            settings: Blob {
                ptr: settings_of[i].as_ptr(),
                len: settings_of[i].len(),
                fmt: BLOB_JSON,
                flags: 0,
            },
        })
        .collect();
    for phase in [CHECK_PHASE_LIMITS, CHECK_PHASE_INSTANCES] {
        let mut f = Frame::new(
            CheckIn {
                head: head::<CheckIn>(),
                phase,
                _reserved: 0,
                instances: instances.as_ptr(),
                instances_len: instances.len(),
            },
            CheckOut {
                head: out_head(),
                findings: NO_BLOB,
            },
        );
        let c = p.call(slot::CHECK, &mut f);
        let b = f.out.findings;
        let findings = if b.ptr.is_null() {
            String::new()
        } else {
            // SAFETY: the findings are the plugin's, held under the answer's lease until release.
            String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(b.ptr, b.len) })
                .into_owned()
        };
        t.push(format!("check {phase} {} {findings}", answered(&c)));
        if c.lease != 0 {
            let mut f = Frame::new(
                ReleaseIn {
                    head: head::<ReleaseIn>(),
                    lease: c.lease,
                },
                out_head(),
            );
            t.push(format!(
                "release {}",
                answered(&p.call(lc::RELEASE, &mut f))
            ));
        }
    }

    let method = b"GET";
    let path = b"/exports/tail/x";
    let mut f = Frame::new(
        ServeIn {
            head: head::<ServeIn>(),
            method: AbiStr {
                ptr: method.as_ptr(),
                len: method.len(),
            },
            path: AbiStr {
                ptr: path.as_ptr(),
                len: path.len(),
            },
            query: AbiStr {
                ptr: std::ptr::null(),
                len: 0,
            },
            headers: std::ptr::null(),
            headers_len: 0,
            body: NO_BLOB,
        },
        ServeOut {
            head: out_head(),
            status_code: 0,
            _reserved: [0; 6],
            headers_out: std::ptr::null(),
            headers_out_len: 0,
            body: NO_BLOB,
        },
    );
    let c = p.call(slot::SERVE, &mut f);
    t.push(format!("serve {} code={}", answered(&c), f.out.status_code));

    let mut f: Frame<InHead, OutHead> = Frame::new(in_head(), out_head());
    t.push(format!("close {}", answered(&p.call(lc::CLOSE, &mut f))));

    t.extend(rec.0.lock().unwrap().drain(..));
    t
}

const SETTINGS: &[u8] =
    br#"{"url":"https://siem.example/in","auth_header":{"name":"Authorization","value":"Bearer x"}}"#;

/// The webhook sink loads as ONE door both ways and answers alike, byte for byte.
#[test]
fn the_linked_and_the_dropped_in_webhook_sink_are_one_sink() {
    let d = Dispatcher::new(DispatchConfig::default());
    let row = LinkedRow::of(busbar_export_webhook::door).expect("the door states itself");

    // What the packer signs into the manifest is the linked row's Statement, byte for byte.
    let packed = rendering_of_library(&cdylib()).expect("the cdylib loads");
    assert_eq!(packed.as_deref(), Some(&row.statement[..]));

    let (lr, dr) = (Arc::new(Recorder::default()), Arc::new(Recorder::default()));
    let linked: Plugin<Export> = load_linked(&row, bind(&d, lr.clone())).expect("linked loads");
    let dropped: Plugin<Export> =
        load_dropped(&cdylib(), &row.statement, bind(&d, dr.clone())).expect("dropped loads");
    assert_eq!(linked.name(), "busbar-export-webhook");
    assert_eq!(dropped.name(), linked.name());

    let a = transcript(&linked, &lr, SETTINGS);
    let b = transcript(&dropped, &dr, SETTINGS);
    assert_eq!(a, b, "the two doors are not one sink");

    // What the script did: the settings refusals in the grammar's words, the two validation-phase
    // checks across the instances (the target's userinfo masked), a dropped delivery raised under
    // its code, a push sink's empty answers.
    let joined = a.join("\n");
    for want in [
        "validate Ready \"\"",
        "settings: missing field `url`",
        "settings: unknown field `bogus`",
        "settings: missing field `value`",
        "open Ready",
        "deliver Ready",
        "scrape Ready \"\" lease=0 written=0",
        "status Ready \"\" lease=0 len=0",
        // The bound is the largest over the instances (8): a stingy sibling is not refused.
        "check 0 Ready \"\" lease=0 \n",
        "targeting 'https://b.example/' (#1)",
        "release Ready",
        "serve Ready \"\" lease=0 code=404",
        "close Ready",
        "BUSBAR-707",
    ] {
        assert!(joined.contains(want), "missing {want:?} in:\n{joined}");
    }

    // The masked userinfo never reaches a transcript line.
    assert!(!joined.contains("s3cret"), "{joined}");

    // RED: the same door over settings that do not parse raises nothing on delivery.
    let rr = Arc::new(Recorder::default());
    let other: Plugin<Export> =
        load_dropped(&cdylib(), &row.statement, bind(&d, rr.clone())).expect("dropped loads");
    let c = transcript(&other, &rr, b"{}");
    assert_ne!(
        c, a,
        "an unconfigured sink must not answer as a configured one"
    );
    assert!(!c.join("\n").contains("BUSBAR-707"));
}

/// The door is refused as another kind, and against a Statement that is not its own.
#[test]
fn the_door_is_refused_as_another_kind_or_statement() {
    let d = Dispatcher::new(DispatchConfig::default());
    let row = LinkedRow::of(busbar_export_webhook::door).expect("the door states itself");
    let rec = Arc::new(Recorder::default());
    assert!(load_linked::<Hook>(&row, bind(&d, rec.clone())).is_err());
    assert!(load_dropped::<Hook>(&cdylib(), &row.statement, bind(&d, rec.clone())).is_err());

    let mut other = row.statement.clone();
    let last = other.len() - 1;
    other[last] ^= 1;
    let refused = load_dropped::<Export>(&cdylib(), &other, bind(&d, rec));
    assert!(matches!(refused, Err(LoadError::StatementMismatch)));
}
