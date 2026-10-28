// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **A PUSH SINK REFUSES `scrape` AND `serve`, SAYING WHY, THROUGH BOTH DOORS** (sibling review of
//! the export kind): the sink carries no `metrics` stream and declares no route, so each answer is
//! REFUSED with its cause in the error text, the same words in every export sibling — never a silent
//! empty exposition or a bare outcome. Driven over the real loader, LINKED and DROPPED IN.
//!
//! RED before: `scrape` answered READY with nothing written (or a bare REFUSED), and `serve` a bare
//! answer with no cause.

use std::path::PathBuf;
use std::sync::Arc;

use busbar_contract::abi::export::{self, ScrapeIn, ScrapeOut, ServeIn, ServeOut};
use busbar_contract::abi::mechanism::call::{Blob, Outcome, BLOB_JSON};
use busbar_contract::abi::mechanism::lifecycle::{slot as lc, OpenIn, OpenOut};
use busbar_contract::abi::sdk::door::{blank_in, blank_out};
use busbar_plugin_loader::dispatch::kinds::export::Export;
use busbar_plugin_loader::dispatch::{
    in_head, load_dropped, load_linked, out_head, Bind, ConnTable, DispatchConfig, Dispatcher,
    Frame, LinkedRow, NoSink, Plugin,
};

const SETTINGS: &[u8] = br#"{"url":"https://w.example/in"}"#;

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
        .unwrap_or_else(|| panic!("the busbar_export_webhook_plugin cdylib ({file}) is not built"))
}

fn row() -> LinkedRow {
    LinkedRow::of(busbar_export_webhook::door).expect("the linked door renders")
}

/// The door, linked or dropped in, opened on `SETTINGS`.
fn opened(dropped: bool) -> (Arc<Dispatcher>, Plugin<Export>) {
    let d = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let bind = Bind {
        instance: Arc::from("export.sibling"),
        max_inflight_cap: 64,
        sink: Arc::new(NoSink),
        dispatcher: d.adopter(),
        conns: ConnTable::Probe,
    };
    let p = if dropped {
        load_dropped::<Export>(&cdylib(), &row().statement, bind).expect("the dropped door loads")
    } else {
        load_linked::<Export>(&row(), bind).expect("the linked door loads")
    };
    let mut input: OpenIn = blank_in();
    input.head = in_head();
    input.settings = Blob {
        ptr: SETTINGS.as_ptr(),
        len: SETTINGS.len(),
        fmt: BLOB_JSON,
        flags: 0,
    };
    input.generation = 1;
    let mut out: OpenOut = blank_out();
    out.head = out_head();
    let called = p.call(lc::OPEN, &mut Frame::new(input, out));
    assert_eq!(called.outcome, Outcome::Ready);
    (d, p)
}

/// The outcome and error text of `scrape` and of `serve`.
fn answers(p: &Plugin<Export>) -> [(Outcome, Option<String>); 2] {
    let text = |e: Option<&Vec<u8>>| e.map(|e| String::from_utf8_lossy(e).into_owned());
    let mut input: ScrapeIn = blank_in();
    input.head = in_head();
    let mut out: ScrapeOut = blank_out();
    out.head = out_head();
    let mut f = Frame::new(input, out);
    let scraped = p.call(export::slot::SCRAPE, &mut f);
    assert_eq!(f.out.written, 0, "a refused scrape writes nothing");
    let mut input: ServeIn = blank_in();
    input.head = in_head();
    let mut out: ServeOut = blank_out();
    out.head = out_head();
    let served = p.call(export::slot::SERVE, &mut Frame::new(input, out));
    [
        (scraped.outcome, text(scraped.error.as_ref())),
        (served.outcome, text(served.error.as_ref())),
    ]
}

#[test]
fn a_push_sink_refuses_scrape_and_serve_saying_why_through_both_doors() {
    let want = [
        (
            Outcome::Refused,
            Some(busbar_export_webhook::NO_EXPOSITION.to_string()),
        ),
        (
            Outcome::Refused,
            Some(busbar_export_webhook::NO_ROUTE.to_string()),
        ),
    ];
    for dropped in [false, true] {
        let (_d, p) = opened(dropped);
        assert_eq!(answers(&p), want, "dropped in: {dropped}");
    }
}
