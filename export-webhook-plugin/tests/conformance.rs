// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE PUBLISHED CONFORMANCE SUITE, RUN BY THIS PLUGIN** (busbar TODO ABI-b4; OWNER 2026-10-03:
//! plugins test themselves against busbar). busbar's suite, at the commit this repo pins
//! (`.busbar-ref`), drives the request-log WEBHOOK sink two ways through the one loader: LINKED (the
//! logic crate's `door`) and DROPPED IN (this crate's built cdylib), over the export kind's script
//! with the inputs in `conformance.json` (refused settings in the grammar's words, a delivery with no
//! connection table lent, a push sink's empty scrape, status and check, a route-less `serve`
//! answering 404); every step's crossings exactly at the script's pin, the two folds equal, and the
//! suite's RED arms kept. `plugin-ci.yml` runs it under `--release`.

//!
//! THE HOST (ARCHITECT Q-P4-9): the sink's `http` need is served by busbar's own connector, composed
//! as the root composes it ([`conformance_host`], rendered by the fleet template), and every delivery
//! reaches a REAL local HTTPS endpoint (the suite's far end, its certificate chained to the suite's
//! test anchors, which only the host trusts): the target in `conformance.json`'s settings.

#[path = "support/conformance_host.rs"]
mod conformance_host;

/// The far end's answer: an HTTP/1.1 `200` once a whole request (its head, then the
/// `content-length` body it states) has been read.
fn accepted(seen: &[u8]) -> Option<Vec<u8>> {
    let end = seen.windows(4).position(|w| w == b"\r\n\r\n")? + 4;
    let head = String::from_utf8_lossy(&seen[..end]).to_ascii_lowercase();
    let body = head
        .lines()
        .find_map(|l| l.strip_prefix("content-length:"))
        .and_then(|n| n.trim().parse::<usize>().ok())
        .unwrap_or(0);
    (seen.len() >= end + body).then(|| b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n".to_vec())
}

/// The host the suite binds the sink over, with the far end its settings name already listening.
fn host(
    wake: std::sync::Arc<dyn Fn(u64) + Send + Sync>,
    anchors: Option<&str>,
) -> std::sync::Arc<dyn busbar_contract::conn::DeclaredConns> {
    conformance_host::far_end(accepted);
    conformance_host::host(wake, anchors)
}

busbar_plugin_loader::conformance_suite! {
    door: busbar_export_webhook::door,
    cdylib: "busbar_export_webhook_plugin",
    inputs: include_str!("conformance.json"),
    host: host,
    tls: conformance_host::anchors(),
}
