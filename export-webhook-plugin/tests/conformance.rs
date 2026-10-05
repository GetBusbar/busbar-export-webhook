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

busbar_plugin_loader::conformance_suite! {
    door: busbar_export_webhook::door,
    cdylib: "busbar_export_webhook_plugin",
    inputs: include_str!("conformance.json"),
}
