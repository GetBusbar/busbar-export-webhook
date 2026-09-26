// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **request-log WEBHOOK sink as a droppable busbar plugin** — the `cdylib` a signed tarball of
//! the sink carries (`kind: export`, alias `request-log-webhook`).
//!
//! All the sink lives in the `busbar-export-webhook` crate, including its one door registration
//! (`export_export_plugin!(open)`): the frozen symbols the loader looks up are the SDK's, defined
//! once, and they answer through that door. This crate re-exports the logic crate so the library it
//! builds carries exactly the code the busbar binary links — one source, both doors (DECISIONS #2
//! rule (1)). Pack it with `busbar-plugin-pack --kind export --alias request-log-webhook
//! --declares-file export-webhook/declares.json`.

#![deny(unsafe_code)]

pub use busbar_export_webhook::*;
