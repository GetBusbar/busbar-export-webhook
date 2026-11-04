// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The wipe-probe hooks of the shipped build: the production code calls them in every build, so the
//! test build (whose `tests/wipe_probe.rs` observes each registered payload's wipe) runs the same
//! function bodies the shipped build does. Here they register nothing.

/// Registers nothing: only the test build observes a payload.
#[inline]
pub(super) fn watch(_: &'static str, _: &[u8]) {}

/// Registers nothing: only the test build observes a JSON tree's strings and keys.
#[inline]
pub(super) fn watch_value(_: &'static str, _: &serde_json::Value) {}
