// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! T4: the Statement's strings asserted by their BYTES, not their lengths. Reading an `AbiStr` is
//! `unsafe` and the logic crate forbids `unsafe`, so the byte read lives in this test crate.

use busbar_export_webhook::{ALIAS, NAME, STATEMENT};

/// The bytes of a `'static` Statement string.
fn bytes(s: &busbar_contract::abi::mechanism::call::AbiStr) -> &'static [u8] {
    // SAFETY: every string of `STATEMENT` is a `'static` str the const builds with `abi_str`.
    unsafe { s.bytes() }
}

#[test]
fn the_statement_names_the_plugin_its_alias_and_its_target_by_bytes() {
    assert_eq!(bytes(&STATEMENT.name), NAME.as_bytes());
    assert_eq!(NAME, "busbar-export-webhook");
    // SAFETY: `rewrites` points at the `'static` one-row table `REWRITES`, `rewrites_len` long.
    let rewrites =
        unsafe { std::slice::from_raw_parts(STATEMENT.rewrites, STATEMENT.rewrites_len) };
    assert_eq!(rewrites.len(), 1);
    assert_eq!(bytes(&rewrites[0].from), ALIAS.as_bytes());
    assert_eq!(ALIAS, "request-log-webhook");
    // SAFETY: `needs` points at the `'static` one-row table `NEEDS`, `needs_len` long.
    let needs = unsafe { std::slice::from_raw_parts(STATEMENT.needs, STATEMENT.needs_len) };
    assert_eq!(needs.len(), 1);
    assert_eq!(bytes(&needs[0].target_from), b"settings.url");
    assert_eq!(bytes(&needs[0].transport), b"http");
    // SAFETY: `secret_refs` points at the `'static` table `SECRET_REFS`, `secret_refs_len` long.
    let secrets =
        unsafe { std::slice::from_raw_parts(STATEMENT.secret_refs, STATEMENT.secret_refs_len) };
    assert_eq!(secrets.len(), 1);
    assert_eq!(bytes(&secrets[0]), b"auth_header.value");
}
