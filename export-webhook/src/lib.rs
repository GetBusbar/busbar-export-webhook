// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **`busbar-export-webhook`** — the request-log WEBHOOK sink as a `kind: export` plugin on the
//! export kind's memory ABI (`busbar_contract::abi::export`):
//! `export.<name>.module: request-log-webhook`. ONE door ([`door`], `plugin_door!`), linked into
//! the binary as a compiled-in row or exported by the sibling `busbar-export-webhook-plugin` cdylib
//! as its one symbol; its manifest carries [`DECLARES`] (the shed counter and the four catalogue
//! codes it raises).
//!
//! Each request-log line of a delivered batch is POSTed, as the compact JSON line it is, with
//! `content-type: application/json`, the instance's optional `auth_header` (one that cannot be sent
//! as an HTTP header, or names a framing field, is refused at validate/open/refresh and check), and
//! the `authorization: Basic …` a userinfo in the URL becomes, to
//! the instance's `https://` target — through the HOST's connector: the Statement declares ONE outbound
//! need whose target is the `url` setting (the host drops its userinfo), under the open-web egress
//! class (public destinations over a secure connection only), and the request rides the SDK's
//! framed `exchange` under the instance's `delivery_timeout_secs`, a deadline over the whole
//! exchange of one line from before its connection is established. The sink never dials. A delivery
//! is fire-and-forget and never retried: a non-2xx answer or a transport failure drops that one line
//! and raises BUSBAR-7071 / BUSBAR-7072 at WARN.
//!
//! **Admission.** The door states `ready`, so the host's verdict on the target (the need's admission
//! at bind) is asked at boot, before the instance serves; a refused target raises BUSBAR-7070
//! (`…; disabling this webhook exporter`) once and the instance takes no delivery until a reload —
//! its siblings keep delivering.
//!
//! **Settings** are checked in two phases: their SHAPE, and an `auth_header` that cannot be sent,
//! while the configuration is resolved (`validate`, and again at `open`/`refresh`); and the
//! in-flight bound (limits phase), the delivery deadline and the auth header (instances phase)
//! while it is validated (`check`). Every line the sink raises about a target or a delivery is
//! logged with the catalogue's `diag` banner field; the one exception is an admission the host
//! could not answer, an ERROR line retried by the next readiness check or delivery, whose batch's
//! dropped lines each raise BUSBAR-7072. The door's call capture carries them to the instance's
//! plugin log.
//!
//! No `unsafe`: `check`'s instance list is read through the SDK's safe lend (`instances()`).

#![cfg_attr(not(test), forbid(unsafe_code))]
#![deny(unsafe_code)]

#[cfg(test)]
#[path = "tests/ownership_tests.rs"]
mod ownership_tests;
#[cfg(test)]
#[allow(unsafe_code)]
#[path = "tests/wipe_probe.rs"]
mod wipe_probe;
// The shipped build's wipe-probe hooks, which observe nothing (the test build's are its observer).
#[cfg(not(test))]
#[path = "wipe_probe_off.rs"]
mod wipe_probe;

use std::ops::Deref;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::task::Poll;

use busbar_contract::abi::export::{
    self, CheckIn, CheckOut, CheckPhase, DeliverIn, ExportStream, Tail, CHECK_PHASE_INSTANCES,
    CHECK_PHASE_LIMITS,
};
use busbar_contract::abi::host::conn::connector::{Need, DIRECTION_OUTBOUND, EGRESS_OPEN_WEB};
use busbar_contract::abi::mechanism::call::{AbiStr, Blob, OutHead, Outcome, BLOB_JSON};
use busbar_contract::abi::mechanism::door::{KindTailHead, Rewrite, Statement};
use busbar_contract::abi::sdk::conn::{ConnFailure, Host};
use busbar_contract::abi::sdk::cred::{Cred, SettingsValue};
use busbar_contract::abi::sdk::door::{abi_str, alias, statement};
use busbar_contract::abi::sdk::exchange::{
    exchange, Exchange, ExchangeResponse, Request, SealedField,
};
use busbar_contract::abi::sdk::export::tail;
use busbar_contract::abi::sdk::life::{settings_value, Held, Life, Refreshed, Refusal};
use busbar_contract::abi::sdk::mask::mask_url;
use busbar_contract::abi::sdk::migrate::{Migrate, Migrated};
use busbar_contract::abi::sdk::url::{self as sdk_url, Userinfo};
use busbar_contract::abi::sdk::{Instance, Lent, Out, Safe, SafeSlot};

/// The plugin's canonical name.
pub const NAME: &str = "busbar-export-webhook";
/// The module name an `export:` instance names it by.
pub const ALIAS: &str = "request-log-webhook";
/// The manifest `declares` section (`--declares-file` for the signed tarball).
pub const DECLARES: &str = include_str!("../declares.json");

/// The in-flight ceiling `check` holds each instance's bound to
/// (`tokio::sync::Semaphore::MAX_PERMITS`, `usize::MAX >> 3`). The host builds no semaphore: its
/// export axis saturates the bound into a `u32`, clamped to at least one, and caps the instance's
/// in-flight deliveries at it.
const MAX_PERMITS: usize = usize::MAX >> 3;
/// The ceiling every duration in a busbar configuration is bounded by (30 years, in seconds).
const MAX_DURATION_SECS: u64 = 30 * 365 * 86_400;

const DISABLED: &str = "BUSBAR-7070";
const NON_2XX: &str = "BUSBAR-7071";
const TRANSPORT_ERROR: &str = "BUSBAR-7072";
const RELOAD_CUT: &str = "BUSBAR-7109";

/// The host pins connector and disk bindings for the entire delivery ticket, including resumes
/// of a parked exchange, when a delivery's head extensions carry this capability at
/// [`TICKET_BINDINGS_VERSION`]: a batch started before a reload then finishes on its original target
/// and credentials instead of being cut ([`Webhook::cut_by_reload`]).
const TICKET_BINDINGS: &str = "busbar.export.ticket-bindings";
/// Version of the host ticket-custody capability documented by the export lifecycle.
const TICKET_BINDINGS_VERSION: &[u8] = b"1";

fn pinned_ticket_bindings(extensions: &[u8]) -> bool {
    busbar_contract::abi::mechanism::extensions::get(extensions, TICKET_BINDINGS)
        == Some(TICKET_BINDINGS_VERSION)
}

/// The config path the target comes from: the `url` setting (`settings.<key>`, the path the host's
/// connection-table fill resolves). A bare key resolves to nothing, and the host's
/// connector refuses a need whose target resolved to nothing.
const TARGET_FROM: &str = "settings.url";

/// The in-flight ceiling this sink declares: no bound of its own. The bound is the operator's
/// `max_inflight_deliveries` (64 when unset), which the host applies per instance, clamped to at
/// least one; `check` refuses each instance's bound past [`MAX_PERMITS`] or below 1
/// ([`check`]).
pub(crate) const MAX_INFLIGHT: u32 = u32::MAX;
/// The one need's index in the Statement.
pub(crate) const NEED: u32 = 0;

mod config;
mod owners;
mod redact;

fn parsed_url(text: &str) -> Result<owners::ParsedUrl, url::ParseError> {
    let parsed = owners::ParsedUrl::parse(text)?;
    wipe_probe::watch("parsed url", parsed.as_str().as_bytes());
    Ok(parsed)
}

pub(crate) use config::{ExportAuthHeader, WebhookSettings};
pub(crate) use redact::{log_target, scrub};

/// This sink's settings (the configuration's `WebhookSettings`).
pub(crate) type Settings = WebhookSettings;

/// The one need: outbound over a secure connection to the `url` setting's target, public
/// destinations only (refusing loopback, link-local, private, CGNAT and cloud-metadata targets).
/// It is framed by the `http` transport — the scheme its claim names; an `https://` target is
/// secured by the host's connector, and the open-web egress class refuses any target that is not
/// secure before a byte leaves.
const NEEDS: &[Need] = &[Need {
    direction: DIRECTION_OUTBOUND,
    egress_class: EGRESS_OPEN_WEB,
    transport: abi_str("http"),
    target_from: abi_str(TARGET_FROM),

    keep_mode: busbar_contract::abi::host::conn::connector::KEEP_NAMED,
    ..Need::EMPTY
}];

/// The streams this sink carries: the request log.
const STREAMS: &[u8] = &[ExportStream::Logs as u8];

/// The export kind's Statement tail: `logs`, and no route (a push-only sink).
const TAIL: Tail = tail(STREAMS, &[]);

/// The module name an operator writes, as the alias the registry holds beside [`NAME`].
const REWRITES: &[Rewrite] = &[alias(ALIAS)];

/// The settings field that is SECRET, declared so the kernel resolves a `{env:}`/`{file:}`/
/// `{module:}` reference written there: `auth_header.value`, the header's value is the credential.
/// The export host preserves literal values for compatibility; the sink receives the resolved string.
const SECRET_REFS: &[AbiStr] = &[abi_str("auth_header.value")];

busbar_contract::statement_extensions!(EXTENSIONS: [
    (busbar_contract::abi::mechanism::extensions::EXT_REFERENCE_FIELDS, br#"["url"]"#),
]);

/// This plugin's Statement: its name, version, its in-flight ceiling, alias, stream and need.
pub(crate) const STATEMENT: Statement = Statement {
    settings_schema: Blob::json(include_bytes!("../settings.schema.json")),
    secret_refs: SECRET_REFS.as_ptr(),
    secret_refs_len: SECRET_REFS.len(),
    extensions: EXTENSIONS,
    kind_tail: (&TAIL as *const Tail).cast::<KindTailHead>(),
    rewrites: REWRITES.as_ptr(),
    rewrites_len: REWRITES.len(),
    needs: NEEDS.as_ptr(),
    needs_len: NEEDS.len(),
    ..statement(NAME, env!("CARGO_PKG_VERSION"), MAX_INFLIGHT)
};

/// The settings, parsed as the configuration grammar parses them (empty is `{}`); a `url` whose
/// credential would be misread as its host is refused ([`ambiguous_url`]).
fn parse(settings: &[u8]) -> Result<Settings, Refusal> {
    let value = SettingsValue::from(settings_value(settings)?);
    wipe_probe::watch_value("settings JSON", &value);

    let mut credentials = zeroize::Zeroizing::new(redact::settings_credentials(&value));
    let settings: Settings =
        serde::Deserialize::deserialize(&*value).map_err(|e: serde_json::Error| {
            let detail = zeroize::Zeroizing::new(format!("settings: {e}"));
            Refusal::failed(sdk_url::scrub(
                &detail,
                std::mem::take(&mut *credentials),
                true,
            ))
        })?;
    if let Some(refusal) = ambiguous_url(&settings.url) {
        return Err(Refusal::failed(refusal));
    }
    Ok(settings)
}

/// The settings an instance runs on: [`parse`]d, and an `auth_header` that cannot be sent is
/// refused: one named for a framing field in [`framing_words`], any other in generic words (the
/// instance would otherwise POST every line unauthenticated). The value is never echoed.
/// The `url` must parse (a URL that does not would silently target `"/"`), the delivery deadline
/// must be in bounds (zero drops every line; a huge value enables a tarpit), and the in-flight
/// bound must be >= 1.
fn parse_to_run(settings: &[u8]) -> Result<Settings, Refusal> {
    let parsed = parse(settings)?;
    if parsed_url(&parsed.url).is_err() && ambiguous_url(&parsed.url).is_none() {
        return Err(Refusal::failed(format!(
            "settings: `url` is not a valid URL (target: {})",
            redact::unparsed_target(&parsed.url),
        )));
    }
    if let Some(h) = parsed.auth_header.as_ref().filter(|h| is_framing(&h.name)) {
        return Err(Refusal::failed(framing_words(&h.name)));
    }
    if parsed
        .auth_header
        .as_ref()
        .is_some_and(|h| !header_builds(h))
    {
        return Err(Refusal::failed(
            "settings: `auth_header` cannot be sent as an HTTP header",
        ));
    }
    if parsed.delivery_timeout_secs < 1 {
        return Err(Refusal::failed(
            "settings: `delivery_timeout_secs` must be >= 1",
        ));
    }
    if parsed.delivery_timeout_secs > MAX_DURATION_SECS {
        return Err(Refusal::failed(format!(
            "settings: `delivery_timeout_secs` ({}) exceeds the {MAX_DURATION_SECS}-second \
             (30-year) ceiling",
            parsed.delivery_timeout_secs,
        )));
    }
    Ok(parsed)
}

/// The ambiguous-URL refusal: `Some(the refusal)` when `url` parses but
/// carries an `@` after its host — `https://tok/en@siem.example/…` or `https://u:123/x@siem.example/…`,
/// a credential holding an unescaped `/`, `?` or `#`, which a URL parser reads as host `tok` (or
/// `u`, port `123`) and a path, so the credential would be dialled as a host and written into
/// lines. A url that does not parse and holds an `@` anywhere is refused the same way
/// (`https:svc:pa/ss@siem/…` fails on the port `pa`). A parsed url with no `@` after its host is not
/// ambiguous here. The refusal shows only `<scheme>:***` ([`redact::unparsed_target`]): the parser's
/// host of an ambiguous url is the front of the credential, so no part of the text is echoed. The
/// words are the SDK's (`sdk::url::ambiguous_url`); the parse is this plugin's own WHATWG reader,
/// the one its target is dialled by.
pub(crate) fn ambiguous_url(url: &str) -> Option<String> {
    let from_path = zeroize::Zeroizing::new(match parsed_url(url) {
        Ok(parsed) => parsed[url::Position::BeforePath..].to_string(),
        Err(_) if url.contains('@') => "@".to_string(),
        Err(_) => return None,
    });
    sdk_url::ambiguous_url(&redact::unparsed_target(url), &from_path)
}

/// One opened instance.
pub(crate) struct Webhook {
    /// Its settings and the request every line shares. `open` and `refresh` refuse settings that do
    /// not parse, so an instance never holds unparsed ones and never sits silently dead.
    settings: RwLock<Arc<Prepared>>,
    /// Counts the reloads that changed the settings, bumped under the `settings` write lock: a
    /// delivery compares it instead of cloning the settings per line.
    generation: AtomicU64,
    /// The host's verdict on the target, asked once: at boot by `ready` (and again after a
    /// `refresh` clears it, by the next delivery or readiness ask); `None` until then.
    live: Mutex<Option<bool>>,
}

/// `Debug` names the settings through [`Prepared`]'s redacting `Debug`, and the generation; the
/// verdict is a plain flag.
impl std::fmt::Debug for Webhook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Webhook")
            .field("settings", &self.settings())
            .field("generation", &self.generation.load(Ordering::Acquire))
            .field(
                "live",
                &*self.live.lock().unwrap_or_else(PoisonError::into_inner),
            )
            .finish()
    }
}

impl Life for Webhook {
    type Kind = busbar_contract::plugin::markers::ExportKind;
    const CANCEL: u32 = export::cancel::ABORTED;

    /// The settings' shape, in the configuration grammar's own serde words.
    fn validate(settings: &[u8]) -> Result<(), Refusal> {
        parse_to_run(settings).map(|_| ())
    }

    /// Refuses settings that do not parse, in the same words as [`Life::validate`]: an instance
    /// that opened on them would drop every delivery without a word.
    fn open(settings: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        Ok(Self {
            settings: RwLock::new(Arc::new(Prepared::new(parse_to_run(settings)?))),
            generation: AtomicU64::new(0),
            live: Mutex::new(None),
        })
    }

    /// Discovery at boot (the mechanism's `ready`, awaited after `open` before the instance serves):
    /// the host's verdict on the target is asked here, once, so a refused target raises BUSBAR-7070
    /// at boot. It never refuses the boot: the instance is disabled and its siblings serve.
    /// Settings that did not parse are the configuration's refusal, not this one's.
    fn ready(
        &self,
        host: &Host<busbar_contract::plugin::markers::ExportKind>,
        _: busbar_contract::abi::mechanism::ticket::Ticket,
    ) -> Poll<Result<(), Refusal>> {
        let _ = self.admitted(Some(host));
        Poll::Ready(Ok(()))
    }

    /// A reload's settings replace the instance's, and its target is asked about afresh; settings
    /// that do not parse are refused and the old ones (and their verdict) stay.
    fn refresh(&self, settings: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
        let parsed = parse_to_run(settings)?;

        let mut live = self.live.lock().unwrap_or_else(PoisonError::into_inner);
        let mut current = self
            .settings
            .write()
            .unwrap_or_else(PoisonError::into_inner);

        if current.settings != parsed {
            let moves = !current.routes_as(&parsed);
            *current = Arc::new(Prepared::new(parsed));
            if moves {
                self.generation.fetch_add(1, Ordering::Release);
            }
        }
        drop(current);
        *live = None;
        Ok(Refreshed::default())
    }
}

impl Webhook {
    /// The instance's settings (with their prepared request).
    pub fn settings(&self) -> Arc<Prepared> {
        self.current().0
    }

    /// Whether the target or the credentials now differ from those `at` started under. The generation
    /// is the fast path; when it moved, the content is compared (a reload back to the same
    /// settings is no reload for the batch) and `at` takes the new generation.
    fn reloaded_since(&self, at: &mut Posting) -> bool {
        if self.generation.load(Ordering::Acquire) == at.generation {
            return false;
        }
        let (now, generation) = self.current();
        at.generation = generation;
        !now.routes_as(&at.settings.settings)
    }

    /// The settings and the generation they are, read together.
    fn current(&self) -> (Arc<Prepared>, u64) {
        let settings = self.settings.read().unwrap_or_else(PoisonError::into_inner);
        (
            Arc::clone(&settings),
            self.generation.load(Ordering::Acquire),
        )
    }

    /// Whether the host admitted the target, asked once: a refusal (or no host to ask) raises
    /// BUSBAR-7070 in the host's words and disables the instance; an answer the host could not
    /// give is logged at ERROR, caches nothing and is asked again next time.
    pub fn admitted(
        &self,
        host: Option<&Host<busbar_contract::plugin::markers::ExportKind>>,
    ) -> bool {
        matches!(self.admission(host), Admission::Admitted(..))
    }

    /// The settings (and their generation) a fresh delivery runs on, when the host admitted the
    /// target; why not, when it did not. The settings are read while the verdict's lock is held
    /// (lock order live -> settings, as `refresh` takes them), so a delivery never pairs an old
    /// verdict with the settings of a reload that landed between the two reads.
    fn admission(
        &self,
        host: Option<&Host<busbar_contract::plugin::markers::ExportKind>>,
    ) -> Admission {
        let mut live = self.live.lock().unwrap_or_else(PoisonError::into_inner);
        let ok = match *live {
            Some(v) => v,
            None => {
                let verdict = host.map_or(Err(ConnFailure::Unarmed), |h| {
                    h.connector(busbar_contract::abi::mechanism::ticket::Ticket::NONE)
                        .admit(NEED)
                });
                let ok = match verdict {
                    Ok(()) => true,
                    Err(e) => {
                        let settings = self.settings();
                        let words = refusal_words(&settings.url, &e);
                        if !matches!(e, ConnFailure::Refused(_) | ConnFailure::Unarmed) {
                            tracing::error!("{words}; webhook target admission failed; the next readiness check or delivery will retry");
                            return Admission::Unsettled(e, settings);
                        }
                        tracing::error!(diag = %DISABLED, "{words}; disabling this webhook exporter");
                        false
                    }
                };
                *live = Some(ok);
                ok
            }
        };
        if !ok {
            return Admission::Disabled;
        }
        let (settings, generation) = self.current();
        Admission::Admitted(settings, generation)
    }

    /// The settings (and their generation) a fresh delivery of `batch` runs on, when the host
    /// admitted the target. A disabled instance drops the batch without a word (BUSBAR-7070 was
    /// raised once); a batch met by an admission the host could not answer is dropped with each of
    /// its lines reported as the transport failure it met (BUSBAR-7072), as a line whose exchange
    /// failed would be.
    fn admitted_for(
        &self,
        host: Option<&Host<busbar_contract::plugin::markers::ExportKind>>,
        batch: &[u8],
    ) -> Option<(Arc<Prepared>, u64)> {
        match self.admission(host) {
            Admission::Admitted(settings, generation) => Some((settings, generation)),
            Admission::Disabled => None,
            Admission::Unsettled(failure, settings) => {
                // Precompute the scrubbed text and log target once for the whole batch instead of
                // re-parsing the URL and re-running scrub for each line (the inputs are identical).
                let header_value = settings.auth_header.as_ref().map(|h| h.value.as_str());
                let target = log_target(&settings.url);
                let error_kind = scrub(&failure.to_string(), &settings.url, header_value);
                let mut from = 0;
                while let Some((_, next)) = next_line(batch, from) {
                    tracing::warn!(
                        diag = %TRANSPORT_ERROR,
                        webhook_url = ?target,
                        error_kind = %error_kind,
                        "request-log webhook delivery failed (transport error); this log was dropped"
                    );
                    from = next;
                }
                None
            }
        }
    }

    /// Whether a reload cut the batch whose rest is `rest` (the bytes after the line just done): when
    /// lines remain and the target or credentials changed, BUSBAR-7109 is raised once and the rest
    /// is dropped.
    fn cut_by_reload(&self, at: &mut Posting, rest: &[u8]) -> bool {
        if at.bindings_pinned || next_line(rest, 0).is_none() || !self.reloaded_since(at) {
            return false;
        }
        let dropped = rest
            .split(|b| *b == b'\n')
            .filter(|l| !l.is_empty())
            .count();
        tracing::warn!(
            diag = %RELOAD_CUT,
            webhook_url = ?log_target(&at.settings.url),
            dropped,
            "request-log webhook settings were reloaded during a delivery; the batch's \
             remaining log lines were dropped"
        );
        true
    }
}

/// What the host's verdict on the target leaves a fresh delivery.
enum Admission {
    /// Admitted: the settings (and their generation) the delivery runs on.
    Admitted(Arc<Prepared>, u64),
    /// Refused (BUSBAR-7070 was raised once): the instance takes no delivery until a reload.
    Disabled,
    /// The host could not answer (its failure, and the settings it was asked about); the next
    /// readiness check or delivery asks again.
    Unsettled(ConnFailure, Arc<Prepared>),
}

/// The next non-empty line of `batch` at or after byte `from`, and the byte offset just past it.
fn next_line(batch: &[u8], from: usize) -> Option<(&[u8], usize)> {
    let mut start = from;
    while start < batch.len() {
        let end = batch[start..]
            .iter()
            .position(|b| *b == b'\n')
            .map_or(batch.len(), |i| start + i);
        if end > start {
            return Some((&batch[start..end], end + 1));
        }
        start = end + 1;
    }
    None
}

/// The settings of one opened instance with the request every line of theirs is POSTed as, built
/// once: compact JSON to the target's path and query, under the instance's deadline, with the
/// fields in this order: the `authorization: Basic …` the URL's userinfo became
/// ([`basic_authorization`]), then `content-type: application/json`, then the auth header — each
/// appended as an `http::HeaderMap` appends, so a configured auth header named `Authorization` is
/// sent too, after the userinfo's. The configured name goes lower-cased (the contract's field block
/// is lower-case).
pub(crate) struct Prepared {
    settings: Settings,
    target: Vec<u8>,
    /// The fields that carry no credential, in order (`content-type`).
    plain: Vec<(Vec<u8>, Vec<u8>)>,
    /// The fields that do (the `authorization` the userinfo became, the auth header): each goes in
    /// before the plain field `at` (their count: last), sealed, so the SDK frames and wipes the
    /// value and a formatted request shows `<sealed>`.
    sealed: Vec<(usize, Vec<u8>, Cred)>,
}

impl Drop for Prepared {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.target);
    }
}

/// `Debug` prints the settings through the sink's own redaction: the url as the logs name it
/// ([`log_target`]), the auth header by name only, the fields by name only, and the target path
/// and query as `***` unless it is the root.
impl std::fmt::Debug for Prepared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names: Vec<std::borrow::Cow<'_, str>> = self
            .plain
            .iter()
            .map(|(n, _)| n)
            .chain(self.sealed.iter().map(|(_, n, _)| n))
            .map(|n| String::from_utf8_lossy(n))
            .collect();
        let header = self.settings.auth_header.as_ref().map(|h| (&h.name, "***"));
        f.debug_struct("Prepared")
            .field("url", &log_target(&self.settings.url))
            .field("auth_header", &header)
            .field(
                "max_inflight_deliveries",
                &self.settings.max_inflight_deliveries,
            )
            .field(
                "delivery_timeout_secs",
                &self.settings.delivery_timeout_secs,
            )
            .field("target", &if self.target == b"/" { "/" } else { "***" })
            .field("fields", &names)
            .finish()
    }
}

impl Deref for Prepared {
    type Target = Settings;
    fn deref(&self) -> &Settings {
        &self.settings
    }
}

impl Prepared {
    fn new(settings: Settings) -> Self {
        let mut fields: Vec<(Vec<u8>, Field)> = Vec::new();
        if let Some(basic) = basic_authorization(&settings.url) {
            append(
                &mut fields,
                b"authorization",
                Field::Secret(cred(basic, &settings.url)),
            );
        }
        append(
            &mut fields,
            b"content-type",
            Field::Plain(b"application/json".to_vec()),
        );
        if let Some(h) = settings.auth_header.as_ref().filter(|h| header_builds(h)) {
            append(
                &mut fields,
                h.name.to_ascii_lowercase().as_bytes(),
                Field::Secret(cred(h.value.to_string(), &settings.url)),
            );
        }
        let (mut plain, mut sealed) = (Vec::new(), Vec::new());
        for (name, field) in fields {
            match field {
                Field::Plain(v) => plain.push((name, v)),
                Field::Secret(c) => sealed.push((plain.len(), name, c)),
            }
        }
        let target = match parsed_url(&settings.url) {
            Ok(u) => match u.query() {
                Some(q) => format!("{}?{q}", u.path()),
                None => u.path().to_string(),
            },
            Err(_) => "/".to_string(),
        }
        .into_bytes();
        Self {
            settings,
            target,
            plain,
            sealed,
        }
    }

    /// The request that POSTs `line` and the sealed fields it carries beside it
    /// ([`Exchange::request_sealed`]).
    fn parts(&self, line: &[u8]) -> (Request, Vec<SealedField>) {
        let request = Request {
            method: b"POST".to_vec(),
            target: self.target.clone(),
            fields: self.plain.clone(),
            body: line.to_vec(),
            timeout_ms: self.deadline_ms(),
        };
        let sealed = self
            .sealed
            .iter()
            .map(|(at, name, c)| (*at, name.clone(), c.field()))
            .collect();
        (request, sealed)
    }

    /// The per-delivery deadline in milliseconds: it bounds the whole exchange of one line, from
    /// before its connection is established through its reply head, as 1.5.5's client timeout did.
    fn deadline_ms(&self) -> u64 {
        self.settings.delivery_timeout_secs.saturating_mul(1000)
    }

    /// Whether `other` sends lines where these do and with the same credentials: the url and the
    /// auth header, not the deadline or the in-flight bound.
    fn routes_as(&self, other: &Settings) -> bool {
        self.settings.url == other.url && self.settings.auth_header == other.auth_header
    }
}

/// One request field before it is split into plain and sealed.
enum Field {
    Plain(Vec<u8>),
    Secret(Cred),
}

/// A credential-bearing field value held as a `Cred` for the target `url` (it has no getter, no
/// `Debug`; the string it was made from is wiped). It may cross only a secure stream unless the url
/// parses as `http`.
fn cred(value: String, url: &str) -> Cred {
    let mut v = serde_json::Value::String(value);
    // `take` answers `None` only for a value that is not a string, which `v` always is.
    Cred::take(&mut v)
        .unwrap_or_else(Cred::empty)
        .require_secure_if(!parsed_url(url).is_ok_and(|u| u.scheme() == "http"))
}

/// Whether the auth header can be sent: it is an HTTP header ([`header_is_http`]) and not one of
/// the framing or connection fields ([`is_framing`]).
fn header_builds(h: &ExportAuthHeader) -> bool {
    header_is_http(h) && !is_framing(&h.name)
}

/// Whether `name` is one of the framing or connection fields, which the sink's own request states
/// itself (the http framer) and a configured one could use to desync the exchange (names compared
/// without case).
fn is_framing(name: &str) -> bool {
    const OWNED: [&str; 9] = [
        "content-length",
        "transfer-encoding",
        "host",
        "connection",
        "te",
        "upgrade",
        "trailer",
        "keep-alive",
        "proxy-connection",
    ];
    OWNED.iter().any(|n| name.eq_ignore_ascii_case(n))
}

/// The truth about a framing or connection field named as the auth header: the name is a valid
/// header, but the http framer states these fields itself and 1.6.0 does not send one.
fn framing_words(name: &str) -> String {
    format!(
        "settings.auth_header.name `{name}` is a framing/connection field the http framer states \
         itself; 1.6.0 does not send it"
    )
}

/// Whether the auth header is a header 1.5.5 could build: `HeaderName::from_bytes` takes a name of 1
/// to 65535 RFC 9110 token bytes, and `HeaderValue::from_str` a value of visible ASCII, space, tab
/// and non-ASCII bytes (no other control byte, no DEL). 1.5.5 left a header that fails either out
/// and POSTed the line without it; 1.6.0 refuses one at `open`/`refresh` and `check`s it.
fn header_is_http(h: &ExportAuthHeader) -> bool {
    let token = |b: &u8| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(b);
    let name = h.name.as_bytes();
    (1..=usize::from(u16::MAX)).contains(&name.len())
        && name.iter().all(token)
        && h.value
            .bytes()
            .all(|b| b == b'\t' || (b >= 0x20 && b != 0x7f))
}

/// One field appended as an `http::HeaderMap` appends it: after the last field of the same name
/// (names compared without case), or last when there is none.
fn append(fields: &mut Vec<(Vec<u8>, Field)>, name: &[u8], value: Field) {
    let field = (name.to_vec(), value);
    match fields
        .iter()
        .rposition(|(n, _)| n.eq_ignore_ascii_case(name))
    {
        Some(i) => fields.insert(i + 1, field),
        None => fields.push(field),
    }
}

/// The `authorization` value a target URL's userinfo becomes, `None` when it carries none. The
/// parsed URL's username and password are each percent-decoded and kept only when that is UTF-8 (a
/// username that is not leaves no field at all; a password that is not is left out), and, when
/// either is set, the value is `Basic ` and the padded standard base64 of `{username}:` followed by
/// the password, if any. The host's connector drops the userinfo from the target the `url` setting
/// gives the need. The decoding and the encoding are the SDK's (`sdk::url::basic_authorization`,
/// read as [`Userinfo::Utf8`], reqwest 0.12's reading for 1.5.5); the parse is this plugin's own.
pub(crate) fn basic_authorization(url: &str) -> Option<String> {
    let u = parsed_url(url).ok()?;
    if !u.has_authority() {
        return None;
    }
    let basic = sdk_url::basic_authorization(u.username(), u.password(), Userinfo::Utf8);
    if let Some(value) = &basic {
        wipe_probe::watch("Basic value", value.as_bytes());
    }
    basic
}

/// Name the current setting and preserve the host's reason for refusing its target. The
/// instance's log context identifies the exporter; its URL and the host's text are scrubbed so
/// credentials never cross into the diagnostic. A generic refusal is not evidence of an SSRF
/// violation, a malformed URL, or a particular scheme violation.
pub(crate) fn refusal_words(url: &str, refused: &ConnFailure) -> String {
    format!(
        "settings.url '{}': {}",
        log_target(url),
        scrub(&refused.to_string(), url, None)
    )
}

/// What became of one line: nothing to say for a 2xx; BUSBAR-7071 for any other status,
/// BUSBAR-7072 for a transport failure — each at WARN. The target is named as [`log_target`] names
/// it: scheme, a masked userinfo marker, host and port, a path other than `/` shown as `/***` and
/// a query as `?***` (the userinfo, path and query can each carry the webhook's secret); the host's
/// failure text is scrubbed of the target's parts ([`scrub`]).
pub(crate) fn report(
    url: &str,
    header_value: Option<&str>,
    answered: Result<ExchangeResponse, ConnFailure>,
) {
    match answered {
        Ok(r) if (200..300).contains(&r.status) => {}
        Ok(r) => tracing::warn!(
            diag = %NON_2XX,
            webhook_url = ?log_target(url),
            status = %r.status,
            "request-log webhook delivery returned a non-2xx status; this log was dropped"
        ),
        Err(e) => tracing::warn!(
            diag = %TRANSPORT_ERROR,
            webhook_url = ?log_target(url),
            error_kind = %scrub(&e.to_string(), url, header_value),
            "request-log webhook delivery failed (transport error); this log was dropped"
        ),
    }
}

fn check_values<'a>(
    phase: CheckPhase,
    instances: impl Iterator<Item = (&'a str, &'a serde_json::Value)>,
) -> Vec<String> {
    let mut errors = Vec::new();
    let parsed: Vec<(usize, &str, Settings)> = instances
        .enumerate()
        .filter_map(|(i, (name, s))| match serde::Deserialize::deserialize(s) {
            Ok(settings) => Some((i, name, settings)),
            Err(e) => {
                errors.push(format!(
                    "export.{name}: settings could not be parsed (#{i}): {e}"
                ));
                None
            }
        })
        .collect();
    match phase {
        CheckPhase::Instances => instance_checks(&parsed, &mut errors),
        CheckPhase::Limits => limit_checks(&parsed, &mut errors),
    }
    errors
}

/// Each instance's in-flight bound, held to 1..=[`MAX_PERMITS`].
fn limit_checks(parsed: &[(usize, &str, Settings)], errors: &mut Vec<String>) {
    for (_, name, settings) in parsed {
        let bound = settings.max_inflight_deliveries;
        if bound < 1 {
            errors.push(format!(
                "export.{name}: settings.max_inflight_deliveries must be >= 1"
            ));
        }
        if bound > MAX_PERMITS {
            errors.push(format!(
                "export.{name}: settings.max_inflight_deliveries must be <= {MAX_PERMITS}"
            ));
        }
    }
}

/// Each instance's auth header and delivery deadline, numbered by configured position.
fn instance_checks(parsed: &[(usize, &str, Settings)], errors: &mut Vec<String>) {
    for (i, name, w) in parsed {
        if let Some(h) = w.auth_header.as_ref().filter(|h| is_framing(&h.name)) {
            errors.push(format!(
                "export.{name}: the `module: request-log-webhook` export instance targeting '{}' (#{i}): {} — \
                 remove the header",
                log_target(&w.url),
                framing_words(&h.name)
            ));
        } else if w.auth_header.as_ref().is_some_and(|h| !header_builds(h)) {
            // The name is not shown: one that is not a token is most often a whole header line
            // (`Authorization: Bearer <token>`) pasted into it, credential and all.
            errors.push(format!(
                "export.{name}: the `module: request-log-webhook` export instance targeting '{}' (#{i}) sets \
                 settings.auth_header with a name or value that is not a valid HTTP header \
                 (the name must be a non-empty RFC 9110 token, and the value may hold \
                 no control byte other than tab); 1.5.5 left such a header out and sent the log \
                 without it — fix or remove the header",
                log_target(&w.url)
            ));
        }
        if w.delivery_timeout_secs > MAX_DURATION_SECS {
            errors.push(format!(
                "export.{name}: the `module: request-log-webhook` export instance targeting '{}' (#{i}) sets \
                 settings.delivery_timeout_secs: {}, above the {MAX_DURATION_SECS}-second (30-year) \
                 ceiling every duration is bounded by — a delivery deadline that far out overflows \
                 the clock",
                log_target(&w.url),
                w.delivery_timeout_secs
            ));
        }
        if w.delivery_timeout_secs < 1 {
            errors.push(format!(
                "export.{name}: the `module: request-log-webhook` export instance targeting '{}' (#{i}) sets \
                 settings.delivery_timeout_secs: 0 — it must be \
                 >= 1",
                log_target(&w.url)
            ));
        }
    }
}

/// The migration's report line when it removes an `auth_header` 1.6.0 refuses.
pub(crate) const REMOVED_AUTH_HEADER: &str =
    "removed settings.auth_header: 1.6.0 does not send it, as it \
     cannot be sent as an HTTP header (its name or value is not a valid HTTP header), which 1.6.0 \
     refuses at validation and open";

/// The migration's report line when it removes an `auth_header` named for a framing or connection
/// field, which the http framer states itself ([`framing_words`]).
pub(crate) fn removed_framing_header(name: &str) -> String {
    format!(
        "removed {}, which 1.6.0 refuses at validation and open",
        framing_words(name)
    )
}

/// The migration receipt for making a historical zero limit's effective value explicit.
pub(crate) const MIGRATED_ZERO_INFLIGHT: &str =
    "changed settings.max_inflight_deliveries: 0 -> 1 (preserves the historical effective per-instance limit)";

/// Migrates webhook settings once, before validation: make the effective zero limit explicit and
/// remove an auth header that validation refuses. This entry is not part of the serving runtime.
pub(crate) struct Migration;

impl Migrate for Migration {
    type Kind = busbar_contract::plugin::markers::ExportKind;
    fn migrate(mut settings: serde_json::Value, _: &str) -> Migrated {
        let mut report = Vec::new();
        if let Some(bound) = settings
            .get_mut("max_inflight_deliveries")
            .filter(|bound| bound.as_u64() == Some(0))
        {
            *bound = serde_json::Value::from(1);
            report.push(MIGRATED_ZERO_INFLIGHT.to_string());
        }
        if auth_header_unbuildable(&settings) {
            let framing = settings
                .pointer("/auth_header/name")
                .or_else(|| settings.pointer("/auth_header/0"))
                .and_then(serde_json::Value::as_str)
                .filter(|n| is_framing(n))
                .map(removed_framing_header);
            let removed = settings
                .as_object_mut()
                .and_then(|section| section.remove("auth_header"));
            if let Some(value) = removed {
                wipe_probe::watch_value("removed migration header", &value);
                drop(SettingsValue::from(value));
                report.push(framing.unwrap_or_else(|| REMOVED_AUTH_HEADER.to_string()));
            }
        }
        Migrated {
            settings,
            report,
            needs: Vec::new(),
        }
    }
}

/// Whether `settings` are refused at validation for their auth header ([`instance_checks`]), a
/// referenced value read as one that builds.
fn auth_header_unbuildable(settings: &serde_json::Value) -> bool {
    let mut probe = SettingsValue::from(settings.clone());
    wipe_probe::watch_value("migration probe JSON", &probe);
    // The section as written: a reference (`{env:}`, `{file:}`, `{module:}`) in either declared
    // reference-capable field is not resolved yet, so it stands in as text for the probe.
    for field in ["/url", "/auth_header/value"] {
        if let Some(value) = probe.pointer_mut(field).filter(|v| v.is_object()) {
            *value = {
                let old = std::mem::replace(value, serde_json::Value::Null);
                drop(SettingsValue::from(old));
                serde_json::Value::String(String::new())
            };
        }
    }
    <Settings as serde::Deserialize>::deserialize(&*probe)
        .is_ok_and(|s| s.auth_header.as_ref().is_some_and(|h| !header_builds(h)))
}

/// `check`'s instances, `(name, settings)` in configuration order (settings that are not JSON read
/// as `null`, which no check parses), through the SDK's safe lend.
fn instances(input: Lent<'_, CheckIn>) -> Vec<(String, SettingsValue)> {
    input
        .instances()
        .iter()
        .map(|c| {
            let settings = SettingsValue::from(
                serde_json::from_slice(c.field(|c| &c.settings).bytes())
                    .unwrap_or(serde_json::Value::Null),
            );
            wipe_probe::watch_value("check settings JSON", &settings);
            (
                String::from_utf8_lossy(c.field(|c| &c.name).bytes()).into_owned(),
                settings,
            )
        })
        .collect()
}

/// The instance state every slot reads.
type State = Held<Webhook>;

/// The error texts of the door's REFUSED answers: one per cause, so the host's line names why
/// instead of a bare outcome.
pub(crate) const NO_INSTANCE: &str = "no opened request-log-webhook instance";
/// `check` at a phase this sink does not know.
pub(crate) const UNKNOWN_PHASE: &str = "not a check phase this sink knows (limits or instances)";

/// A parked delivery keeps its admitted settings, binding capability and parked exchange (which
/// closes its own host connection when the host gives the delivery up and the SDK drops it).
struct Posting {
    settings: Arc<Prepared>,
    generation: u64,
    offset: usize,
    issued: u32,
    exchange: Option<Exchange>,
    /// Captured at admission, never upgraded on resume: an old host can finish the already-open
    /// exchange of a batch it did not pin, but that batch stays one a reload cuts
    /// ([`Webhook::cut_by_reload`]); a pinned batch finishes on the bindings it started under.
    bindings_pinned: bool,
}

/// `deliver`: each line of the batch POSTed in order, one exchange after another; fire-and-forget,
/// so READY whatever became of the lines, PENDING while an exchange runs.
pub(crate) struct Deliver;

impl SafeSlot for Deliver {
    type Kind = busbar_contract::plugin::markers::ExportKind;
    type In = DeliverIn;
    type Out = OutHead;
    type State = State;
    fn call(
        instance: Instance<'_, State, busbar_contract::plugin::markers::ExportKind>,
        input: Lent<'_, DeliverIn>,
        mut out: Out<'_, OutHead>,
    ) -> Outcome {
        let Some(h) = instance.get() else {
            return out.fail(Refusal::refused(NO_INSTANCE));
        };
        let hook = h.life();

        let batch = input.field(|i| &i.batch).bytes();
        let parked = instance.resume::<Posting>().map(|p| *p);
        let mut at = match parked {
            Some(p) => p,
            None => {
                let Some((settings, generation)) = hook.admitted_for(h.host(), batch) else {
                    return Outcome::Ready;
                };
                Posting {
                    settings,
                    generation,
                    offset: 0,
                    issued: 0,
                    exchange: None,
                    bindings_pinned: pinned_ticket_bindings(
                        input.field(|i| &i.head.extensions).bytes(),
                    ),
                }
            }
        };
        while let Some((line, next)) = next_line(batch, at.offset) {
            let answered = match h.host() {
                None => Err(ConnFailure::Unarmed),
                Some(host) => {
                    let mut c = host.connector_from(instance.ticket(), at.issued);
                    let started = match at.exchange.take() {
                        Some(ex) => Ok(ex),
                        None => {
                            let (request, sealed) = at.settings.parts(line);
                            Exchange::request_sealed(request, sealed)
                                .map(|ex| ex.head_only().with_timeout_ms(at.settings.deadline_ms()))
                        }
                    };
                    match started {
                        Err(e) => Err(e),
                        Ok(mut ex) => match exchange(&mut c, &mut ex, NEED, None) {
                            Poll::Pending => {
                                // A parked exchange the host gives up (a cancel, or a fresh entry on
                                // the ticket) closes its own stream as the SDK drops it.
                                if let Some(expiry) = ex.wake_at_ns() {
                                    out.wake_at(expiry);
                                }
                                at.exchange = Some(ex);
                                instance.park(at);
                                return Outcome::Pending;
                            }
                            Poll::Ready(r) => {
                                at.issued = c.issued();
                                r
                            }
                        },
                    }
                }
            };
            report(
                &at.settings.url,
                at.settings.auth_header.as_ref().map(|h| h.value.as_str()),
                answered,
            );
            at.offset = next;
            if hook.cut_by_reload(&mut at, &batch[next.min(batch.len())..]) {
                break;
            }
        }
        Outcome::Ready
    }
}

/// `check`: [`check`] at the phase asked, its lines as a JSON array under a lease.
pub(crate) struct Check;

impl SafeSlot for Check {
    type Kind = busbar_contract::plugin::markers::ExportKind;
    type In = CheckIn;
    type Out = CheckOut;
    type State = State;
    fn call(
        instance: Instance<'_, State, busbar_contract::plugin::markers::ExportKind>,
        input: Lent<'_, CheckIn>,
        mut out: Out<'_, CheckOut>,
    ) -> Outcome {
        let Some(h) = instance.get() else {
            return out.fail(Refusal::refused(NO_INSTANCE));
        };
        let phase = match input.phase {
            CHECK_PHASE_LIMITS => CheckPhase::Limits,
            CHECK_PHASE_INSTANCES => CheckPhase::Instances,

            _ => return out.fail(Refusal::refused(UNKNOWN_PHASE)),
        };
        let instances = instances(input);
        let lines = check_values(
            phase,
            instances
                .iter()
                .map(|(name, value)| (name.as_str(), &**value)),
        );
        if !lines.is_empty() {
            let json = serde_json::to_vec(&lines).unwrap_or_default();
            out.lease(|o| &o.findings, h.leases(), json, BLOB_JSON);
        }
        Outcome::Ready
    }
}

mod table {
    use super::{Check, Deliver, Safe, Webhook};
    use busbar_contract::abi::sdk::export::{NoScrape, NoServe, Quiet};

    busbar_contract::plugin_door! {
        ops: busbar_contract::abi::export::Ops,
        statement: super::STATEMENT,
        lifecycle: life(Webhook, ready),
        migrate: busbar_contract::abi::sdk::migrate::Migrator<super::Migration>,
        kind_ops: {
            deliver: Safe<Deliver>, scrape: Safe<NoScrape<Webhook>>, status: Safe<Quiet<Webhook>>,
            check: Safe<Check>, serve: Safe<NoServe<Webhook>>,
        },
    }
}

/// This plugin's door: the one a compiled-in build links and the dropped-in image exports.
pub use table::{door, MACRO_DOOR};

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/audit_reconciliation.rs"]
mod audit_reconciliation;
