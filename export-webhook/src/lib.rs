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
//! `content-type: application/json`, the instance's optional `auth_header` (left out when it is not
//! a header that can be built), and the `authorization: Basic …` a userinfo in the URL becomes, to
//! the instance's `https://` target — through the HOST's connector: the Statement declares ONE outbound
//! need whose target is the `url` setting (the host drops its userinfo), under the open-web egress
//! class (public destinations over a secure connection only), and the request rides the SDK's
//! framed `exchange` under the instance's `delivery_timeout_secs`. The sink never dials. A delivery
//! is fire-and-forget and never retried: a non-2xx answer or a transport failure drops that one line
//! and raises BUSBAR-7071 / BUSBAR-7072 at WARN.
//!
//! **Admission.** The door states `ready`, so the host's verdict on the target (the need's admission
//! at bind) is asked at boot, before the instance serves; a refused target raises BUSBAR-7070
//! (`…; disabling this webhook exporter`) once and the instance takes no delivery until a reload —
//! its siblings keep delivering.
//!
//! **Settings** are checked in two phases: their SHAPE while the configuration is resolved
//! (`validate`), and the delivery deadline and in-flight bound while it is validated (`check`,
//! after the limits). Every line the sink raises is logged with the catalogue's `diag` banner
//! field; the door's call capture carries it to the instance's plugin log.
//!
//! No `unsafe`: `check`'s instance list is read through the SDK's safe lend (`instances()`).

#![forbid(unsafe_code)]

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
use busbar_contract::abi::sdk::door::{abi_str, alias, statement};
use busbar_contract::abi::sdk::exchange::{exchange, Exchange, ExchangeResponse, Request};
use busbar_contract::abi::sdk::export::tail;
pub use busbar_contract::abi::sdk::export::{NO_EXPOSITION, NO_ROUTE};
use busbar_contract::abi::sdk::life::{settings_value, Held, Life, Refreshed, Refusal};
use busbar_contract::abi::sdk::mask::mask_url;
use busbar_contract::abi::sdk::migrate::{Migrate, Migrated};
use busbar_contract::abi::sdk::url::{self as sdk_url, Userinfo};
use busbar_contract::abi::sdk::{Instance, Lent, Out, Safe, SafeSlot};
use zeroize::Zeroizing;

/// The plugin's canonical name.
pub const NAME: &str = "busbar-export-webhook";
/// The module name an `export:` instance names it by.
pub const ALIAS: &str = "request-log-webhook";
/// The manifest `declares` section (`--declares-file` for the signed tarball).
pub const DECLARES: &str = include_str!("../declares.json");

/// The in-flight ceiling `check` holds the largest instance's bound to
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

/// The config path the target comes from: the `url` setting (`settings.<key>`, the path the host's
/// connection-table fill resolves). A bare key resolves to nothing, and the host's
/// connector refuses a need whose target resolved to nothing.
const TARGET_FROM: &str = "settings.url";

/// The in-flight ceiling this sink declares: no bound of its own. The bound is the operator's
/// `max_inflight_deliveries` (64 when unset), which the host applies per instance, clamped to at
/// least one; `check` refuses the LARGEST instance's bound past [`MAX_PERMITS`] or below 1
/// ([`check`]).
const MAX_INFLIGHT: u32 = u32::MAX;
/// The one need's index in the Statement.
const NEED: u32 = 0;

mod config;
mod redact;
use config::DEFAULT_MAX_INFLIGHT;
pub use config::{ExportAuthHeader, WebhookSettings};
pub use redact::{log_target, scrub};

/// This sink's settings (the configuration's `WebhookSettings`).
pub type Settings = WebhookSettings;

const NONE: AbiStr = AbiStr {
    ptr: std::ptr::null(),
    len: 0,
};

/// The one need: outbound over a secure connection to the `url` setting's target, public
/// destinations only (refusing loopback, link-local, private, CGNAT and cloud-metadata targets). It is framed by the `http` transport — the scheme its claim names; an
/// `https://` target is secured by the host's connector, and the open-web egress class refuses any
/// target that is not secure before a byte leaves.
const NEEDS: &[Need] = &[Need {
    direction: DIRECTION_OUTBOUND,
    egress_class: EGRESS_OPEN_WEB,
    transport: abi_str("http"),
    auth: NONE,
    target_from: abi_str(TARGET_FROM),
    trust_from: NONE,
    details: Blob::ABSENT,
    keep_response_headers: std::ptr::null(),
    keep_response_headers_len: 0,
    timeout_ms: 0,
    // The receiver's response head is not read: the named (empty) list, nothing denied beyond it.
    keep_mode: busbar_contract::abi::host::conn::connector::KEEP_NAMED,
    _reserved: 0,
    deny_response_headers: std::ptr::null(),
    deny_response_headers_len: 0,
}];

/// The streams this sink carries: the request log.
const STREAMS: &[u8] = &[ExportStream::Logs as u8];

/// The export kind's Statement tail: `logs`, and no route (a push-only sink).
const TAIL: Tail = tail(STREAMS, &[]);

/// The module name an operator writes, as the alias the registry holds beside [`NAME`].
const REWRITES: &[Rewrite] = &[alias(ALIAS)];

/// The settings field that is SECRET, declared so the kernel resolves a `{env:}`/`{file:}`/
/// `{module:}` reference written there and refuses a literal: `auth_header.value`, the header's
/// value is the credential. The export host lends nothing; the sink receives the resolved string.
const SECRET_REFS: &[AbiStr] = &[abi_str("auth_header.value")];

// THE REFERENCE-CAPABLE, NOT-SECRET SETTINGS FIELDS (busbar lead ruling item 7a), stated in the
// Statement's extensions under the contract's `EXT_REFERENCE_FIELDS` key: a `{env:}`/`{file:}`/
// `{module:}` reference written at `url` is resolved by the kernel IN PLACE to its string (a 1.5.5
// config's `url: {env: VAR}` keeps booting), and a literal url passes as written (never refused
// as a secret literal). The value is not a secret: it is never lent.
busbar_contract::statement_extensions!(EXTENSIONS: [
    (busbar_contract::abi::mechanism::extensions::EXT_REFERENCE_FIELDS, br#"["url"]"#),
]);

/// This plugin's Statement: its name, version, its in-flight ceiling, alias, stream and need.
pub const STATEMENT: Statement = Statement {
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
    let value = settings_value(settings)?;
    // serde's shape refusal quotes the offending value (`invalid type: string "Bearer …"`): the
    // settings' credential strings are cut from it, the words otherwise serde's (H2).
    let credentials = redact::settings_credentials(&value);
    let settings: Settings = serde_json::from_value(value).map_err(|e| {
        Refusal::failed(sdk_url::scrub(&format!("settings: {e}"), credentials, true))
    })?;
    if let Some(refusal) = ambiguous_url(&settings.url) {
        return Err(Refusal::failed(refusal));
    }
    Ok(settings)
}

/// The settings an instance runs on: [`parse`]d, and an `auth_header` that cannot be sent is
/// refused (lead-signed): the instance would otherwise POST every line unauthenticated. The value is
/// never echoed.
fn parse_to_run(settings: &[u8]) -> Result<Settings, Refusal> {
    let parsed = parse(settings)?;
    if parsed
        .auth_header
        .as_ref()
        .is_some_and(|h| !header_builds(h))
    {
        return Err(Refusal::failed(
            "settings: `auth_header` cannot be sent as an HTTP header",
        ));
    }
    Ok(parsed)
}

/// The ambiguous-URL refusal: `Some(the refusal)` when `url` parses but
/// carries an `@` after its host — `https://tok/en@siem.example/…` or `https://u:123/x@siem.example/…`,
/// a credential holding an unescaped `/`, `?` or `#`, which a URL parser reads as host `tok` (or
/// `u`, port `123`) and a path, so the credential would be dialled as a host and written into
/// lines. The refusal shows the url with everything between `://` and its last `@` cut, never the
/// credential. A url that does not parse, or has no `@` after its host, is not ambiguous here.
/// The words and the cut are the SDK's (`sdk::url::ambiguous_url`); the parse is this plugin's own
/// WHATWG reader, the one its target is dialled by.
pub fn ambiguous_url(url: &str) -> Option<String> {
    let parsed = url::Url::parse(url).ok()?;
    sdk_url::ambiguous_url(url, &parsed[url::Position::BeforePath..])
}

/// One opened instance.
pub struct Webhook {
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

/// `Debug` names the settings through [`Prepared`]'s redacting `Debug`, and the counters; the
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
    const CANCEL: u32 = export::cancel::ABORTED;

    /// The settings' shape, in the configuration grammar's own serde words.
    fn validate(settings: &[u8]) -> Result<(), Refusal> {
        parse(settings).map(|_| ())
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
    /// at boot. It never refuses the boot: the instance is disabled and its siblings serve. Settings that did not parse are the
    /// configuration's refusal, not this one's.
    fn ready(
        &self,
        host: &Host,
        _: busbar_contract::abi::mechanism::ticket::Ticket,
    ) -> Poll<Result<(), Refusal>> {
        let _ = self.admitted(Some(host));
        Poll::Ready(Ok(()))
    }

    /// A reload's settings replace the instance's, and its target is asked about afresh; settings
    /// that do not parse are refused and the old ones (and their verdict) stay.
    fn refresh(&self, settings: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
        let parsed = parse_to_run(settings)?;
        // Hold the verdict across the settings write (lock order live -> settings, as `admitted`),
        // so no delivery reads the new settings beside the old target's cached verdict.
        let mut live = self.live.lock().unwrap_or_else(PoisonError::into_inner);
        let mut current = self
            .settings
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        // Settings equal to the held ones are no reload for a delivery in flight.
        if current.settings != parsed {
            *current = Arc::new(Prepared::new(parsed));
            self.generation.fetch_add(1, Ordering::Release);
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

    /// Whether the settings now differ in content from those `at` started under. The generation
    /// is the fast path; when it moved, the content is compared (a reload back to the same
    /// settings is no reload for the batch) and `at` takes the new generation.
    fn reloaded_since(&self, at: &mut Posting) -> bool {
        if self.generation.load(Ordering::Acquire) == at.generation {
            return false;
        }
        let (now, generation) = self.current();
        at.generation = generation;
        now.settings != at.settings.settings
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
    /// BUSBAR-7070 in the host's words and disables the instance.
    pub fn admitted(&self, host: Option<&Host>) -> bool {
        let mut live = self.live.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(v) = *live {
            return v;
        }
        let verdict = host.map_or(Err(ConnFailure::Unarmed), |h| {
            h.connector(busbar_contract::abi::mechanism::ticket::Ticket::NONE)
                .admit(NEED)
        });
        let ok = match verdict {
            Ok(()) => true,
            Err(e) => {
                let words = refusal_words(Some(&self.settings().url), &e);
                tracing::error!(diag = %DISABLED, "{words}; disabling this webhook exporter");
                false
            }
        };
        *live = Some(ok);
        ok
    }
}

/// The settings of one opened instance with the request every line of theirs is POSTed as, built
/// once: compact JSON to the target's path and query, under the instance's deadline, with the
/// fields in this order: the `authorization: Basic …` the URL's userinfo became
/// ([`basic_authorization`]), then `content-type: application/json`, then the auth header — each
/// appended as an `http::HeaderMap` appends, so a configured auth header named `Authorization` is
/// sent too, after the userinfo's. The configured name goes lower-cased (the contract's field block
/// is lower-case).
pub struct Prepared {
    settings: Settings,
    target: Vec<u8>,
    /// Name and value of each field; the values can hold a credential and are wiped when dropped.
    fields: Vec<(Vec<u8>, Zeroizing<Vec<u8>>)>,
}

/// `Debug` prints the settings through the sink's own redaction: the url as the logs name it
/// ([`log_target`]), the auth header by name only, the fields by name only, and the target path
/// and query as `***` unless it is the root.
impl std::fmt::Debug for Prepared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names: Vec<std::borrow::Cow<'_, str>> = self
            .fields
            .iter()
            .map(|(n, _)| String::from_utf8_lossy(n))
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
        let mut fields = Vec::new();
        if let Some(basic) = basic_authorization(&settings.url) {
            append(&mut fields, b"authorization", Zeroizing::new(basic));
        }
        append(
            &mut fields,
            b"content-type",
            Zeroizing::new(b"application/json".to_vec()),
        );
        if let Some(h) = settings.auth_header.as_ref().filter(|h| header_builds(h)) {
            append(
                &mut fields,
                h.name.to_ascii_lowercase().as_bytes(),
                Zeroizing::new(h.value.as_bytes().to_vec()),
            );
        }
        let target = match url::Url::parse(&settings.url) {
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
            fields,
        }
    }

    /// The request that POSTs `line`.
    pub fn request(&self, line: &[u8]) -> Request {
        Request {
            method: b"POST".to_vec(),
            target: self.target.clone(),
            fields: self
                .fields
                .iter()
                .map(|(n, v)| (n.clone(), v.to_vec()))
                .collect(),
            body: line.to_vec(),
            timeout_ms: self.settings.delivery_timeout_secs.saturating_mul(1000),
        }
    }
}

/// Whether the auth header can be sent: it is an HTTP header ([`header_is_http`]) and not one of
/// the framing or connection fields, which the sink's own request owns and a configured one could
/// use to desync the exchange (names compared without case).
fn header_builds(h: &ExportAuthHeader) -> bool {
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
    header_is_http(h) && !OWNED.iter().any(|n| h.name.eq_ignore_ascii_case(n))
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
fn append(fields: &mut Vec<(Vec<u8>, Zeroizing<Vec<u8>>)>, name: &[u8], value: Zeroizing<Vec<u8>>) {
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
pub fn basic_authorization(url: &str) -> Option<Vec<u8>> {
    let u = url::Url::parse(url).ok()?;
    if !u.has_authority() {
        return None;
    }
    sdk_url::basic_authorization(u.username(), u.password(), Userinfo::Utf8).map(String::into_bytes)
}

/// The standard base64 alphabet, padded: the `base64` crate's `STANDARD` engine, the encoding
/// `sdk::url::basic_authorization` writes; kept for the tests' RFC 4648 vectors.
#[cfg(test)]
fn base64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// BUSBAR-7070's words for a refused target: a target that is not an `https://`
/// URL is the scheme rule (the scheme read without case); one that does not parse is an invalid
/// URL; a parseable `https://` target the host refused is the destination guard, the only rule
/// left on that path. Userinfo is masked. A host that gave no verdict, or any
/// failure that is not a refusal, is said in the host's words.
pub fn refusal_words(url: Option<&str>, refused: &ConnFailure) -> String {
    match (url, refused) {
        (Some(u), ConnFailure::Refused(_)) if !is_https(u) => format!(
            "observability.request_log_webhook_url must be an https:// URL (got '{}')",
            mask_url(u)
        ),
        (Some(u), ConnFailure::Refused(_)) => match url::Url::parse(u) {
            Err(e) => format!("observability.request_log_webhook_url is not a valid URL: {e}"),
            Ok(_) => format!(
                "observability.request_log_webhook_url must not target a loopback/link-local/\
                 private/CGNAT/cloud-metadata host (SSRF guard); got '{}'",
                mask_url(u)
            ),
        },
        (Some(u), _) => scrub(&refused.to_string(), u),
        (None, _) => refused.to_string(),
    }
}

/// `url` names the `https` scheme, read without case (RFC 3986).
fn is_https(url: &str) -> bool {
    url.split_once("://")
        .is_some_and(|(scheme, _)| scheme.eq_ignore_ascii_case("https"))
}

/// What became of one line: nothing to say for a 2xx; BUSBAR-7071 for any other status,
/// BUSBAR-7072 for a transport failure — each at WARN. The target is named by scheme and host only ([`log_target`]:
/// its userinfo, path and query can each carry the webhook's secret) and the host's failure text is
/// scrubbed of the target's parts ([`scrub`]).
pub fn report(url: &str, answered: Result<ExchangeResponse, ConnFailure>) {
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
            error_kind = %scrub(&e.to_string(), url),
            "request-log webhook delivery failed (transport error); this log was dropped"
        ),
    }
}

/// The checks the configuration's validation runs across every webhook instance: AMONG the
/// operational limits' checks ([`CheckPhase::Limits`]) the in-flight bound — one bound over the
/// instances, the largest configured (64 with none), so a generous instance is never refused for a
/// stingy sibling; AFTER them ([`CheckPhase::Instances`]) each instance's delivery deadline,
/// numbered by its position.
///
/// Only the largest instance's bound is validated (the shared bound must accommodate the most
/// permissive sink), and the host's export axis clamps each instance's bound to at least one. An
/// instance stating `0` beside a larger sibling therefore validates and runs at one permit; refusing
/// it per instance would tighten customer-visible behaviour.
pub fn check(phase: CheckPhase, instances: &[(String, serde_json::Value)]) -> Vec<String> {
    let parsed: Vec<Settings> = instances
        .iter()
        .filter_map(|(_, s)| serde_json::from_value(s.clone()).ok())
        .collect();
    let mut errors = Vec::new();
    if phase == CheckPhase::Instances {
        instance_checks(&parsed, &mut errors);
        return errors;
    }
    let bound = parsed
        .iter()
        .map(|w| w.max_inflight_deliveries)
        .max()
        .unwrap_or(DEFAULT_MAX_INFLIGHT);
    if bound < 1 {
        errors.push(
            "export.request-log-webhook.settings.max_inflight_deliveries must be >= 1 (a 0-permit \
             semaphore admits nothing, silently dropping every webhook delivery)"
                .to_string(),
        );
    }
    if bound > MAX_PERMITS {
        errors.push(format!(
            "export.request-log-webhook.settings.max_inflight_deliveries must be <= \
             {MAX_PERMITS} (tokio::sync::Semaphore's hard permit ceiling — a value above \
             it panics at build time instead of failing validation)"
        ));
    }
    errors
}

/// Each instance's delivery deadline, numbered by its position among the instances.
fn instance_checks(parsed: &[Settings], errors: &mut Vec<String>) {
    for (i, w) in parsed.iter().enumerate() {
        if let Some(h) = w.auth_header.as_ref().filter(|h| !header_builds(h)) {
            errors.push(format!(
                "the `module: request-log-webhook` export instance targeting '{}' (#{i}) sets \
                 settings.auth_header with a name or value that is not a valid HTTP header \
                 (name {:?}: the name must be a non-empty RFC 9110 token, and the value may hold \
                 no control byte other than tab); 1.5.5 left such a header out and sent the log \
                 without it — fix or remove the header",
                mask_url(&w.url),
                h.name
            ));
        }
        if w.delivery_timeout_secs > MAX_DURATION_SECS {
            errors.push(format!(
                "the `module: request-log-webhook` export instance targeting '{}' (#{i}) sets \
                 settings.delivery_timeout_secs: {}, above the {MAX_DURATION_SECS}-second (30-year) \
                 ceiling every duration is bounded by — a delivery deadline that far out overflows \
                 the clock",
                mask_url(&w.url),
                w.delivery_timeout_secs
            ));
        }
        if w.delivery_timeout_secs < 1 {
            errors.push(format!(
                "the `module: request-log-webhook` export instance targeting '{}' (#{i}) sets \
                 settings.delivery_timeout_secs: 0, which would abort every delivery — it must be \
                 >= 1",
                mask_url(&w.url)
            ));
        }
    }
}

/// The migration's report line when it removes an `auth_header` 1.5.5 could not build.
pub const REMOVED_AUTH_HEADER: &str = "removed settings.auth_header: its name or value is not a \
     valid HTTP header, which 1.6.0 refuses at validation; 1.5.5 never sent it";

/// THE 1.5.5 UPGRADE (`busbar --migrate-config`; owner ruling 2026-10-27): this sink's own
/// migration of its settings section, stated on the door as `migrate`.
///
/// 1.5.5 left an `auth_header` it could not build out of every delivery and sent the line without
/// it (export-webhook #33 W1); 1.6.0 refuses such a header at validation ([`check`]). The migration
/// removes exactly the header that refusal names, reporting [`REMOVED_AUTH_HEADER`]: settings that
/// parse as [`Settings`] and carry an `auth_header` that does not build ([`header_builds`]). A value
/// written as a reference the kernel resolves (`auth_header.value` is a declared secret field) is
/// unknown here, so only the header's name is judged. Anything else, a section the grammar refuses
/// for its shape included, is unchanged: that refusal is the operator's to read.
pub struct Migration;

impl Migrate for Migration {
    fn migrate(mut settings: serde_json::Value, _: &str) -> Migrated {
        if !auth_header_unbuildable(&settings) {
            return Migrated::unchanged(settings);
        }
        if let Some(section) = settings.as_object_mut() {
            section.remove("auth_header");
        }
        Migrated {
            settings,
            report: vec![REMOVED_AUTH_HEADER.to_string()],
            needs: Vec::new(),
        }
    }
}

/// Whether `settings` are refused at validation for their auth header ([`instance_checks`]), a
/// referenced value read as one that builds.
fn auth_header_unbuildable(settings: &serde_json::Value) -> bool {
    let mut probe = settings.clone();
    if let Some(value) = probe
        .pointer_mut("/auth_header/value")
        .filter(|v| v.is_object())
    {
        *value = serde_json::Value::String(String::new());
    }
    serde_json::from_value::<Settings>(probe)
        .is_ok_and(|s| s.auth_header.is_some_and(|h| !header_is_http(&h)))
}

/// `check`'s instances, `(name, settings)` in configuration order (settings that are not JSON read
/// as `null`, which no check parses), through the SDK's safe lend.
fn instances(input: Lent<'_, CheckIn>) -> Vec<(String, serde_json::Value)> {
    input
        .instances()
        .iter()
        .map(|c| {
            (
                String::from_utf8_lossy(c.field(|c| &c.name).bytes()).into_owned(),
                serde_json::from_slice(c.field(|c| &c.settings).bytes())
                    .unwrap_or(serde_json::Value::Null),
            )
        })
        .collect()
}

/// The instance state every slot reads.
type State = Held<Webhook>;

/// The error texts of the door's REFUSED answers: one per cause, so the host's line names why
/// instead of a bare outcome.
pub const NO_INSTANCE: &str = "no opened request-log-webhook instance";
/// `check` at a phase this sink does not know.
pub const UNKNOWN_PHASE: &str = "not a check phase this sink knows (limits or instances)";

/// What a delivery parks across PENDING: the settings it started under and their generation (a
/// reload mid-batch changes nothing for it: its lines go, and are reported, to the target it began
/// with), the line it is on, the handles issued before that line's exchange, and the exchange.
struct Posting {
    settings: Arc<Prepared>,
    generation: u64,
    line: usize,
    issued: u32,
    exchange: Option<Exchange>,
}

/// `deliver`: each line of the batch POSTed in order, one exchange after another; fire-and-forget,
/// so READY whatever became of the lines, PENDING while an exchange runs.
pub struct Deliver;

impl SafeSlot for Deliver {
    type In = DeliverIn;
    type Out = OutHead;
    type State = State;
    fn call(
        instance: Instance<'_, State>,
        input: Lent<'_, DeliverIn>,
        mut out: Out<'_, OutHead>,
    ) -> Outcome {
        let Some(h) = instance.get() else {
            return out.fail(Refusal::refused(NO_INSTANCE));
        };
        let hook = h.life();
        // A RESUMED delivery finishes its parked exchange whatever a reload changed meanwhile: it
        // is driven to its end (the host's stream closed), on the settings it started under. If a
        // reload changed the settings, the batch's remaining lines are dropped after it (below):
        // the host's pin now names the new target, and the old settings' credentials must not go
        // there, nor the new ones on an exchange this batch began elsewhere.
        let parked = instance.resume::<Posting>().map(|p| *p);
        let mut at = match parked {
            Some(p) => p,
            None => {
                if !hook.admitted(h.host()) {
                    return Outcome::Ready;
                }
                let (settings, generation) = hook.current();
                Posting {
                    settings,
                    generation,
                    line: 0,
                    issued: 0,
                    exchange: None,
                }
            }
        };
        let lines: Vec<&[u8]> = input
            .field(|i| &i.batch)
            .bytes()
            .split(|b| *b == b'\n')
            .filter(|l| !l.is_empty())
            .collect();
        while let Some(line) = lines.get(at.line) {
            let answered = match h.host() {
                None => Err(ConnFailure::Unarmed),
                Some(host) => {
                    let mut c = host.connector_from(instance.ticket(), at.issued);
                    let started = match at.exchange.take() {
                        Some(ex) => Ok(ex),
                        None => Exchange::request(at.settings.request(line)),
                    };
                    match started {
                        Err(e) => Err(e),
                        Ok(mut ex) => match exchange(&mut c, &mut ex, NEED, None) {
                            Poll::Pending => {
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
            report(&at.settings.url, answered);
            at.line += 1;
            let left = lines.len().saturating_sub(at.line);
            if left > 0 && hook.reloaded_since(&mut at) {
                tracing::warn!(
                    diag = %RELOAD_CUT,
                    webhook_url = ?log_target(&at.settings.url),
                    dropped = left,
                    "request-log webhook settings were reloaded during a delivery; the batch's \
                     remaining log lines were dropped"
                );
                break;
            }
        }
        Outcome::Ready
    }
}

/// `check`: [`check`] at the phase asked, its lines as a JSON array under a lease.
pub struct Check;

impl SafeSlot for Check {
    type In = CheckIn;
    type Out = CheckOut;
    type State = State;
    fn call(
        instance: Instance<'_, State>,
        input: Lent<'_, CheckIn>,
        mut out: Out<'_, CheckOut>,
    ) -> Outcome {
        let Some(h) = instance.get() else {
            return out.fail(Refusal::refused(NO_INSTANCE));
        };
        let phase = match input.phase {
            CHECK_PHASE_LIMITS => CheckPhase::Limits,
            CHECK_PHASE_INSTANCES => CheckPhase::Instances,
            // A phase this sink does not know is refused, never run as another.
            _ => return out.fail(Refusal::refused(UNKNOWN_PHASE)),
        };
        let lines = check(phase, &instances(input));
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
pub use table::door;

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
