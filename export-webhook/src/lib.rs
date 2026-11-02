// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **`busbar-export-webhook`** — the request-log WEBHOOK sink as a `kind: export` plugin on the

#![cfg_attr(not(test), forbid(unsafe_code))]
#![deny(unsafe_code)]

#[cfg(test)]
#[path = "tests/ownership_tests.rs"]
mod ownership_tests;
#[cfg(test)]
#[allow(unsafe_code)]
#[path = "tests/wipe_probe.rs"]
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
use busbar_contract::abi::mechanism::call::{AbiStr, OutHead, Outcome, BLOB_JSON};
use busbar_contract::abi::mechanism::door::{KindTailHead, Rewrite, Statement};
use busbar_contract::abi::sdk::conn::{ConnFailure, Host};
use busbar_contract::abi::sdk::cred::Cred;
use busbar_contract::abi::sdk::door::{abi_str, alias, statement};
use busbar_contract::abi::sdk::exchange::{
    exchange, Exchange, ExchangeResponse, Request, SealedField,
};
use busbar_contract::abi::sdk::export::tail;
pub use busbar_contract::abi::sdk::export::{NO_EXPOSITION, NO_ROUTE};
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

/// The in-flight ceiling `check` holds the largest instance's bound to

const MAX_PERMITS: usize = usize::MAX >> 3;
/// The ceiling every duration in a busbar configuration is bounded by (30 years, in seconds).
const MAX_DURATION_SECS: u64 = 30 * 365 * 86_400;

const DISABLED: &str = "BUSBAR-7070";
const NON_2XX: &str = "BUSBAR-7071";
const TRANSPORT_ERROR: &str = "BUSBAR-7072";
const RELOAD_CUT: &str = "BUSBAR-7109";

/// The host pins connector and disk bindings for the entire delivery ticket, including resumes

const TICKET_BINDINGS: &str = "busbar.export.ticket-bindings";
/// Version of the host ticket-custody capability documented by the export lifecycle.
const TICKET_BINDINGS_VERSION: &[u8] = b"1";

fn pinned_ticket_bindings(extensions: &[u8]) -> bool {
    busbar_contract::abi::mechanism::extensions::get(extensions, TICKET_BINDINGS)
        == Some(TICKET_BINDINGS_VERSION)
}

/// The config path the target comes from: the `url` setting (`settings.<key>`, the path the host's

const TARGET_FROM: &str = "settings.url";

/// The in-flight ceiling this sink declares: no bound of its own. The bound is the operator's

pub const MAX_INFLIGHT: u32 = u32::MAX;
/// The one need's index in the Statement.
pub const NEED: u32 = 0;

mod config;
fn parsed_url(text: &str) -> Result<owners::ParsedUrl, url::ParseError> {
    let parsed = owners::ParsedUrl::parse(text)?;
    #[cfg(test)]
    crate::wipe_probe::watch("parsed url", parsed.as_str().as_bytes());
    Ok(parsed)
}

mod owners;
mod redact;
use config::DEFAULT_MAX_INFLIGHT;
pub use config::{ExportAuthHeader, WebhookSettings};
pub use redact::{log_target, scrub};

/// This sink's settings (the configuration's `WebhookSettings`).
pub type Settings = WebhookSettings;

/// The one need: outbound over a secure connection to the `url` setting's target, public

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

const SECRET_REFS: &[AbiStr] = &[abi_str("auth_header.value")];

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

fn parse(settings: &[u8]) -> Result<Settings, Refusal> {
    let value = owners::SettingsValue(settings_value(settings)?);
    #[cfg(test)]
    ownership_tests::watch_settings_value(&value);

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

fn parse_to_run(settings: &[u8]) -> Result<Settings, Refusal> {
    let parsed = parse(settings)?;
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
    Ok(parsed)
}

/// The ambiguous-URL refusal: `Some(the refusal)` when `url` parses but

pub fn ambiguous_url(url: &str) -> Option<String> {
    let from_path = zeroize::Zeroizing::new(match parsed_url(url) {
        Ok(parsed) => parsed[url::Position::BeforePath..].to_string(),
        Err(_) if url.contains('@') => "@".to_string(),
        Err(_) => return None,
    });
    sdk_url::ambiguous_url(&redact::unparsed_target(url), &from_path)
}

/// One opened instance.
pub struct Webhook {
    /// Its settings and the request every line shares. `open` and `refresh` refuse settings that do
    settings: RwLock<Arc<Prepared>>,
    /// Counts the reloads that changed the settings, bumped under the `settings` write lock: a
    generation: AtomicU64,
    /// The host's verdict on the target, asked once: at boot by `ready` (and again after a
    live: Mutex<Option<bool>>,
}

/// `Debug` names the settings through [`Prepared`]'s redacting `Debug`, and the counters; the

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
        parse_to_run(settings).map(|_| ())
    }

    /// Refuses settings that do not parse, in the same words as [`Life::validate`]: an instance

    fn open(settings: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        Ok(Self {
            settings: RwLock::new(Arc::new(Prepared::new(parse_to_run(settings)?))),
            generation: AtomicU64::new(0),
            live: Mutex::new(None),
        })
    }

    /// Discovery at boot (the mechanism's `ready`, awaited after `open` before the instance serves):

    fn ready(
        &self,
        host: &Host,
        _: busbar_contract::abi::mechanism::ticket::Ticket,
    ) -> Poll<Result<(), Refusal>> {
        let _ = self.admitted(Some(host));
        Poll::Ready(Ok(()))
    }

    /// A reload's settings replace the instance's, and its target is asked about afresh; settings

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

    pub fn admitted(&self, host: Option<&Host>) -> bool {
        self.admitted_settings(host).is_some()
    }

    /// The settings (and their generation) a fresh delivery runs on, when the host admitted the

    fn admitted_settings(&self, host: Option<&Host>) -> Option<(Arc<Prepared>, u64)> {
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
                        let words = refusal_words(Some(&self.settings().url), &e);
                        if !matches!(e, ConnFailure::Refused(_) | ConnFailure::Unarmed) {
                            tracing::error!("{words}; webhook target admission failed; the next readiness check or delivery will retry");
                            return None;
                        }
                        tracing::error!(diag = %DISABLED, "{words}; disabling this webhook exporter");
                        false
                    }
                };
                *live = Some(ok);
                ok
            }
        };
        ok.then(|| self.current())
    }

    /// Whether a reload cut the batch whose rest is `rest` (the bytes after the line just done): when

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

pub struct Prepared {
    settings: Settings,
    target: Vec<u8>,
    /// The fields that carry no credential, in order (`content-type`).
    plain: Vec<(Vec<u8>, Vec<u8>)>,
    /// The fields that do (the `authorization` the userinfo became, the auth header): each goes in
    sealed: Vec<(usize, Vec<u8>, Cred)>,
}

impl Drop for Prepared {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.target);
    }
}

/// `Debug` prints the settings through the sink's own redaction: the url as the logs name it

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
                Field::Secret(cred(h.value.as_bytes().to_vec(), &settings.url)),
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

    fn parts(&self, line: &[u8]) -> (Request, Vec<SealedField>) {
        let request = Request {
            method: b"POST".to_vec(),
            target: self.target.clone(),
            fields: self.plain.clone(),
            body: line.to_vec(),
            timeout_ms: self.settings.delivery_timeout_secs.saturating_mul(1000),
        };
        let sealed = self
            .sealed
            .iter()
            .map(|(at, name, c)| (*at, name.clone(), c.field()))
            .collect();
        (request, sealed)
    }

    /// Whether `other` sends lines where these do and with the same credentials: the url and the

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

fn cred(value: Vec<u8>, url: &str) -> Cred {
    let mut v = serde_json::Value::String(String::from_utf8(value).unwrap_or_else(|e| {
        let bytes = zeroize::Zeroizing::new(e.into_bytes());
        String::from_utf8_lossy(&bytes).into_owned()
    }));

    Cred::take(&mut v)
        .unwrap_or_else(Cred::empty)
        .secure_for(url)
}

/// Whether the auth header can be sent: it is an HTTP header ([`header_is_http`]) and not one of

fn header_builds(h: &ExportAuthHeader) -> bool {
    header_is_http(h) && !is_framing(&h.name)
}

/// Whether `name` is one of the framing or connection fields, which the sink's own request states

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

fn framing_words(name: &str) -> String {
    format!(
        "settings.auth_header.name `{name}` is a framing/connection field the http framer states \
         itself; 1.6.0 does not send it"
    )
}

/// Whether the auth header is a header 1.5.5 could build: `HeaderName::from_bytes` takes a name of 1

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

pub fn basic_authorization(url: &str) -> Option<Vec<u8>> {
    let u = parsed_url(url).ok()?;
    if !u.has_authority() {
        return None;
    }
    let basic = sdk_url::basic_authorization(u.username(), u.password(), Userinfo::Utf8)
        .map(String::into_bytes);
    #[cfg(test)]
    if let Some(value) = &basic {
        crate::wipe_probe::watch("Basic value", value);
    }
    basic
}

/// BUSBAR-7070's words for a refused target, 1.5.5's: a target whose raw text is not an `https://`

pub fn refusal_words(url: Option<&str>, refused: &ConnFailure) -> String {
    match (url, refused) {
        (Some(u), ConnFailure::Refused(_)) if !undeclared(refused) && !is_https(u) => format!(
            "observability.request_log_webhook_url must be an https:// URL (got '{}')",
            shown_target(u)
        ),
        (Some(u), ConnFailure::Refused(_)) if !undeclared(refused) => match parsed_url(u) {
            Err(e) => format!("observability.request_log_webhook_url is not a valid URL: {e}"),
            Ok(_) => format!(
                "observability.request_log_webhook_url must not target a loopback/link-local/\
                 private/CGNAT/cloud-metadata host (SSRF guard); got '{}'",
                shown_target(u)
            ),
        },
        (Some(u), _) => scrub(&refused.to_string(), u, None),
        (None, _) => refused.to_string(),
    }
}

/// Refusal and check lines use the same credential-free target as delivery logs.
fn shown_target(url: &str) -> String {
    log_target(url)
}

/// Whether `refused` is the host's refusal of a need the plugin never declared

fn undeclared(refused: &ConnFailure) -> bool {
    matches!(refused, ConnFailure::Refused(t) if t.starts_with(busbar_contract::conn::ConnError::UndeclaredNeed.text()))
}

/// `url` names the `https` scheme, read without case and judged on the raw text before any parse, as

fn is_https(url: &str) -> bool {
    url.trim_start_matches(|c: char| c <= ' ')
        .chars()
        .filter(|c| !matches!(c, '\t' | '\r' | '\n'))
        .take(8)
        .map(|c| c.to_ascii_lowercase())
        .eq("https://".chars())
}

/// What became of one line: nothing to say for a 2xx; BUSBAR-7071 for any other status,

pub fn report(
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

/// The checks the configuration's validation runs across every webhook instance: AMONG the

pub fn check(phase: CheckPhase, instances: &[(String, serde_json::Value)]) -> Vec<String> {
    let parsed: Vec<(usize, &str, Settings)> = instances
        .iter()
        .enumerate()
        .filter_map(|(i, (name, s))| {
            Some((i, name.as_str(), serde::Deserialize::deserialize(s).ok()?))
        })
        .collect();
    let mut errors = Vec::new();
    if phase == CheckPhase::Instances {
        instance_checks(&parsed, &mut errors);
        return errors;
    }
    let bound = parsed
        .iter()
        .map(|(_, _, w)| w.max_inflight_deliveries)
        .max()
        .unwrap_or(DEFAULT_MAX_INFLIGHT);
    if bound < 1 {
        errors.push(
            "the largest settings.max_inflight_deliveries among `module: request-log-webhook` \
             export instances must be >= 1"
                .to_string(),
        );
    }
    if bound > MAX_PERMITS {
        errors.push(format!(
            "the largest settings.max_inflight_deliveries among `module: request-log-webhook` \
             export instances must be <= {MAX_PERMITS}"
        ));
    }
    errors
}

/// Each instance's delivery deadline, numbered by its configured position.
fn instance_checks(parsed: &[(usize, &str, Settings)], errors: &mut Vec<String>) {
    for (i, name, w) in parsed {
        if let Some(h) = w.auth_header.as_ref().filter(|h| is_framing(&h.name)) {
            errors.push(format!(
                "export.{name}: the `module: request-log-webhook` export instance targeting '{}' (#{i}): {} — \
                 remove the header",
                shown_target(&w.url),
                framing_words(&h.name)
            ));
        } else if let Some(h) = w.auth_header.as_ref().filter(|h| !header_builds(h)) {
            errors.push(format!(
                "export.{name}: the `module: request-log-webhook` export instance targeting '{}' (#{i}) sets \
                 settings.auth_header with a name or value that is not a valid HTTP header \
                 (name {:?}: the name must be a non-empty RFC 9110 token, and the value may hold \
                 no control byte other than tab); 1.5.5 left such a header out and sent the log \
                 without it — fix or remove the header",
                shown_target(&w.url),
                h.name
            ));
        }
        if w.delivery_timeout_secs > MAX_DURATION_SECS {
            errors.push(format!(
                "export.{name}: the `module: request-log-webhook` export instance targeting '{}' (#{i}) sets \
                 settings.delivery_timeout_secs: {}, above the {MAX_DURATION_SECS}-second (30-year) \
                 ceiling every duration is bounded by — a delivery deadline that far out overflows \
                 the clock",
                shown_target(&w.url),
                w.delivery_timeout_secs
            ));
        }
        if w.delivery_timeout_secs < 1 {
            errors.push(format!(
                "export.{name}: the `module: request-log-webhook` export instance targeting '{}' (#{i}) sets \
                 settings.delivery_timeout_secs: 0 — it must be \
                 >= 1",
                shown_target(&w.url)
            ));
        }
    }
}

/// The migration's report line when it removes an `auth_header` 1.6.0 refuses.
pub const REMOVED_AUTH_HEADER: &str =
    "removed settings.auth_header: 1.6.0 does not send it, as it \
     cannot be sent as an HTTP header (its name or value is not a valid HTTP header), which 1.6.0 \
     refuses at validation and open";

/// The migration's report line when it removes an `auth_header` named for a framing or connection

pub fn removed_framing_header(name: &str) -> String {
    format!(
        "removed {}, which 1.6.0 refuses at validation and open",
        framing_words(name)
    )
}

/// THE 1.5.5 UPGRADE (`busbar --migrate-config`; owner ruling 2026-10-27): this sink's own

pub struct Migration;

impl Migrate for Migration {
    fn migrate(mut settings: serde_json::Value, _: &str) -> Migrated {
        if !auth_header_unbuildable(&settings) {
            return Migrated::unchanged(settings);
        }
        let framing = settings
            .pointer("/auth_header/name")
            .and_then(serde_json::Value::as_str)
            .filter(|n| is_framing(n))
            .map(removed_framing_header);
        if let Some(section) = settings.as_object_mut() {
            let removed = section.remove("auth_header");
            #[cfg(test)]
            if let Some(value) = &removed {
                ownership_tests::watch_value_as("removed migration header", value);
            }
            drop(removed.map(owners::SettingsValue));
        }
        Migrated {
            settings,
            report: vec![framing.unwrap_or_else(|| REMOVED_AUTH_HEADER.to_string())],
            needs: Vec::new(),
        }
    }
}

/// Whether `settings` are refused at validation for their auth header ([`instance_checks`]), a

fn auth_header_unbuildable(settings: &serde_json::Value) -> bool {
    let mut probe = owners::SettingsValue(settings.clone());
    #[cfg(test)]
    ownership_tests::watch_value_as("migration probe JSON", &probe);
    if let Some(value) = probe
        .0
        .pointer_mut("/auth_header/value")
        .filter(|v| v.is_object())
    {
        *value = {
            let old = std::mem::replace(value, serde_json::Value::Null);
            drop(owners::SettingsValue(old));
            serde_json::Value::String(String::new())
        };
    }
    <Settings as serde::Deserialize>::deserialize(&*probe)
        .is_ok_and(|s| s.auth_header.as_ref().is_some_and(|h| !header_builds(h)))
}

/// `check`'s instances, `(name, settings)` in configuration order (settings that are not JSON read

fn instances(input: Lent<'_, CheckIn>) -> owners::SettingsInstances {
    owners::SettingsInstances(
        input
            .instances()
            .iter()
            .map(|c| {
                let settings = serde_json::from_slice(c.field(|c| &c.settings).bytes())
                    .unwrap_or(serde_json::Value::Null);
                #[cfg(test)]
                ownership_tests::watch_value_as("check settings JSON", &settings);
                (
                    String::from_utf8_lossy(c.field(|c| &c.name).bytes()).into_owned(),
                    settings,
                )
            })
            .collect(),
    )
}

/// The instance state every slot reads.
type State = Held<Webhook>;

/// The error texts of the door's REFUSED answers: one per cause, so the host's line names why

pub const NO_INSTANCE: &str = "no opened request-log-webhook instance";
/// `check` at a phase this sink does not know.
pub const UNKNOWN_PHASE: &str = "not a check phase this sink knows (limits or instances)";

/// What a delivery parks across PENDING: the settings it started under and their generation (a

struct Posting {
    settings: Arc<Prepared>,
    generation: u64,
    offset: usize,
    issued: u32,
    exchange: Option<Exchange>,
    /// Captured at admission, never upgraded on resume: an old host can finish the already-open
    bindings_pinned: bool,
}

/// `deliver`: each line of the batch POSTed in order, one exchange after another; fire-and-forget,

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

        let parked = instance.resume::<Posting>().map(|p| *p);
        let mut at = match parked {
            Some(p) => p,
            None => {
                let Some((settings, generation)) = hook.admitted_settings(h.host()) else {
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
        let batch = input.field(|i| &i.batch).bytes();
        while let Some((line, next)) = next_line(batch, at.offset) {
            let answered = match h.host() {
                None => Err(ConnFailure::Unarmed),
                Some(host) => {
                    let mut c = host.connector_from(instance.ticket(), at.issued);
                    let started = match at.exchange.take() {
                        Some(ex) => Ok(ex),
                        None => {
                            let (request, sealed) = at.settings.parts(line);
                            Exchange::request_sealed(request, sealed).map(Exchange::head_only)
                        }
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

#[cfg(test)]
#[path = "tests/audit_reconciliation.rs"]
mod audit_reconciliation;
