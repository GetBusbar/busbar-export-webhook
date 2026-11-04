// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `settings:` grammar of an `export.<name>.module: request-log-webhook` instance — config
//! grammar, tracked by the config-schema gate here, where the sink that reads it lives.

use serde::de::{self, MapAccess, SeqAccess, Unexpected, Visitor};
use serde::{Deserialize, Deserializer};
use zeroize::{Zeroize, Zeroizing};

/// `settings:` of an `export.<name>.module: request-log-webhook` instance — relocated from the retired
/// `observability` webhook keys. Also absorbs the retired `generic-webhook` exporter: its ONLY extra
/// over this one was `auth_header:`, which is now just a setting here, and its other reason to exist
/// (a SECOND webhook target) is what the named-instance map itself provides. The FIELD ORDER is the
/// order serde names them in an unknown-field refusal: do not reorder. `Debug` carries no
/// credential: the url is named as the sink's log lines name it (scheme, masked userinfo, host and
/// port; a path or query is `***`), and the auth header's value is redacted.
#[derive(Deserialize, Clone, PartialEq)]
#[serde(from = "ParsedSettings")]
pub struct WebhookSettings {
    /// The webhook target URL — REQUIRED, `https://`-only, refused by the host's policy when it
    /// targets an internal host.
    pub url: String,
    /// An optional auth header applied to every delivery from THIS instance (e.g.
    /// `{ name: Authorization, value: { env: WEBHOOK_AUTHORIZATION } }`). The host resolves the
    /// reference to the complete header value before handing these settings to the sink. Existing
    /// literal header values remain accepted by the export host's compatibility policy.
    pub auth_header: Option<ExportAuthHeader>,
    /// Max concurrent deliveries (default 64) — relocated from `max_inflight_webhook_deliveries`.
    pub max_inflight_deliveries: usize,
    /// Per-delivery timeout (seconds, default 2) — relocated from `webhook_delivery_timeout_secs`.
    /// Applied PER INSTANCE (each sink carries its own deadline).
    pub delivery_timeout_secs: u64,
}

/// What serde reads: `WebhookSettings` is built `from` it, so its defaults and its refusal of
/// unknown keys are these.
#[derive(Deserialize)]
#[serde(rename = "WebhookSettings", deny_unknown_fields)]
struct ParsedSettings {
    #[serde(deserialize_with = "wiped_url")]
    url: Zeroizing<String>,
    #[serde(default)]
    auth_header: Option<ExportAuthHeader>,
    #[serde(default = "default_max_inflight")]
    max_inflight_deliveries: usize,
    #[serde(default = "default_timeout_secs")]
    delivery_timeout_secs: u64,
}

fn wiped_url<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Zeroizing<String>, D::Error> {
    url_string(d).map(Zeroizing::new)
}

impl From<ParsedSettings> for WebhookSettings {
    fn from(mut parsed: ParsedSettings) -> Self {
        Self {
            url: std::mem::take(&mut *parsed.url),
            auth_header: parsed.auth_header,
            max_inflight_deliveries: parsed.max_inflight_deliveries,
            delivery_timeout_secs: parsed.delivery_timeout_secs,
        }
    }
}

impl Drop for WebhookSettings {
    fn drop(&mut self) {
        self.url.zeroize();
    }
}

fn url_string<'de, D: serde::Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    let url = String::deserialize(d)?;
    crate::wipe_probe::watch("decoded settings url", url.as_bytes());
    Ok(url)
}

impl std::fmt::Debug for WebhookSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebhookSettings")
            .field("url", &crate::log_target(&self.url))
            .field("auth_header", &self.auth_header)
            .field("max_inflight_deliveries", &self.max_inflight_deliveries)
            .field("delivery_timeout_secs", &self.delivery_timeout_secs)
            .finish()
    }
}

/// One `{ name, value }` auth header for a webhook export instance. Its `value` is the credential:
/// `Debug` names the header and prints the value as `<redacted>`, so no formatted settings, header
/// or instance carries it.
#[derive(Clone, PartialEq)]
pub struct ExportAuthHeader {
    pub name: String,
    /// The credential, wiped from memory when the header is dropped.
    pub value: Zeroizing<String>,
}

/// The header's fields, in the order serde names them.
const HEADER_FIELDS: &[&str] = &["name", "value"];

/// What an `auth_header` refusal shows of text it must not repeat (an unknown key).
const REDACTED_KEY: &str = "***";
/// What an `auth_header` refusal shows of a string written where the header belongs.
const REDACTED_STRING: &str = "string \"***\"";

/// Reads the header as `#[derive(Deserialize)]` with `deny_unknown_fields` reads it, in its words,
/// except that a refusal never quotes the text it refused: serde's own words for a string where
/// the header belongs, or for an unknown key, would carry that text (a credential, most often) into
/// an error message that is freed without being wiped. It reads through `deserialize_any`, as a
/// JSON tree's `deserialize_struct` would itself name a string it refused.
impl<'de> Deserialize<'de> for ExportAuthHeader {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(HeaderVisitor)
    }
}

struct HeaderVisitor;

impl<'de> Visitor<'de> for HeaderVisitor {
    type Value = ExportAuthHeader;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("struct ExportAuthHeader")
    }

    fn visit_str<E: de::Error>(self, _: &str) -> Result<ExportAuthHeader, E> {
        Err(E::invalid_type(Unexpected::Other(REDACTED_STRING), &self))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<ExportAuthHeader, A::Error> {
        const EXPECTED: &str = "struct ExportAuthHeader with 2 elements";
        let name = seq
            .next_element::<String>()?
            .ok_or_else(|| de::Error::invalid_length(0, &EXPECTED))?;
        let value = seq
            .next_element::<String>()?
            .map(Zeroizing::new)
            .ok_or_else(|| de::Error::invalid_length(1, &EXPECTED))?;
        Ok(ExportAuthHeader { name, value })
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<ExportAuthHeader, A::Error> {
        let (mut name, mut value) = (None, None);
        while let Some(key) = map.next_key::<String>()? {
            let key = Zeroizing::new(key);
            match key.as_str() {
                "name" if name.is_some() => return Err(de::Error::duplicate_field("name")),
                "name" => name = Some(map.next_value::<String>()?),
                "value" if value.is_some() => return Err(de::Error::duplicate_field("value")),
                "value" => value = Some(Zeroizing::new(map.next_value::<String>()?)),
                _ => return Err(de::Error::unknown_field(REDACTED_KEY, HEADER_FIELDS)),
            }
        }
        Ok(ExportAuthHeader {
            name: name.ok_or_else(|| de::Error::missing_field("name"))?,
            value: value.ok_or_else(|| de::Error::missing_field("value"))?,
        })
    }
}

impl std::fmt::Debug for ExportAuthHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExportAuthHeader")
            .field("name", &self.name)
            .field("value", &"<redacted>")
            .finish()
    }
}

/// The default in-flight bound per instance.
pub const DEFAULT_MAX_INFLIGHT: usize = 64;
/// The default per-delivery deadline (seconds).
pub const DEFAULT_TIMEOUT_SECS: u64 = 2;

fn default_max_inflight() -> usize {
    DEFAULT_MAX_INFLIGHT
}

fn default_timeout_secs() -> u64 {
    DEFAULT_TIMEOUT_SECS
}
