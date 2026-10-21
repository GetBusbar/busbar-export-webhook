// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `settings:` grammar of an `export.<name>.module: request-log-webhook` instance — config
//! grammar, tracked by the config-schema gate here, where the sink that reads it lives (K9c).

use serde::Deserialize;

/// `settings:` of an `export.<name>.module: request-log-webhook` instance — relocated from the retired
/// `observability` webhook keys. Also absorbs the retired `generic-webhook` exporter: its ONLY extra
/// over this one was `auth_header:`, which is now just a setting here, and its other reason to exist
/// (a SECOND webhook target) is what the named-instance map itself provides. The FIELD ORDER is the
/// order serde names them in an unknown-field refusal: do not reorder. `Debug` carries no
/// credential: the url's userinfo is masked as every line the sink writes masks it, and the auth
/// header's value is redacted.
#[derive(Deserialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct WebhookSettings {
    /// The webhook target URL — REQUIRED, `https://`-only, refused by the host's policy when it
    /// targets an internal host (relocated from the retired `observability.request_log_webhook_url`).
    pub url: String,
    /// An optional auth header applied to every delivery from THIS instance (e.g.
    /// `{ name: Authorization, value: "Bearer ${WEBHOOK_TOKEN}" }`). The `value` rides the config's
    /// `${VAR}` env interpolation, so a secret is never stored literally.
    #[serde(default)]
    pub auth_header: Option<ExportAuthHeader>,
    /// Max concurrent deliveries (default 64) — relocated from `max_inflight_webhook_deliveries`.
    #[serde(default = "default_max_inflight")]
    pub max_inflight_deliveries: usize,
    /// Per-delivery timeout (seconds, default 2) — relocated from `webhook_delivery_timeout_secs`.
    /// Applied PER INSTANCE (each sink carries its own deadline).
    #[serde(default = "default_timeout_secs")]
    pub delivery_timeout_secs: u64,
}

impl std::fmt::Debug for WebhookSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebhookSettings")
            .field("url", &crate::mask_userinfo(&self.url))
            .field("auth_header", &self.auth_header)
            .field("max_inflight_deliveries", &self.max_inflight_deliveries)
            .field("delivery_timeout_secs", &self.delivery_timeout_secs)
            .finish()
    }
}

/// One `{ name, value }` auth header for a webhook export instance. Its `value` is the credential:
/// `Debug` names the header and prints the value as `<redacted>`, so no formatted settings, header
/// or instance carries it.
#[derive(Deserialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ExportAuthHeader {
    pub name: String,
    pub value: String,
}

impl ExportAuthHeader {
    /// Overwrite the credential with zeros and empty it.
    pub fn wipe(&mut self) {}
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
