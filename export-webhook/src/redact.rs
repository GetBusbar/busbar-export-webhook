// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Keeping credentials out of the sink's own words.
//!
//! A webhook target carries its secret in more places than the userinfo: Slack-style targets put it
//! in the path (`/services/T…/B…/X…`), others in the query (`?api_key=…`). And the host's failure
//! text may quote the target. So a delivery LOG line names only the target's scheme and host
//! ([`log_target`]), and any text that came from elsewhere is scrubbed of the target's parts
//! ([`scrub`]) and of the settings' credential strings ([`settings_credentials`]).
//!
//! The refusal lines that name the target (BUSBAR-7070, the delivery-deadline check) keep the path:
//! only their userinfo and secret-looking query values are masked
//! (`busbar_contract::abi::sdk::mask::mask_url`).

use busbar_contract::abi::sdk::url as sdk_url;

/// What a redacted part becomes.
const REDACTED: &str = "***";

/// `url` as a delivery log line names it: scheme, a masked userinfo, host and port. A path other
/// than `/` becomes `/***` and a query `?***`; a fragment is dropped. A string that is not a URL keeps
/// only what precedes its authority's end, the rest `/***`.
pub fn log_target(url: &str) -> String {
    let Ok(u) = url::Url::parse(url) else {
        let masked = crate::mask_url(url);
        let Some((scheme, rest)) = masked.split_once("://") else {
            return REDACTED.to_string();
        };
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let tail = if end < rest.len() { "/***" } else { "" };
        return format!("{scheme}://{}{tail}", &rest[..end]);
    };
    let Some(host) = u.host_str() else {
        return format!("{}:{REDACTED}", u.scheme());
    };
    let mut out = format!("{}://", u.scheme());
    if !u.username().is_empty() || u.password().is_some() {
        out.push_str("***@");
    }
    out.push_str(host);
    if let Some(p) = u.port() {
        out.push_str(&format!(":{p}"));
    }
    if !matches!(u.path(), "" | "/") {
        out.push_str("/***");
    }
    if u.query().is_some() {
        out.push_str("?***");
    }
    out
}

/// `text` (a host's failure words, say) with every part of `url` that can carry a credential
/// replaced by `***`: the URL itself (as written and masked, `mask_url`), its path, query, userinfo,
/// each also percent-decoded; the decoding and the cut (as written and as serde quotes it, longest
/// first) are the SDK's (`sdk::url::and_decoded`, `sdk::url::scrub`). The request's own credentials
/// are cut too, for a receiver may echo its request back: the `Authorization: Basic` value the
/// userinfo became, its base64 token, and the `auth_header` value (`header_value`).
pub fn scrub(text: &str, url: &str, header_value: Option<&str>) -> String {
    let mut parts = vec![url.to_string(), crate::mask_url(url)];
    if let Ok(u) = url::Url::parse(url) {
        if !matches!(u.path(), "" | "/") {
            parts.push(u.path().to_string());
        }
        if let Some(q) = u.query().filter(|q| !q.is_empty()) {
            parts.push(q.to_string());
        }
        if let Some(p) = u.password() {
            parts.push(p.to_string());
        }
        parts.push(u.username().to_string());
    }
    if let Some(basic) = crate::basic_authorization(url) {
        let basic = String::from_utf8_lossy(&basic).into_owned();
        parts.extend(basic.strip_prefix("Basic ").map(str::to_owned));
        parts.push(basic);
    }
    parts.extend(header_value.filter(|v| !v.is_empty()).map(str::to_owned));
    sdk_url::scrub(text, sdk_url::and_decoded(parts), true)
}

/// Every credential-bearing string the settings JSON holds: every string (and map key) under
/// `auth_header` except the header's `name`. These are what serde may quote back in a shape refusal.
pub fn settings_credentials(settings: &serde_json::Value) -> Vec<String> {
    fn walk(v: &serde_json::Value, out: &mut Vec<String>) {
        match v {
            serde_json::Value::String(s) => out.push(s.clone()),
            serde_json::Value::Array(a) => a.iter().for_each(|v| walk(v, out)),
            serde_json::Value::Object(o) => {
                for (k, v) in o {
                    if k == "name" && v.is_string() {
                        continue;
                    }
                    if k != "name" && k != "value" {
                        out.push(k.clone());
                    }
                    walk(v, out);
                }
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    if let Some(h) = settings.get("auth_header") {
        walk(h, &mut out);
    }
    out
}
