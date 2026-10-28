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
//! only their userinfo is masked.

/// What a redacted part becomes.
const REDACTED: &str = "***";

/// `url` as a delivery log line names it: scheme, a masked userinfo, host and port. A path other
/// than `/` becomes `/***` and a query `?***`; a fragment is dropped. A string that is not a URL keeps
/// only what precedes its authority's end, the rest `/***`.
pub fn log_target(url: &str) -> String {
    let Ok(u) = url::Url::parse(url) else {
        let masked = crate::mask_unparsed(url);
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
/// replaced by `***`: the URL itself (as written and userinfo-masked), its path, query, userinfo,
/// each also percent-decoded.
pub fn scrub(text: &str, url: &str) -> String {
    let mut parts = vec![url.to_string(), crate::mask_userinfo(url)];
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
    let decoded: Vec<String> = parts
        .iter()
        .map(|p| String::from_utf8_lossy(&crate::percent_decode(p.as_bytes())).into_owned())
        .collect();
    parts.extend(decoded);
    replace_all(text, parts)
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

/// `text` with each of `secrets` (as written, and as serde's `{:?}` escapes it inside a quoted
/// string) replaced by `***`, longest first so no secret is left half-cut.
pub fn replace_all(text: &str, secrets: Vec<String>) -> String {
    let mut all: Vec<String> = secrets
        .into_iter()
        .flat_map(|s| {
            let escaped = format!("{s:?}");
            let escaped = escaped[1..escaped.len() - 1].to_string();
            [s, escaped]
        })
        .filter(|s| !s.is_empty())
        .collect();
    all.sort_by_key(|s| std::cmp::Reverse(s.len()));
    all.dedup();
    let mut out = text.to_string();
    for s in &all {
        if out.contains(s.as_str()) {
            out = out.replace(s.as_str(), REDACTED);
        }
    }
    out
}
