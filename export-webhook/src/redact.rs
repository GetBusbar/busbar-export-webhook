// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Keeping credentials out of the sink's own words.

use busbar_contract::abi::sdk::url as sdk_url;
use zeroize::Zeroizing;

/// What a redacted part becomes.
const REDACTED: &str = "***";

/// `url` as a delivery log line names it: scheme, a masked userinfo, host and port. A path other
pub fn log_target(url: &str) -> String {
    let Ok(u) = crate::parsed_url(url) else {
        return unparsed_target(url);
    };

    if u[url::Position::BeforePath..].contains('@') {
        return unparsed_target(url);
    }
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

/// What a line shows of url text that does not parse: `<scheme>:***` when it opens with `http` or
pub(crate) fn unparsed_target(url: &str) -> String {
    let scheme = url
        .split_once(':')
        .map(|(s, _)| s)
        .filter(|s| s.eq_ignore_ascii_case("http") || s.eq_ignore_ascii_case("https"));
    scheme.map_or_else(|| REDACTED.to_string(), |s| format!("{s}:{REDACTED}"))
}

/// `text` (a host's failure words, say) with every part of `url` that can carry a credential
pub fn scrub(text: &str, url: &str, header_value: Option<&str>) -> String {
    let mut parts = Zeroizing::new(vec![url.to_string(), crate::mask_url(url)]);
    if let Ok(u) = crate::parsed_url(url) {
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
        let bytes = Zeroizing::new(basic);
        let basic = String::from_utf8_lossy(&bytes).into_owned();
        parts.extend(basic.strip_prefix("Basic ").map(str::to_owned));
        parts.push(basic);
    }
    parts.extend(header_value.filter(|v| !v.is_empty()).map(str::to_owned));
    if let Some(value) = header_value {
        let value = value.trim_ascii_start();
        if let Some((scheme, credential)) = value.split_once(|c: char| c.is_ascii_whitespace()) {
            if scheme.eq_ignore_ascii_case("Bearer") || scheme.eq_ignore_ascii_case("Basic") {
                let credential = credential.trim_ascii();
                parts.extend((!credential.is_empty()).then(|| credential.to_owned()));
            }
        }
    }
    #[cfg(test)]
    for part in parts.iter() {
        crate::wipe_probe::watch("redaction part", part.as_bytes());
    }
    sdk_url::scrub(
        text,
        sdk_url::and_decoded(std::mem::take(&mut *parts)),
        true,
    )
}

/// Every credential-bearing string the settings JSON holds: every string (and map key) under
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
    #[cfg(test)]
    for credential in &out {
        crate::wipe_probe::watch("settings credential copy", credential.as_bytes());
    }
    out
}
