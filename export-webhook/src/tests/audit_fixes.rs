// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Regressions for the credential, admission and migration defects the fleet audit found.

use super::*;

/// A credential written as a JSON number where a string belongs is refused without quoting it:
/// serde names the number it refused, and the number is the credential.
#[test]
fn a_non_string_auth_header_credential_is_never_quoted() {
    for (settings, secret) in [
        (
            json!({"url": "https://a.example/", "auth_header": {"name": "X-Key", "value": 12345678}}),
            "12345678",
        ),
        (
            json!({"url": "https://a.example/", "auth_header": {"name": "X-Key", "value": 1234.5678}}),
            "1234.5678",
        ),
        (
            json!({"url": "https://a.example/", "auth_header": 4242}),
            "4242",
        ),
        (
            json!({"url": "https://a.example/", "auth_header": ["X-Key", 99887766]}),
            "99887766",
        ),
    ] {
        let text = refused(settings);
        assert!(text.starts_with("settings: invalid type: "), "{text}");
        assert!(!text.contains(secret), "{text}");
    }
    // A number serde reads as a float is named in serde's own float words, not JSON's.
    for (value, secret) in [
        ("123456789012345678901234", "12345678901234"),
        ("1e-7", "0000001"),
        ("5e300", "500000000000"),
        ("1e21", "1000000000000000000000"),
        ("-98765", "98765"),
        ("-98765432101234567890123", "9876543210"),
    ] {
        let settings = serde_json::from_str(&format!(
            r#"{{"url":"https://a.example/","auth_header":{value}}}"#
        ))
        .unwrap();
        let text = refused(settings);
        assert!(text.starts_with("settings: invalid type: "), "{text}");
        assert!(!text.contains(secret), "{text}");
    }
}

/// Settings written as a bare string (the url, credential and all) are refused without quoting it.
#[test]
fn settings_that_are_not_a_section_are_refused_without_quoting_them() {
    let text = refused(json!("https://operator:s3cret@siem.example/hook?k=T0KEN"));
    assert!(text.starts_with("settings: invalid type: string"), "{text}");
    for secret in ["operator", "s3cret", "siem.example", "T0KEN"] {
        assert!(!text.contains(secret), "{text}");
    }
}

/// A url that parses without a host keeps no word before its colon: that word may be the front of
/// a credential pasted where the url belongs, as it may be in text that does not parse.
#[test]
fn a_hostless_url_shows_no_word_before_its_colon() {
    assert_eq!(log_target("AKIAEXAMPLE:secretpart"), "***");
    assert_eq!(log_target("sk_live_ab12:cd34"), "***");
    assert_eq!(
        refusal_words(
            "sk_live_ab12:cd34",
            None,
            &ConnFailure::Refused("destination refused".to_string())
        ),
        "settings.url '***': destination refused"
    );
}

/// The credentials of a target the url parser reads as `https` must cross only a secure stream,
/// however the scheme's separator is written.
#[test]
fn credentials_for_an_https_target_written_without_slashes_require_a_secure_stream() {
    for url in [
        "https:operator:s3cret@siem.example/hook",
        "HTTPS:/operator:s3cret@siem.example/hook",
        " https://operator:s3cret@siem.example/hook",
    ] {
        let p = Prepared::new(settings(
            json!({"url": url, "auth_header": {"name": "X-Key", "value": "T0KEN"}}),
        ));
        assert_eq!(p.sealed.len(), 2, "{url}: userinfo and header are sealed");
        for (_, name, cred) in &p.sealed {
            assert!(
                cred.secure_required(),
                "{url}: {}",
                String::from_utf8_lossy(name)
            );
        }
    }
}

/// A url that does not parse is not known to be `http`: its auth header still requires a secure
/// stream.
#[test]
fn credentials_for_a_url_that_does_not_parse_require_a_secure_stream() {
    let p = Prepared::new(settings(
        json!({"url": "https://exa mple.com/x", "auth_header": {"name": "X-Key", "value": "T0KEN"}}),
    ));
    assert_eq!(p.sealed.len(), 1);
    assert!(p.sealed[0].2.secure_required());
}

/// A framing field written in the `[name, value]` pair form is removed with the framing receipt,
/// as the object form is.
#[test]
fn migration_names_a_framing_field_written_as_a_pair() {
    let m = migrated(json!({"url": "https://a.example/", "auth_header": ["Host", "x"]}));
    assert_eq!(m.report, vec![removed_framing_header("Host")]);
    assert!(m.settings.get("auth_header").is_none(), "{:?}", m.settings);
}

/// Migration on settings that are not a section removes nothing, so it reports no removal.
#[test]
fn migration_reports_no_removal_it_did_not_make() {
    let before = json!(["https://a.example/", ["X-Key", "bad\nvalue"]]);
    assert!(
        auth_header_unbuildable(&before),
        "the probe reads it as refused"
    );
    let m = migrated(before.clone());
    assert_eq!(m.settings, before);
    assert!(m.report.is_empty(), "{:?}", m.report);
}

/// A batch met by an admission the host could not answer is not dropped without a word: each line
/// is reported as BUSBAR-7072 (the url masked), and the instance is not disabled.
#[test]
fn a_batch_met_by_an_unsettled_admission_reports_each_dropped_line() {
    let failing = AdmissionHost::new(Outcome::Failed);
    let w = Webhook::open(
        br#"{"url":"https://operator:s3cret@siem.example/in"}"#,
        &[],
        1,
    )
    .expect("opens");
    let mut admitted = None;
    let got = logged(|| {
        admitted =
            Some(w.admitted_for(Some(&failing.host()), b"{\"a\":1}\n\n{\"b\":2}\n{\"c\":3}"));
    });
    assert!(matches!(admitted, Some(None)), "no delivery runs");
    assert_eq!(field(&got[0], "level"), "ERROR", "the admission failure");
    let got = &got[1..];
    assert_eq!(got.len(), 3, "one line per dropped log line: {got:?}");
    for e in got {
        assert_eq!(field(e, "diag"), "BUSBAR-7072");
        assert_eq!(field(e, "level"), "WARN");
        assert_eq!(field(e, "webhook_url"), "\"https://***@siem.example/***\"");
        assert!(!format!("{e:?}").contains("s3cret"), "{e:?}");
    }
    assert_eq!(
        logged(|| assert!(w.admitted_for(Some(&failing.host()), b"\n\n").is_none())).len(),
        1,
        "an empty batch drops no line, only the admission is reported"
    );

    let ready = AdmissionHost::new(Outcome::Ready);
    assert!(w.admitted(Some(&ready.host())), "asked again, and admitted");
}
