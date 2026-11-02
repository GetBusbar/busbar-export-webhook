// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Runs the published conformance suite through this plugin's linked and dropped-in doors.

#[path = "support/settings.rs"]
mod settings;

#[path = "support/conformance_host.rs"]
mod conformance_host;

/// The far end's answer: an HTTP/1.1 `200` once a whole request (its head, then the
fn accepted(seen: &[u8]) -> Option<Vec<u8>> {
    let end = seen.windows(4).position(|w| w == b"\r\n\r\n")? + 4;
    let head = String::from_utf8_lossy(&seen[..end]).to_ascii_lowercase();
    let body = head
        .lines()
        .find_map(|l| l.strip_prefix("content-length:"))
        .and_then(|n| n.trim().parse::<usize>().ok())
        .unwrap_or(0);
    (seen.len() >= end + body).then(|| b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n".to_vec())
}

/// The host the suite binds the sink over, with the far end its settings name already listening.
fn host(
    wake: busbar_contract::conn::ConnWake,
    anchors: Option<&str>,
) -> std::sync::Arc<dyn busbar_contract::conn::DeclaredConns> {
    conformance_host::far_end(accepted);
    conformance_host::host(wake, anchors)
}

#[path = "support/artifact.rs"]
mod artifact;
#[path = "support/calls.rs"]
mod calls;

#[test]
fn the_linked_and_freshly_built_dropped_webhook_obey_the_export_contract() {
    use busbar_contract::abi::sdk::door::{blank_in, blank_out};
    use busbar_contract::abi::{
        export::{self, CheckIn, CheckInstance, CheckOut, DeliverIn, ServeIn, ServeOut, StatusOut},
        mechanism::{
            call::{AbiStr, Blob, DeadlineClass, InHead, OutHead, Outcome, BLOB_JSONL},
            lifecycle::{self, ReleaseIn, TickIn, TickOut, ValidateIn},
        },
    };
    use busbar_plugin_loader::dispatch::kinds::export::Export;
    use busbar_plugin_loader::dispatch::{load_dropped, load_linked, ConnTable, Frame, LinkedRow};
    use std::sync::Arc;
    let inputs: serde_json::Value = serde_json::from_str(include_str!("conformance.json")).unwrap();
    let settings = inputs["settings"].to_string().into_bytes();
    let row = LinkedRow::of(busbar_export_webhook::door).expect("actual linked statement");
    let mut answers = Vec::new();
    for dropped in [false, true] {
        let d = calls::dispatcher();
        let bind = busbar_plugin_loader::dispatch::Bind {
            conns: ConnTable::Host(host(d.conn_waker(), Some(conformance_host::anchors()))),
            ..calls::bind(&d, "conformance")
        };
        let p = if dropped {
            load_dropped::<Export>(
                &artifact::cdylib_of("busbar_export_webhook_plugin"),
                &row.statement,
                bind,
            )
        } else {
            load_linked::<Export>(&row, bind)
        }
        .expect("actual webhook loads");
        let mut observed = vec![format!(
            "{} {:?} {:?}",
            p.name(),
            p.secret_refs(),
            p.reference_fields()
        )];
        for case in inputs["export"]["bad_settings"].as_array().unwrap() {
            let bytes = case["settings"].to_string().into_bytes();
            let mut i: ValidateIn = blank_in();
            i.settings = Blob::json(&bytes);
            let mut error = [0u8; 1024];
            i.err_buf = error.as_mut_ptr();
            i.err_cap = error.len();
            let c = p.call(
                lifecycle::slot::VALIDATE,
                &mut Frame::new(i, blank_out::<OutHead>()),
            );
            assert_eq!(c.outcome, Outcome::Failed);
            assert_eq!(c.lease, 0);
            assert!(String::from_utf8_lossy(c.error.as_deref().unwrap())
                .contains(case["refusal"].as_str().unwrap()));
            observed.push(calls::called(&c));
        }
        let batch = Arc::new(
            inputs["export"]["deliver"][0]["batch"]
                .as_str()
                .unwrap()
                .as_bytes()
                .to_vec(),
        );
        let deliver = || {
            let mut i: DeliverIn = blank_in();
            i.stream = export::ExportStream::Logs as u8;
            i.op_id = [1; 16];
            i.batch = Blob {
                fmt: BLOB_JSONL,
                ..Blob::json(&batch)
            };
            calls::on_ticket(
                &p,
                &d,
                export::slot::DELIVER,
                Frame::new(i, blank_out::<OutHead>()),
                DeadlineClass::WriteBehind,
                0,
                batch.clone(),
            )
        };
        assert_ne!(
            deliver().outcome,
            Outcome::Ready,
            "unopened exporter delivers nothing"
        );
        let mut i: ValidateIn = blank_in();
        i.settings = Blob::json(&settings);
        assert_eq!(
            p.call(
                lifecycle::slot::VALIDATE,
                &mut Frame::new(i, blank_out::<OutHead>())
            )
            .outcome,
            Outcome::Ready
        );
        assert_eq!(
            calls::open_resumed(&p, &d, &settings).outcome,
            Outcome::Ready
        );
        p.ready(&d, std::time::Duration::from_secs(10))
            .expect("webhook ready");
        let mut tick = Frame::new(blank_in::<TickIn>(), blank_out::<TickOut>());
        assert_eq!(
            p.call(lifecycle::slot::TICK, &mut tick).outcome,
            Outcome::Ready
        );
        let c = deliver();
        assert_eq!(c.outcome, Outcome::Ready);
        assert_eq!(c.lease, 0);
        observed.push(calls::called(&c));
        let mut leases = Vec::new();
        let mut status = Frame::new(blank_in::<InHead>(), blank_out::<StatusOut>());
        let c = p.call(export::slot::STATUS, &mut status);
        assert_eq!(c.outcome, Outcome::Ready);
        // SAFETY: the loader judged the returned blob; its result lease is still live.
        let bytes = if status.out.status.len == 0 {
            Vec::new()
        } else {
            unsafe { std::slice::from_raw_parts(status.out.status.ptr, status.out.status.len) }
                .to_vec()
        };
        observed.push(format!("status {:?}", bytes));
        if c.lease != 0 {
            leases.push(c.lease);
        }
        let rows = [CheckInstance {
            name: AbiStr::of("conformance"),
            settings: Blob::json(&settings),
        }];
        for phase in [export::CHECK_PHASE_LIMITS, export::CHECK_PHASE_INSTANCES] {
            let mut i: CheckIn = blank_in();
            i.phase = phase;
            i.instances = rows.as_ptr();
            i.instances_len = rows.len();
            let mut f = Frame::new(i, blank_out::<CheckOut>());
            let c = p.call(export::slot::CHECK, &mut f);
            assert_eq!(c.outcome, Outcome::Ready);
            // SAFETY: the loader judged the findings blob; its result lease is still live.
            let bytes = if f.out.findings.len == 0 {
                Vec::new()
            } else {
                unsafe { std::slice::from_raw_parts(f.out.findings.ptr, f.out.findings.len) }
                    .to_vec()
            };
            observed.push(format!("check {phase} {:?}", bytes));
            if c.lease != 0 {
                leases.push(c.lease);
            }
        }
        let mut i: ServeIn = blank_in();
        i.method = AbiStr::of("GET");
        i.path = AbiStr::of("/exports/tail/x");
        let c = p.call(
            export::slot::SERVE,
            &mut Frame::new(i, blank_out::<ServeOut>()),
        );
        assert_eq!(c.outcome, Outcome::Refused);
        observed.push(calls::called(&c));
        if c.lease != 0 {
            leases.push(c.lease);
        }
        let unique: std::collections::BTreeSet<_> = leases.iter().collect();
        assert_eq!(unique.len(), leases.len());
        let release = |lease| {
            let mut i: ReleaseIn = blank_in();
            i.lease = lease;
            p.call(
                lifecycle::slot::RELEASE,
                &mut Frame::new(i, blank_out::<OutHead>()),
            )
        };
        for &lease in &leases {
            assert_eq!(release(lease).outcome, Outcome::Ready);
        }
        if let Some(&lease) = leases.first() {
            assert_eq!(release(lease).outcome, Outcome::Refused);
        }
        let bad = inputs["export"]["bad_settings"][0]["settings"].to_string();
        assert_eq!(calls::refresh(&p, bad.as_bytes()).outcome, Outcome::Failed);
        assert_eq!(calls::refresh(&p, &settings).outcome, Outcome::Ready);
        assert_eq!(deliver().outcome, Outcome::Ready);
        assert_eq!(
            p.call(
                lifecycle::slot::CLOSE,
                &mut Frame::new(blank_in::<InHead>(), blank_out::<OutHead>())
            )
            .outcome,
            Outcome::Ready
        );
        assert_ne!(
            deliver().outcome,
            Outcome::Ready,
            "closed exporter delivers nothing"
        );
        answers.push(observed);
    }
    assert_eq!(
        answers[0], answers[1],
        "linked and dropped actual plugin results"
    );
}

/// The kernel resolves references at declared secret fields in place and refuses undeclared ones.
mod declared_secrets {
    use std::sync::Arc;

    use super::settings::settings_as_the_kernel_resolves;
    use busbar_plugin_loader::dispatch::kinds::export::Export;
    use busbar_plugin_loader::dispatch::{
        load_linked, Bind, ConnTable, DispatchConfig, Dispatcher, LinkedRow, NoSink, Plugin,
    };
    use serde_json::{json, Value};

    fn load() -> Plugin<Export> {
        let d = Arc::new(Dispatcher::new(DispatchConfig::default()));
        load_linked::<Export>(
            &LinkedRow::of(busbar_export_webhook::door).expect("the linked door renders"),
            Bind {
                instance: Arc::from("declared"),
                max_inflight_cap: 64,
                sink: Arc::new(NoSink),
                dispatcher: d.adopter(),
                conns: ConnTable::Host(super::conformance_host::host(Arc::new(|_, _| {}), None)),
            },
        )
        .expect("the linked door loads")
    }

    fn resolved(_: &str, _: &busbar_contract::secret_ref::SecretRef) -> Result<String, String> {
        Ok("resolved-value".to_string())
    }

    #[test]
    fn a_reference_at_each_declared_field_resolves_in_place() {
        let out = settings_as_the_kernel_resolves(
            &load(),
            br#"{"url":{"env":"X"},"auth_header":{"name":"Authorization","value":{"env":"X"}}}"#,
            resolved,
        )
        .expect("the declared fields take a reference");
        let v: Value = serde_json::from_slice(&out).expect("json");
        assert_eq!(v["url"], json!("resolved-value"), "{v}");
        assert_eq!(v["auth_header"]["value"], json!("resolved-value"), "{v}");
        assert_eq!(v["auth_header"]["name"], json!("Authorization"), "{v}");
    }

    #[test]
    fn a_reference_at_an_undeclared_field_is_refused() {
        let e = settings_as_the_kernel_resolves(
            &load(),
            br#"{"url":"https://h.example/hook","auth_header":{"name":{"env":"X"},"value":"v"}}"#,
            resolved,
        )
        .expect_err("an undeclared field takes no reference");
        assert!(e.contains("did not declare it as a secret"), "{e}");
    }
}
