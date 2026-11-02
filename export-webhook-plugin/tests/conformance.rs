// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Runs the published conformance suite through this plugin's linked and dropped-in doors.

#[path = "support/settings.rs"]
mod settings;

#[path = "support/conformance_host.rs"]
mod conformance_host;

/// The far end's answer: an HTTP/1.1 `200` once a whole request (its head, then the
static RECEIVED: std::sync::Mutex<Vec<Vec<u8>>> = std::sync::Mutex::new(Vec::new());

fn accepted(seen: &[u8]) -> Option<Vec<u8>> {
    let end = seen.windows(4).position(|w| w == b"\r\n\r\n")? + 4;
    let head = String::from_utf8_lossy(&seen[..end]).to_ascii_lowercase();
    let body = head
        .lines()
        .find_map(|l| l.strip_prefix("content-length:"))
        .and_then(|n| n.trim().parse::<usize>().ok())
        .unwrap_or(0);
    (seen.len() >= end + body).then(|| {
        RECEIVED.lock().unwrap().push(seen[..end + body].to_vec());
        b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n".to_vec()
    })
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
        RECEIVED.lock().unwrap().clear();
        let d = calls::dispatcher();
        let tape = Arc::new(calls::Observed::default());
        let bind = busbar_plugin_loader::dispatch::Bind {
            sink: tape.clone(),
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
        use std::sync::atomic::Ordering;
        let mut prior_crossings = p.inner.crossings.load(Ordering::SeqCst);
        let mut prior_resumes = p.inner.resumes.load(Ordering::SeqCst);
        let mut counts = Vec::new();
        let mut pin = |label: &str, first: u64| {
            let crossings = p.inner.crossings.load(Ordering::SeqCst);
            let resumes = p.inner.resumes.load(Ordering::SeqCst);
            let resumed = resumes - prior_resumes;
            assert_eq!(
                crossings - prior_crossings - resumed,
                first,
                "{label}: first invocations"
            );
            counts.push((label.to_owned(), first, tape.take()));
            eprintln!("{label}: first={first} resumes={resumed}");
            prior_crossings = crossings;
            prior_resumes = resumes;
        };
        assert_eq!(p.kind(), busbar_contract::abi::mechanism::KindCode::Export);
        assert_eq!(p.name(), "busbar-export-webhook");
        assert_eq!(p.max_inflight(), 64);
        pin("facts", 0);
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
            pin("validate bad", 1);
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
        pin("deliver unopened", 0);
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
        pin("validate", 1);
        assert_eq!(
            calls::open_resumed(&p, &d, &settings).outcome,
            Outcome::Ready
        );
        pin("open", 1);
        p.ready(&d, std::time::Duration::from_secs(10))
            .expect("webhook ready");
        pin("ready", u64::from(p.has_ready()));
        let mut tick = Frame::new(blank_in::<TickIn>(), blank_out::<TickOut>());
        assert_eq!(
            p.call(lifecycle::slot::TICK, &mut tick).outcome,
            Outcome::Ready
        );
        pin("tick", 1);
        let c = deliver();
        assert_eq!(c.outcome, Outcome::Ready);
        assert_eq!(c.lease, 0);
        observed.push(calls::called(&c));
        pin("deliver #0", 1);
        let mut leases = Vec::new();
        let mut status = Frame::new(blank_in::<InHead>(), blank_out::<StatusOut>());
        let c = p.call(export::slot::STATUS, &mut status);
        assert_eq!(c.outcome, Outcome::Ready);
        pin("status", 1);
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
            pin("check phase", 1);
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
        pin("serve #0", 1);
        observed.push(calls::called(&c));
        if c.lease != 0 {
            leases.push(c.lease);
        }
        let unique: std::collections::BTreeSet<_> = leases.iter().collect();
        assert_eq!(unique.len(), leases.len());
        pin("own leases", 0);
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
            pin("release", 1);
        }
        if let Some(&lease) = leases.first() {
            assert_eq!(release(lease).outcome, Outcome::Refused);
            pin("release again", 1);
        }
        let bad = inputs["export"]["bad_settings"][0]["settings"].to_string();
        assert_eq!(calls::refresh(&p, bad.as_bytes()).outcome, Outcome::Failed);
        pin("refresh bad", 1);
        assert_eq!(calls::refresh(&p, &settings).outcome, Outcome::Ready);
        pin("refresh", 1);
        assert_eq!(deliver().outcome, Outcome::Ready);
        pin("deliver after refresh", 1);
        assert_eq!(
            p.call(
                lifecycle::slot::CLOSE,
                &mut Frame::new(blank_in::<InHead>(), blank_out::<OutHead>())
            )
            .outcome,
            Outcome::Ready
        );
        pin("close", 1);
        assert_ne!(
            deliver().outcome,
            Outcome::Ready,
            "closed exporter delivers nothing"
        );
        pin("deliver after close", 0);
        let received = std::mem::take(&mut *RECEIVED.lock().unwrap());
        assert_eq!(
            received.len(),
            2,
            "one actual POST before and after refresh"
        );
        for request in received {
            let split = request
                .windows(4)
                .position(|bytes| bytes == b"\r\n\r\n")
                .unwrap()
                + 4;
            assert!(request.starts_with(b"POST /busbar HTTP/1.1\r\n"));
            assert_eq!(&request[split..], batch.strip_suffix(b"\n").unwrap());
        }
        answers.push((observed, counts));
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

#[test]
fn the_declared_needs_are_the_statements() {
    let row = busbar_plugin_loader::dispatch::LinkedRow::of(busbar_export_webhook::door)
        .expect("actual statement");
    let statement = busbar_contract::abi::mechanism::rendering::read(&row.statement)
        .expect("statement renders");
    let actual: std::collections::BTreeSet<_> = statement
        .needs
        .iter()
        .filter(|need| !need.transport.is_empty())
        .map(|need| need.transport.as_str())
        .collect();
    let declared: serde_json::Value =
        serde_json::from_str(include_str!("../../export-webhook/declares.json"))
            .expect("declared needs JSON");
    let expected: std::collections::BTreeSet<_> = declared["needs"]
        .as_array()
        .expect("declared needs list")
        .iter()
        .map(|value| value.as_str().expect("transport scheme"))
        .collect();
    assert_eq!(actual, expected);
}
#[test]
fn the_suite_runs_in_the_profile_it_was_asked_to() {
    assert!(
        !(cfg!(debug_assertions) && std::env::var_os("BUSBAR_EXPECT_RELEASE").is_some()),
        "BUSBAR_EXPECT_RELEASE requires --release"
    );
}
