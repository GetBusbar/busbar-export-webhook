// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE REQUEST-LOG WEBHOOK SINK, BOTH WAYS** — the webhook sink's linked + dropped-in conformance,
//! run against the busbar rev this repo pins (`.busbar-ref`).
//!
//! The sink is held two ways at once: LINKED (its `linked::EXPORT` statement and boundary, the row a
//! busbar build that compiles it in registers) and DROPPED IN (this crate's built cdylib, signed
//! first-party under the SAME statement — `declares` included, which is what
//! `busbar-plugin-pack --declares-file` embeds — into a temp `plugins/` directory and found by the
//! loader's scan). Each is registered through the plugin registry's one admission and opened through
//! its one `open_export`. One script runs against each: validate and check its settings, start it
//! (the host's policy asked of its target), deliver two lines (one the far end accepts, one it
//! answers 503), shed one. Everything the host sees — the answers, the requests its egress carrier
//! was asked to make, and every metric and diagnostic it folded — must be byte-identical between the
//! doors.
//!
//! RED ARMS: a tarball packed WITHOUT the declaration the linked row states (the pack tool's
//! `--declares-file` left off) is not the same plugin — its shed counter is not granted; and without
//! the linked row the module is not on the axis at all.
//!
//! Ported from busbar's `crates/busbar/src/root/tests/export_webhook_conformance.rs` (K9c), where the
//! sink was proven before it moved to this repo; busbar still runs that test against the pinned sink.

use busbar_plugin_loader::sign::{sign, Manifest, SigningKey, TrustPolicy};
use busbar_plugin_loader::{
    ExportStream, HostResult, HttpRequest, HttpResponse, LinkedPlugin, PluginRegistry,
};
use serde_json::{json, Value};
use std::sync::Mutex;

const ALIAS: &str = "request-log-webhook";

/// The version both arms state (a linked row states its binary's version; here, this crate's).
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// What the host was handed during one script: carried requests and folded observations.
static CARRIED: Mutex<Vec<Value>> = Mutex::new(Vec::new());
static FOLDED: Mutex<Vec<Value>> = Mutex::new(Vec::new());
/// One script at a time (the carrier and the observer are process-global).
static SERIAL: Mutex<()> = Mutex::new(());

/// The egress this test installs: its policy refuses `*.internal.example`; the far end answers 503
/// on a path ending `/fail` and 204 otherwise. It records every request it carries.
struct Carrier;

impl busbar_plugin_loader::EgressCarrier for Carrier {
    fn carry(&self, request: &HttpRequest) -> HostResult {
        CARRIED
            .lock()
            .unwrap()
            .push(serde_json::to_value(request).unwrap());
        let status = if request.url.ends_with("/fail") {
            503
        } else {
            204
        };
        HostResult::Http(HttpResponse {
            status,
            body: String::new(),
        })
    }

    fn admit(&self, url: &str) -> Result<(), String> {
        match url.contains(".internal.example") {
            true => Err(format!("refused target '{url}'")),
            false => Ok(()),
        }
    }
}

struct Observer;

impl busbar_plugin_loader::observe::PluginObserver for Observer {
    fn observe(&self, plugin: &str, kind: &str, metrics: &[Value], diagnostics: &[Value]) {
        FOLDED.lock().unwrap().push(json!({
            "plugin": plugin, "kind": kind, "metrics": metrics, "diagnostics": diagnostics,
            "first_party": busbar_plugin_loader::observe::first_party(plugin),
        }));
    }
}

fn installed() -> std::sync::MutexGuard<'static, ()> {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        // Both are first-install-wins process globals: if another test in this binary had installed
        // its own, every assertion below would read somebody else's record — refuse that loudly.
        assert!(busbar_plugin_loader::install_egress_carrier(&Carrier));
        assert!(busbar_plugin_loader::observe::install_plugin_observer(
            &Observer
        ));
    });
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

/// This crate's built cdylib (uplifted or under `deps`, newest wins). A missing artifact is a
/// failure, never a skip: this test IS the dropped-in door's proof.
fn cdylib() -> Vec<u8> {
    let exe = std::env::current_exe().expect("the test binary has a path");
    let profile = exe
        .parent()
        .and_then(|d| d.parent())
        .expect("target/<profile>");
    let file = busbar_plugin_loader::plugin_library_filename("busbar_export_webhook_plugin");
    let found = [profile.join(&file), profile.join("deps").join(&file)]
        .into_iter()
        .filter_map(|p| Some((std::fs::metadata(&p).ok()?.modified().ok()?, p)))
        .max()
        .map(|(_, p)| p)
        .unwrap_or_else(|| panic!("the busbar-export-webhook-plugin cdylib ({file}) is not built"));
    std::fs::read(found).expect("read the cdylib")
}

/// THE LINKED DOOR: exactly the row busbar's composition root states for `linked::EXPORT`.
fn linked_door() -> PluginRegistry {
    let (name, alias, declares, entry) = busbar_export_webhook::linked::EXPORT;
    let abi = busbar_plugin_loader::supported_abi("export")
        .iter()
        .copied()
        .max()
        .unwrap_or_default();
    let manifest = Manifest {
        name: name.into(),
        alias: alias.into(),
        kind: "export".into(),
        version: VERSION.into(),
        publisher: busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER.into(),
        abi_version: abi,
        sha256: String::new(),
        signature: String::new(),
        description: String::new(),
        homepage: String::new(),
        license: String::new(),
        needs: Default::default(),
        settings_schema: None,
        schema_derived: false,
        host: None,
        declares: serde_json::from_str(declares).expect("declares.json parses"),
    };
    PluginRegistry::empty()
        .link(vec![LinkedPlugin::boundary(manifest, entry)])
        .expect("the linked door admits it")
}

/// The statement the linked row makes for `ALIAS` — what the tarball must state too.
fn statement(registry: &PluginRegistry) -> Manifest {
    registry
        .resolve(ALIAS)
        .expect("the webhook row")
        .manifest
        .clone()
}

/// THE DROPPED-IN DOOR: `lib` signed by the release key under `manifest` into a fresh `plugins/`.
fn dropped_door(tag: &str, mut manifest: Manifest, lib: &[u8]) -> PluginRegistry {
    let dir =
        std::env::temp_dir().join(format!("export-webhook-conf-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let release = SigningKey::from_bytes(&[9u8; 32]);
    manifest.sha256 = busbar_plugin_loader::sign::sha256_hex(lib);
    let signed = sign(&release, manifest, lib);
    let tarball = busbar_plugin_loader::tarball::package(&signed, "libwebhook.so", lib).unwrap();
    std::fs::write(dir.join("webhook.tar.gz"), tarball).unwrap();
    let policy = TrustPolicy {
        first_party_key: Some(release.verifying_key()),
        binary_version: VERSION.into(),
        first_party_floors: Default::default(),
        first_party_high_water: Default::default(),
        publishers: Default::default(),
        allow_unsigned: false,
        allow_third_party: false,
        min_versions: Default::default(),
    };
    let registry = busbar_plugin_loader::scan_and_validate(&dir, &policy).expect("the scan");
    let _ = std::fs::remove_dir_all(&dir);
    registry
}

/// What the host folded for `plugin` since the record was cleared — only its own entries.
fn folded_for(plugin: &str) -> Vec<Value> {
    let folded = FOLDED.lock().unwrap();
    folded
        .iter()
        .filter(|f| f["plugin"] == plugin)
        .cloned()
        .collect()
}

/// The requests the carrier was asked to make to this test's own targets.
fn carried_here() -> Vec<Value> {
    let targets = [
        "//siem.example/",
        "@siem.example/",
        "//hooks.internal.example/",
    ];
    let carried = CARRIED.lock().unwrap();
    let ours = |r: &&Value| {
        targets
            .iter()
            .any(|t| r["url"].as_str().unwrap_or("").contains(t))
    };
    carried.iter().filter(ours).cloned().collect()
}

/// One script against the `request-log-webhook` row of `registry`: everything the host saw.
fn transcript(registry: &PluginRegistry) -> Value {
    CARRIED.lock().unwrap().clear();
    FOLDED.lock().unwrap().clear();
    let good = json!({
        "url": "https://user:pw@siem.example/in",
        "auth_header": {"name": "Authorization", "value": "Bearer x"},
        "delivery_timeout_secs": 3,
        "max_inflight_deliveries": 7
    });
    let refused = json!({"url": "https://hooks.internal.example/in"});
    let failing = json!({"url": "https://siem.example/fail"});
    let validated = (
        registry.validate_export(ALIAS, "w", &json!({"url": "https://a/", "x": 1})),
        registry.check_export(
            ALIAS,
            busbar_plugin_loader::CheckPhase::Instances,
            &[(
                "w".into(),
                json!({"url": "https://a/", "delivery_timeout_secs": 0}),
            )],
        ),
    );
    let open = |settings: &Value| {
        registry
            .open_export(ALIAS, &settings.to_string())
            .expect("opens")
    };
    let live = open(&good);
    let started = (live.start(), open(&refused).start());
    live.deliver(
        ExportStream::Logs,
        &json!({"ts": 1, "pool": "p", "outcome": "ok"}),
    )
    .unwrap();
    let failing = open(&failing);
    let _ = failing.start();
    failing
        .deliver(ExportStream::Logs, &json!({"ts": 2}))
        .unwrap();
    live.shed();
    json!({
        "validated": format!("{validated:?}"),
        "started": format!("{started:?}"),
        "streams": format!("{:?}", live.streams()),
        "carried": carried_here(),
        "folded": folded_for(live.name()),
    })
}

/// The linked and the dropped-in webhook sink register one statement and hand the host
/// byte-identical transcripts; the RED arms diverge.
#[test]
fn the_linked_and_the_dropped_in_webhook_sink_are_one_plugin() {
    let _guard = installed();
    let linked = linked_door();
    let lib = cdylib();
    let dropped = dropped_door("both", statement(&linked), &lib);
    let (a, b) = (statement(&linked), statement(&dropped));
    assert_eq!(a.name, "busbar-export-webhook");
    let same = |m: &Manifest| {
        (
            m.name.clone(),
            m.alias.clone(),
            m.kind.clone(),
            m.declares.clone(),
        )
    };
    assert_eq!(same(&a), same(&b), "both doors state the same plugin");

    let linked_run = transcript(&linked);
    let dropped_run = transcript(&dropped);
    // What the host sees, spelled out once so the equality below is about the right thing.
    let text = linked_run.to_string();
    for want in [
        r#""url":"https://user:pw@siem.example/in""#,
        r#"["content-type","application/json"],["Authorization","Bearer x"]"#,
        r#""timeout_ms":3000"#,
        "BUSBAR-7070",
        "refused target 'https://hooks.internal.example/in'; disabling this webhook exporter",
        "BUSBAR-7071",
        r#""status":"503""#,
        r#""webhook_url":"\"https://siem.example/fail\"""#,
        r#""name":"busbar_webhook_logs_dropped_total""#,
        "Some((true, 7, \\\"webhook\\\"))",
        "Some((false, 0, \\\"webhook\\\"))",
        "unknown field `x`",
        "(#0) sets settings.delivery_timeout_secs: 0",
    ] {
        assert!(
            text.contains(want),
            "linked transcript lacks {want}: {text}"
        );
    }
    assert_eq!(linked_run, dropped_run, "the two doors are one plugin");

    // RED ARM 1: a tarball without the declaration the linked row states is a different plugin —
    // its shed counter is not granted, so the host's fold of a shed delivery differs.
    let mut undeclared = statement(&linked);
    undeclared.name = "busbar-export-webhook-undeclared".into();
    undeclared.alias = "request-log-webhook-undeclared".into();
    undeclared.declares = Default::default();
    let bare = dropped_door("undeclared", undeclared, &lib);
    let sink = bare
        .open_export(
            "request-log-webhook-undeclared",
            r#"{"url":"https://a.example/"}"#,
        )
        .expect("opens");
    FOLDED.lock().unwrap().clear();
    sink.shed();
    let folded = folded_for(sink.name());
    assert!(
        folded
            .iter()
            .all(|f| f["metrics"].as_array().is_none_or(Vec::is_empty)),
        "an undeclared shed counter must not be granted: {folded:?}"
    );

    // RED ARM 2: without the linked row the module is not on the axis.
    assert!(PluginRegistry::empty().resolve(ALIAS).is_none());
    assert!(PluginRegistry::empty()
        .validate_export(ALIAS, "w", &json!({}))
        .is_none());
}
