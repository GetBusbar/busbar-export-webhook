// SPDX-License-Identifier: Apache-2.0
//! The artifact built with `--features dropped-in` immediately before this test run.
pub fn cdylib_of() -> std::path::PathBuf {
    let path = std::env::var_os("BUSBAR_PLUGIN_CDYLIB")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            let exe = std::env::current_exe().expect("test executable");
            exe.parent()
                .and_then(std::path::Path::parent)
                .expect("target/profile/deps")
                .join(format!(
                    "{}busbar_export_webhook_plugin{}",
                    std::env::consts::DLL_PREFIX,
                    std::env::consts::DLL_SUFFIX
                ))
        });
    assert!(
        path.is_absolute(),
        "BUSBAR_PLUGIN_CDYLIB must name an absolute artifact path"
    );
    assert!(
        path.is_file(),
        "build busbar-export-webhook-plugin with --features dropped-in before testing; missing {}",
        path.display()
    );
    path
}
