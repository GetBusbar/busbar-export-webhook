// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SINK HOLDS NO `unsafe` (THE DESIGN §2 l.300-303, §11.5): its lent memory is read and written
//! through the SDK's safe lend, so no source file allows `unsafe_code` or spells an `unsafe` block.
//! RED before `instances` read check's list through raw pointers (Q128 export-webhook LOW).

#[test]
fn no_source_file_allows_or_spells_unsafe() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut stack = vec![src];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("src reads") {
            let path = entry.expect("an entry").path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("a source file");
            for (n, line) in text.lines().enumerate() {
                let code = line.split("//").next().unwrap_or("");
                assert!(
                    !code.contains("allow(unsafe_code)")
                        && !code.contains("unsafe {")
                        && !code.contains("unsafe fn"),
                    "{}:{}: {line}",
                    path.display(),
                    n + 1
                );
            }
        }
    }
}
