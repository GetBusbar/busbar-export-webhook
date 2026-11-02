// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SINK HOLDS NO `unsafe` (THE DESIGN §2 l.300-303, §11.5): its lent memory is read and written
//! through the SDK's safe lend, so no source file allows `unsafe_code` or spells an `unsafe` block.
//! RED before `instances` read check's list through raw pointers (Q128 export-webhook LOW).

#[test]
fn no_source_file_allows_or_spells_unsafe() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let root = std::fs::read_to_string(src.join("lib.rs")).expect("lib.rs reads");
    assert!(
        root.lines().any(|l| l.trim() == "#![forbid(unsafe_code)]"),
        "the crate root must forbid unsafe_code"
    );
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
                let squashed: String = code.split_whitespace().collect::<Vec<_>>().join(" ");
                let spells_unsafe = squashed.match_indices("unsafe").any(|(i, _)| {
                    let before_ok = !squashed[..i]
                        .chars()
                        .next_back()
                        .is_some_and(|c| c.is_alphanumeric() || c == '_');
                    let rest = squashed[i + 6..].trim_start();
                    before_ok
                        && (rest.starts_with('{')
                            || ["impl", "trait", "fn", "extern"].iter().any(|k| {
                                rest.strip_prefix(k).is_some_and(|r| {
                                    !r.starts_with(|c: char| c.is_alphanumeric() || c == '_')
                                })
                            }))
                });
                assert!(
                    !code.contains("allow(unsafe_code)") && !spells_unsafe,
                    "{}:{}: {line}",
                    path.display(),
                    n + 1
                );
            }
        }
    }
}
