use std::{
    path::Path,
    process::{Command, Output},
};

const NAMESPACE: &str = concat!(
    "4a4a4a4a4a4a4a4a",
    "4a4a4a4a4a4a4a4a",
    "4a4a4a4a4a4a4a4a",
    "4a4a4a4a4a4a4a4a",
);
fn command(root: &Path, backend: &str, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_radio"))
        .arg("--database")
        .arg(root.join("bbg"))
        .args(["--backend", backend, "--namespace", NAMESPACE])
        .args(args)
        .output()
        .unwrap()
}
fn ok(root: &Path, backend: &str, args: &[&str]) -> String {
    let output = command(root, backend, args);
    assert!(
        output.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}
fn fails(root: &Path, backend: &str, args: &[&str]) {
    let output = command(root, backend, args);
    assert!(!output.status.success(), "unexpected success: {args:?}");
    assert!(
        output.stdout.is_empty(),
        "failed mutation must not print a committed head"
    );
}
fn field<'a>(text: &'a str, label: &str) -> &'a str {
    text.lines()
        .find_map(|line| line.strip_prefix(label))
        .unwrap()
        .trim()
}

#[test]
fn names_preserve_revisions_and_retries_across_real_cli_processes() {
    for backend in ["ssd", "hdd"] {
        let root = tempfile::tempdir().unwrap();
        let root = root.path();
        let first_path = root.join("first.bin");
        let second_path = root.join("second.bin");
        std::fs::write(&first_path, b"original payload").unwrap();
        std::fs::write(&second_path, b"edited payload").unwrap();
        let first = ok(
            root,
            backend,
            &["file", "add", first_path.to_str().unwrap()],
        )
        .trim()
        .to_owned();
        let second = ok(
            root,
            backend,
            &["file", "add", second_path.to_str().unwrap()],
        )
        .trim()
        .to_owned();
        let req1 = format!("{:064x}", 1);
        let req2 = format!("{:064x}", 2);
        let req3 = format!("{:064x}", 3);
        let create = ok(
            root,
            backend,
            &["name", "set", "notes/start", &first, "--request", &req1],
        );
        assert!(create.starts_with("0 "));
        let original = ok(root, backend, &["name", "resolve", "notes/start"]);
        assert_eq!(field(&original, "particle"), first);
        let rename = ok(
            root,
            backend,
            &[
                "name",
                "rename",
                "notes/start",
                "archive/moved",
                "--expected",
                "0",
                "--request",
                &req2,
            ],
        );
        assert!(rename.starts_with("1 "));
        assert_eq!(
            ok(root, backend, &["name", "resolve", "archive/moved"]),
            original
        );
        fails(root, backend, &["name", "resolve", "notes/start"]);
        assert_eq!(
            ok(
                root,
                backend,
                &["name", "resolve", "notes/start", "--at", "0"]
            ),
            original
        );
        let edit = ok(
            root,
            backend,
            &[
                "name",
                "set",
                "archive/moved",
                &second,
                "--expected",
                "1",
                "--request",
                &req3,
            ],
        );
        assert!(edit.starts_with("2 "));
        let revised = ok(root, backend, &["name", "resolve", "archive/moved"]);
        assert_eq!(field(&revised, "particle"), second);
        assert_eq!(field(&revised, "binding"), field(&original, "binding"));
        assert_ne!(field(&revised, "revision"), field(&original, "revision"));
        assert_eq!(
            ok(
                root,
                backend,
                &["name", "resolve", "archive/moved", "--at", "1"]
            ),
            original
        );
        let old_listing = ok(root, backend, &["name", "list", "--at", "0"]);
        assert!(old_listing.contains("\"notes/start\""));
        assert!(old_listing.starts_with(&first));
        let current_listing = ok(root, backend, &["name", "list"]);
        assert!(current_listing.contains("\"archive/moved\""));
        assert!(current_listing.starts_with(&second));
        // Reconstruct original operations even after later revisions selected another path.
        assert_eq!(
            ok(
                root,
                backend,
                &["name", "set", "notes/start", &first, "--request", &req1]
            ),
            create
        );
        assert_eq!(
            ok(
                root,
                backend,
                &[
                    "name",
                    "rename",
                    "notes/start",
                    "archive/moved",
                    "--expected",
                    "0",
                    "--request",
                    &req2
                ]
            ),
            rename
        );
        assert_eq!(
            ok(
                root,
                backend,
                &[
                    "name",
                    "set",
                    "archive/moved",
                    &second,
                    "--expected",
                    "1",
                    "--request",
                    &req3
                ]
            ),
            edit
        );
        fails(
            root,
            backend,
            &["name", "set", "notes/start", &second, "--request", &req1],
        );
        fails(
            root,
            backend,
            &["name", "rename", "notes/start", "stale", "--expected", "0"],
        );
        fails(
            root,
            backend,
            &["name", "set", "archive/moved", &first, "--expected", "1"],
        );
        assert_eq!(
            ok(root, backend, &["name", "history", "--limit", "2"]),
            format!("{create}{rename}")
        );
        assert_eq!(
            ok(
                root,
                backend,
                &["name", "history", "--after", "1", "--limit", "2"]
            ),
            edit
        );
        let removed = ok(
            root,
            backend,
            &["name", "remove", "archive/moved", "--expected", "2"],
        );
        assert!(removed.starts_with("3 "));
        assert!(ok(root, backend, &["name", "list"]).is_empty());
        assert_eq!(
            ok(
                root,
                backend,
                &["name", "resolve", "archive/moved", "--at", "2"]
            ),
            revised
        );
        let exported = root.join("restored.bin");
        ok(
            root,
            backend,
            &[
                "file",
                "export",
                &first,
                "--out",
                exported.to_str().unwrap(),
            ],
        );
        assert_eq!(std::fs::read(exported).unwrap(), b"original payload");
    }
}

#[test]
fn names_reject_bad_paths_missing_payloads_and_unknown_history_without_publishing() {
    for backend in ["ssd", "hdd"] {
        let root = tempfile::tempdir().unwrap();
        let root = root.path();
        let missing = format!("{:064x}", 999);
        fails(root, backend, &["name", "set", "../outside", &missing]);
        fails(root, backend, &["name", "set", "notes/missing", &missing]);
        fails(root, backend, &["name", "resolve", "missing", "--at", "0"]);
        fails(
            root,
            backend,
            &["name", "list", "--at", "18446744073709551615"],
        );
        fails(root, backend, &["name", "history", "--limit", "0"]);
        fails(root, backend, &["name", "history", "--limit", "4097"]);
        assert!(ok(root, backend, &["name", "history"]).is_empty());
        assert!(ok(root, backend, &["name", "list"]).is_empty());
    }
}
