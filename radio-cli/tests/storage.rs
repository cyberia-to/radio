use std::{
    io::{BufRead, BufReader},
    path::Path,
    process::{Child, Command, Output, Stdio},
    sync::mpsc,
    time::Duration,
};

const NAMESPACE: &str = "0101010101010101010101010101010101010101010101010101010101010101";
fn command(path: &Path, backend: &str) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_radio"));
    cmd.args([
        "--database",
        path.to_str().unwrap(),
        "--namespace",
        NAMESPACE,
        "--backend",
        backend,
    ]);
    cmd.env_remove("RADIO_SECRET");
    cmd
}
fn success(output: Output) -> String {
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}
struct Server(Child);
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn serve(path: &Path, backend: &str, permission: &[&str]) -> (Server, String, String) {
    let mut child = command(path, backend)
        .args(["node", "start", "--local"])
        .args(permission)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let output = child.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(output).lines() {
            if tx.send(line.unwrap()).is_err() {
                break;
            }
        }
    });
    let server = Server(child);
    let mut peer = None;
    let addr = loop {
        let line = rx
            .recv_timeout(Duration::from_secs(15))
            .expect("server readiness timeout");
        if let Some(value) = line.strip_prefix("endpoint id: ") {
            peer = Some(value.to_string());
        }
        if let Some(value) = line.strip_prefix("direct address: ") {
            if !value.starts_with('[') {
                let address: std::net::SocketAddr = value.parse().unwrap();
                break format!("127.0.0.1:{}", address.port());
            }
        }
    };
    (server, peer.unwrap(), addr)
}

#[test]
fn add_list_export_and_hash_agree_across_invocations_for_both_profiles() {
    for backend in ["ssd", "hdd"] {
        let temp = tempfile::tempdir().unwrap();
        let db = temp.path().join("bbg");
        assert!(
            success(
                command(&db, backend)
                    .args(["blob", "list"])
                    .output()
                    .unwrap()
            )
            .contains("no files")
        );
        for bytes in [vec![], (0..131_079).map(|i| (i * 17) as u8).collect()] {
            let input = temp.path().join("input");
            let out = temp.path().join("output");
            std::fs::write(&input, &bytes).unwrap();
            let particle = success(
                command(&db, backend)
                    .args(["file", "add", input.to_str().unwrap()])
                    .output()
                    .unwrap(),
            );
            let duplicate = success(
                command(&db, backend)
                    .args(["blob", "add", input.to_str().unwrap()])
                    .output()
                    .unwrap(),
            );
            assert_eq!(particle, duplicate);
            let listed = success(
                command(&db, backend)
                    .args(["file", "list"])
                    .output()
                    .unwrap(),
            );
            assert_eq!(
                listed
                    .lines()
                    .filter(|line| line.starts_with(&particle))
                    .count(),
                1
            );
            success(
                command(&db, backend)
                    .args(["file", "export", &particle, "--out", out.to_str().unwrap()])
                    .output()
                    .unwrap(),
            );
            assert_eq!(std::fs::read(&out).unwrap(), bytes);
            assert!(
                !command(&db, backend)
                    .args(["file", "export", &particle, "--out", out.to_str().unwrap()])
                    .output()
                    .unwrap()
                    .status
                    .success()
            );
            assert_eq!(std::fs::read(&out).unwrap(), bytes);
            let sum = success(
                Command::new(env!("CARGO_BIN_EXE_radio"))
                    .args(["hash", "sum", input.to_str().unwrap()])
                    .output()
                    .unwrap(),
            );
            assert_eq!(sum, particle);
            success(
                Command::new(env!("CARGO_BIN_EXE_radio"))
                    .args(["hash", "verify", input.to_str().unwrap(), &particle])
                    .output()
                    .unwrap(),
            );
            std::fs::remove_file(&out).unwrap();
        }
        let other_scope = success(
            Command::new(env!("CARGO_BIN_EXE_radio"))
                .args([
                    "--database",
                    db.to_str().unwrap(),
                    "--backend",
                    backend,
                    "--namespace",
                    &"02".repeat(32),
                    "file",
                    "list",
                ])
                .output()
                .unwrap(),
        );
        assert!(other_scope.contains("no files"));
    }
}

#[test]
fn command_line_transfer_uses_bbg_across_profiles_and_survives_server_exit() {
    for (source, destination) in [("ssd", "hdd"), ("hdd", "ssd")] {
        let temp = tempfile::tempdir().unwrap();
        let source_db = temp.path().join("source");
        let target_db = temp.path().join("target");
        let input = temp.path().join("input");
        let bytes: Vec<_> = (0..196_617).map(|i| (i * 31) as u8).collect();
        std::fs::write(&input, &bytes).unwrap();
        let particle = success(
            command(&source_db, source)
                .args(["file", "add", input.to_str().unwrap()])
                .output()
                .unwrap(),
        );
        // Empty files need descriptor lookup even though they have no ranges.
        let empty = temp.path().join("empty");
        std::fs::write(&empty, []).unwrap();
        let empty_particle = success(
            command(&source_db, source)
                .args(["file", "add", empty.to_str().unwrap()])
                .output()
                .unwrap(),
        );
        let (server, peer, addr) = serve(&source_db, source, &["--public"]);
        for id in [&particle, &empty_particle] {
            let out = temp.path().join(format!("received-{id}"));
            success(
                command(&target_db, destination)
                    .args([
                        "file",
                        "get",
                        id,
                        &peer,
                        "--addr",
                        &addr,
                        "--local",
                        "--out",
                        out.to_str().unwrap(),
                    ])
                    .output()
                    .unwrap(),
            );
            assert_eq!(
                std::fs::read(&out).unwrap(),
                if *id == particle {
                    bytes.as_slice()
                } else {
                    &[]
                }
            );
        }
        drop(server); // Abrupt process exit, then read both independent owners offline.
        for (db, backend) in [(&source_db, source), (&target_db, destination)] {
            let out = temp.path().join(format!("offline-{backend}"));
            success(
                command(db, backend)
                    .args(["file", "export", &particle, "--out", out.to_str().unwrap()])
                    .output()
                    .unwrap(),
            );
            assert_eq!(std::fs::read(out).unwrap(), bytes);
        }
        assert!(!temp.path().join("blobs").exists());
        assert!(!temp.path().join("docs.redb").exists());
    }
}

#[test]
fn private_serving_is_explicit_and_unauthorized_reads_leave_no_sealed_file() {
    let temp = tempfile::tempdir().unwrap();
    let db = temp.path().join("source");
    assert!(
        !command(&db, "ssd")
            .args(["node", "start", "--local"])
            .output()
            .unwrap()
            .status
            .success()
    );
    let input = temp.path().join("input");
    std::fs::write(&input, b"private fixture").unwrap();
    let particle = success(
        command(&db, "ssd")
            .args(["file", "add", input.to_str().unwrap()])
            .output()
            .unwrap(),
    );
    let permitted = iroh::SecretKey::from_bytes(&[42; 32]).public().to_string();
    let (server, peer, addr) = serve(&db, "ssd", &["--allow-peer", &permitted]);
    let target = temp.path().join("target");
    let out = temp.path().join("out");
    let result = command(&target, "ssd")
        .args([
            "file",
            "get",
            &particle,
            &peer,
            "--addr",
            &addr,
            "--local",
            "--out",
            out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(!out.exists());
    assert!(
        success(
            command(&target, "ssd")
                .args(["file", "list"])
                .output()
                .unwrap()
        )
        .contains("no files")
    );
    // Explicitly authorized endpoint can read the same private namespace.
    let mut authorized = command(&target, "ssd");
    authorized.env("RADIO_SECRET", data_encoding::HEXLOWER.encode(&[42; 32]));
    success(
        authorized
            .args([
                "file",
                "get",
                &particle,
                &peer,
                "--addr",
                &addr,
                "--local",
                "--out",
                out.to_str().unwrap(),
            ])
            .output()
            .unwrap(),
    );
    assert_eq!(std::fs::read(&out).unwrap(), b"private fixture");
    drop(server);
    for bad in ["Ж0", "zz", "0"] {
        assert!(
            !command(&target, "ssd")
                .args(["file", "export", bad, "--out", out.to_str().unwrap()])
                .output()
                .unwrap()
                .status
                .success()
        );
    }
}

#[test]
fn recognized_legacy_directories_are_preserved_before_bbg_is_opened() {
    for marker in ["blobs.db", "docs.redb", "blobs/blobs.db"] {
        let temp = tempfile::tempdir().unwrap();
        let original = temp.path().join(marker);
        std::fs::create_dir_all(original.parent().unwrap()).unwrap();
        std::fs::write(&original, b"original legacy bytes").unwrap();
        let result = command(temp.path(), "ssd")
            .args(["file", "list"])
            .output()
            .unwrap();
        assert!(!result.status.success());
        assert!(String::from_utf8_lossy(&result.stderr).contains("verified import"));
        assert_eq!(std::fs::read(&original).unwrap(), b"original legacy bytes");
        assert!(!temp.path().join("bbg.lock").exists());
        assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 1);
    }
}
