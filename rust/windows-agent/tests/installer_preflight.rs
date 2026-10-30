use std::process::Command;

#[test]
fn public_preflight_never_creates_installation_or_identity_state() {
    let directory = tempfile::tempdir().unwrap();
    for (origin, success) in [
        ("https://manager.example:9443", true),
        ("http://manager.example:9443", false),
        ("https://manager.example:9443/path", false),
        ("https://user:password@manager.example", false),
    ] {
        let result = Command::new(env!("CARGO_BIN_EXE_tracebolt-windows-agent"))
            .args(["validate-config", "--manager-origin", origin])
            .current_dir(directory.path())
            .output()
            .unwrap();
        assert_eq!(result.status.success(), success);
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
        assert!(!String::from_utf8_lossy(&result.stderr).contains("password"));
    }
    let ca = directory.path().join("invalid-ca.pem");
    std::fs::write(&ca, b"not a certificate").unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_tracebolt-windows-agent"))
        .args([
            "validate-config",
            "--manager-origin",
            "https://manager.example:9443",
            "--server-ca-file",
        ])
        .arg(ca)
        .current_dir(directory.path())
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
}
