use std::{fs, path::PathBuf};

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("remota-server lives below the repository root")
        .to_path_buf()
}

#[test]
fn updater_vnc_tauri_plugins_and_relay_are_absent() {
    let root = repository_root();
    for path in [
        "server/agent/Cargo.toml",
        "server/relay/Cargo.toml",
        "server/proto/Cargo.toml",
        "src/components/UpdateBanner.tsx",
        "src/lib/useUpdate.ts",
        "src/renderers/VncView.tsx",
        "src-tauri/src/gateway/relay.rs",
        "src-tauri/src/update.rs",
        ".github/workflows/release.yml",
        "scripts/build-update-manifest.py",
        "scripts/deploy-app.sh",
        "packaging",
    ] {
        assert!(!root.join(path).exists(), "removed feature remains: {path}");
    }

    let package = fs::read_to_string(root.join("package.json")).expect("read package.json");
    for dependency in [
        "@novnc/novnc",
        "@tauri-apps/plugin-clipboard-manager",
        "@tauri-apps/plugin-dialog",
        "@tauri-apps/plugin-opener",
        "@tauri-apps/plugin-process",
        "@tauri-apps/plugin-updater",
    ] {
        assert!(
            !package.contains(dependency),
            "removed dependency remains: {dependency}"
        );
    }

    let frontend = fs::read_to_string(root.join("src/App.tsx")).expect("read App.tsx");
    assert!(!frontend.to_ascii_lowercase().contains("relay"));
    assert!(!frontend.to_ascii_lowercase().contains("update"));
}
