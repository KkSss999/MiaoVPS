use std::{env, path::PathBuf, process::Command};

fn main() {
    let manifest_dir =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("missing manifest directory"));
    let workspace_root = manifest_dir
        .join("../../..")
        .canonicalize()
        .expect("failed to locate workspace root");

    // Tauri validates `bundle.externalBin` during this build script. Prepare the
    // target-specific executable first so `cargo build` at the workspace root
    // works without requiring a separate pnpm command.
    println!(
        "cargo:rerun-if-changed={}",
        workspace_root.join("Cargo.lock").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        workspace_root.join("crates").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        workspace_root.join("scripts/prepare-sidecar.sh").display()
    );

    let profile = env::var("PROFILE").expect("missing Cargo profile");
    let target = env::var("TARGET").expect("missing Cargo target");
    let script = workspace_root.join("scripts/prepare-sidecar.sh");
    let sidecar_target_dir = workspace_root.join("target/miaovps-sidecar");

    let status = Command::new("sh")
        .arg(script)
        .arg(profile)
        // A separate target directory prevents the nested Cargo invocation from
        // competing with the workspace build's target-directory lock.
        .env("CARGO_TARGET_DIR", sidecar_target_dir)
        .env("MIAOVPS_SIDECAR_TARGET", target)
        .status()
        .expect("failed to start sidecar preparation");

    assert!(status.success(), "failed to prepare miaovps sidecar");
    tauri_build::build()
}
