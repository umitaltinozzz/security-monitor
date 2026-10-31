include!("src/ipc_commands.rs");

fn main() {
    println!("cargo:rerun-if-changed=src/ipc_commands.rs");
    println!("cargo:rerun-if-changed=capabilities/main.json");
    let attributes = tauri_build::Attributes::new()
        .app_manifest(tauri_build::AppManifest::new().commands(APP_COMMANDS));
    tauri_build::try_build(attributes).expect("failed to build Tauri app command permissions");
}
