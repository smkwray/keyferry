fn main() {
    #[cfg(target_os = "windows")]
    {
        println!("cargo:rerun-if-changed=keyferry.rc");
        println!("cargo:rerun-if-changed=assets/icons/keyferry.ico");
        embed_resource::compile_for("keyferry.rc", ["keyferry"], embed_resource::NONE)
            .manifest_required()
            .expect("failed to embed the Windows application icon");
    }

    let config = slint_build::CompilerConfiguration::new().with_style("fluent-dark".into());
    slint_build::compile_with_config("ui/main.slint", config).expect("failed to compile Slint UI");
}
