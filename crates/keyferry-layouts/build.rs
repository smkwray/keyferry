use std::{env, fs, path::PathBuf};

fn main() {
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest directory"));
    let registry = manifest.join("../../protocol/keyboard-key-registry-v1.csv");
    println!("cargo:rerun-if-changed={}", registry.display());

    let source = fs::read_to_string(&registry).expect("read keyboard key registry");
    let mut lines = source.lines().filter(|line| !line.starts_with('#'));
    assert_eq!(
        lines.next(),
        Some("name,class,code,portability"),
        "keyboard key registry header"
    );
    let mut generated = String::from("pub const KEYBOARD_KEYS: &[KeyboardKey] = &[\n");
    let mut count = 0usize;
    for line in lines.filter(|line| !line.is_empty()) {
        let fields: Vec<_> = line.split(',').collect();
        assert_eq!(fields.len(), 4, "keyboard key registry row: {line}");
        let class = match fields[1] {
            "modifier" => "KeyClass::Modifier",
            "non-modifier" => "KeyClass::NonModifier",
            value => panic!("invalid key class: {value}"),
        };
        let portability = match fields[3] {
            "boot-common" => "KeyPortability::BootCommon",
            "report-extended" => "KeyPortability::ReportExtended",
            value => panic!("invalid key portability: {value}"),
        };
        let code =
            u8::from_str_radix(fields[2].trim_start_matches("0x"), 16).expect("keyboard key code");
        generated.push_str(&format!(
            "    KeyboardKey {{ name: {:?}, class: {class}, code: 0x{code:02X}, portability: {portability} }},\n",
            fields[0]
        ));
        count += 1;
    }
    assert_eq!(count, 211, "keyboard key registry entry count");
    generated.push_str("];\n");
    let output = PathBuf::from(env::var_os("OUT_DIR").expect("output directory"))
        .join("keyboard_key_registry.rs");
    fs::write(output, generated).expect("write generated keyboard key registry");
}
