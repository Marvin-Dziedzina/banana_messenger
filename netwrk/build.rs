fn main() {
    set_version_marjor_minor();
}

fn set_version_marjor_minor() {
    let version = env!("CARGO_PKG_VERSION").to_string();
    let major_minor = match version.rfind('.') {
        Some(pos) => &version[..pos],
        None => panic!("Version invalid"),
    };
    println!("cargo:rustc-env=VERSION_MAJOR_MINOR={}", major_minor);
}
