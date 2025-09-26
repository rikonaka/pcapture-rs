use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=wrapper.h");

    if cfg!(target_os = "linux") || cfg!(target_os = "android") {
        println!("cargo:rustc-link-lib=pcap");
    } else if cfg!(target_os = "macos") {
        println!("cargo:rustc-link-lib=pcap");
    } else if cfg!(target_os = "windows") {
        // windows use npcap
        println!("cargo:rustc-link-lib=wpcap");
        println!("cargo:rustc-link-lib=Packet");
    }

    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .allowlist_function("pcap_.*")
        .allowlist_type("pcap_.*")
        .allowlist_var("PCAP_.*")
        .generate_inline_functions(true)
        .generate_comments(true)
        .clang_arg("-Wno-everything")
        .generate()
        .expect("Unable to generate libpcap bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
