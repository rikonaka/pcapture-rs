#[cfg(unix)]
use std::env;
#[cfg(unix)]
use std::path::PathBuf;

#[cfg(unix)]
fn main() {
    println!("cargo:rerun-if-changed=wrapper.h");
    println!("cargo:rustc-link-lib=pcap");

    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .allowlist_function("pcap_.*")
        .allowlist_type("pcap_.*")
        .allowlist_var("PCAP_.*")
        .generate_inline_functions(true)
        .generate_comments(true)
        .clang_arg("-Wno-everything")
        .generate()
        .expect("Unable to generate libpcap bindings on Unix");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}

#[cfg(windows)]
fn main() {}

// Generate bindings for Npcap on Windows, using the Npcap SDK specified
// by the environment variables `NPCAP_SDK_INCLUDE` and `NPCAP_SDK_LIB`.
// `NPCAP_SDK_INCLUDE` should point to the include directory (where pcap.h is),
// and `NPCAP_SDK_LIB` should point to the lib directory (where wpcap.lib, Packet.lib are).
// Windows builds still have some problems, so this is disabled by default.
//
// #[cfg(windows)]
// fn main() {
//     println!("cargo:rerun-if-changed=wrapper.h");
//     println!("cargo:rustc-link-lib=wpcap");
//     println!("cargo:rustc-link-lib=Packet");
//
//     let npcapsdk_include = env::var("NPCAP_SDK_INCLUDE")
//         .expect("Please set NPCAP_SDK_INCLUDE to Npcap SDK include directory (where pcap.h is)");
//     let npcapsdk_lib = env::var("NPCAP_SDK_LIB").expect(
//         "Please set NPCAP_SDK_LIB to Npcap SDK lib directory (where wpcap.lib, Packet.lib are)",
//     );
//
//     println!("cargo:rustc-link-search=native={npcapsdk_lib}\\x64");
//
//     let bindings = bindgen::Builder::default()
//         .header("wrapper.h")
//         .allowlist_function("pcap_.*")
//         .allowlist_type("pcap_.*")
//         .allowlist_var("PCAP_.*")
//         .generate_inline_functions(true)
//         .generate_comments(true)
//         .clang_arg("-Wno-everything")
//         .clang_arg(format!("-I{npcapsdk_include}"))
//         .generate()
//         .expect("Unable to generate libpcap (Npcap) bindings on Windows");
//
//     let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
//     bindings
//         .write_to_file(out_path.join("bindings.rs"))
//         .expect("Couldn't write bindings!");
// }
