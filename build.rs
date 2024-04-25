fn main() {
    cxx_build::bridge("src/lib.rs")
        .file("src/yapi.cxx")
        .include("include")
        .flag_if_supported("-std=c++17")
        .compile("yapi"); 

    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=src/yapi.h");
    println!("cargo:rerun-if-changed=src/yapi.hpp");
    println!("cargo:rerun-if-changed=src/yapi.cxx");
}