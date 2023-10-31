// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/// Minijail's build script invoked by cargo.
///
/// This script prefers linking against a pkg-config provided libminijail, but will fall back to
/// building libminijail statically.
use std::env;
use std::fs::remove_file;
use std::io;
use std::path::Path;
use std::process::Command;

fn get_bindgen_cmd() -> Command {
    let bindgen = which::which("bindgen").unwrap();

    let mut cmd = Command::new(bindgen);
    cmd.args(["--default-enum-style", "rust"]);
    cmd.args(["--blocklist-type", "__rlim64_t"]);
    cmd.args(["--raw-line", "pub type __rlim64_t = u64;"]);
    cmd.args(["--blocklist-type", "__u\\d{1,2}"]);
    cmd.args(["--raw-line", "pub type __u8 = u8;"]);
    cmd.args(["--raw-line", "pub type __u16 = u16;"]);
    cmd.args(["--raw-line", "pub type __u32 = u32;"]);
    cmd.arg("--no-layout-tests");
    cmd.arg("--disable-header-comment");

    cmd
}

fn generate_crossystem_bindings() -> io::Result<()> {
    let out_dir = env::var("OUT_DIR").unwrap();
    let gen_file = Path::new(&out_dir).join("./crossystem.rs");
    if gen_file.exists() {
        remove_file(&gen_file).expect("Failed to remove generated file.");
    }
    let header_dir = Path::new(".");
    let crosssystem_header_path = header_dir.join("crossystem.h");
    println!(
        "cargo:rerun-if-changed={}",
        crosssystem_header_path.display()
    );
    let mut bindgen_cmd = get_bindgen_cmd();
    bindgen_cmd.args(["--blocklist-type", "__uint64_t"]);
    bindgen_cmd.args(["--output", gen_file.to_str().unwrap()]);
    bindgen_cmd.arg(crosssystem_header_path.to_str().unwrap());
    bindgen_cmd.args([
        "--",
        "-DUSE_BINDGEN",
        "-D_FILE_OFFSET_BITS=64",
        "-D_LARGEFILE_SOURCE",
        "-D_LARGEFILE64_SOURCE",
    ]);

    assert!(bindgen_cmd.status()?.success());

    Ok(())
}

fn generate_vboot_host_binding() -> io::Result<()> {
    let out_dir = env::var("OUT_DIR").unwrap();
    let gen_file = Path::new(&out_dir).join("./vboot_host.rs");
    if gen_file.exists() {
        remove_file(&gen_file).expect("Failed to remove generated file.");
    }
    let header_dir = Path::new(".");
    let header_path = header_dir.join("vboot_host.h");
    println!("cargo:rerun-if-changed={}", header_path.display());
    for file in std::fs::read_dir("include")? {
        println!("cargo:rerun-if-changed={}", file?.path().display());
    }

    let mut bindgen_cmd = get_bindgen_cmd();
    // Some functions or types define a `long double`, which is turned into u128
    // by bindgen, which is not FFI-safe. See
    // https://github.com/rust-lang/rust-bindgen/issues/1549 for more information.
    bindgen_cmd.args(["--blocklist-function", "qfcvt"]);
    bindgen_cmd.args(["--blocklist-function", "qgcvt"]);
    bindgen_cmd.args(["--blocklist-function", "qecvt"]);
    bindgen_cmd.args(["--blocklist-function", "qecvt_r"]);
    bindgen_cmd.args(["--blocklist-function", "qfcvt_r"]);
    bindgen_cmd.args(["--blocklist-function", "strtold"]);
    bindgen_cmd.args(["--blocklist-type", "_Float64x"]);
    bindgen_cmd.args(["--blocklist-type", "max_align_t"]);

    bindgen_cmd.arg("--no-size_t-is-usize");
    bindgen_cmd.args(["--output", gen_file.to_str().unwrap()]);
    bindgen_cmd.arg(header_path.to_str().unwrap());
    bindgen_cmd.args([
        "--",
        "-DUSE_BINDGEN",
        "-D_FILE_OFFSET_BITS=64",
        "-D_LARGEFILE_SOURCE",
        "-D_LARGEFILE64_SOURCE",
        "-Iinclude",
    ]);
    assert!(bindgen_cmd.status()?.success());

    Ok(())
}

fn main() -> io::Result<()> {
    pkg_config::Config::new().probe("vboot_host").unwrap();
    generate_crossystem_bindings()?;
    generate_vboot_host_binding()
}
