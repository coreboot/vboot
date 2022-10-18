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

fn bindings_generation() -> io::Result<()> {
    let bindgen = which::which("bindgen").unwrap();

    let out_dir = env::var("OUT_DIR").unwrap();
    let gen_file = Path::new(&out_dir).join("./crossystem.rs");
    if gen_file.exists() {
        remove_file(&gen_file).expect("Failed to remove generated file.");
    }
    let header_dir = Path::new(".");
    let header_path = header_dir.join("crossystem.h");
    println!("cargo:rerun-if-changed={}", header_path.display());
    let status = Command::new(&bindgen)
        .args(&["--default-enum-style", "rust"])
        .args(&["--blacklist-type", "__rlim64_t"])
        .args(&["--raw-line", "pub type __rlim64_t = u64;"])
        .args(&["--blacklist-type", "__u\\d{1,2}"])
        .args(&["--raw-line", "pub type __u8 = u8;"])
        .args(&["--raw-line", "pub type __u16 = u16;"])
        .args(&["--raw-line", "pub type __u32 = u32;"])
        .args(&["--blacklist-type", "__uint64_t"])
        .arg("--no-layout-tests")
        .arg("--disable-header-comment")
        .args(&["--output", gen_file.to_str().unwrap()])
        .arg(header_path.to_str().unwrap())
        .args(&[
            "--",
            "-DUSE_BINDGEN",
            "-D_FILE_OFFSET_BITS=64",
            "-D_LARGEFILE_SOURCE",
            "-D_LARGEFILE64_SOURCE",
        ])
        .status()?;
    assert!(status.success());
    Ok(())
}

fn main() -> io::Result<()> {
    pkg_config::Config::new().probe("vboot_host").unwrap();
    bindings_generation()
}
