use rustc_tools_util::{self, VersionInfo};
/// CLI utility functions
///
/// The code in this module is from clippy. See their copyright.
use std::ops::Deref;
use std::{
    env,
    path::{Path, PathBuf},
    process::{exit, Command},
};

fn toolchain_path(home: Option<String>, toolchain: Option<String>) -> Option<PathBuf> {
    home.and_then(|home| {
        toolchain.map(|toolchain| {
            let mut path = PathBuf::from(home);
            path.push("toolchains");
            path.push(toolchain);
            path
        })
    })
}

/// If a command-line option matches `find_arg`, then apply the predicate `pred` on its value. If
/// true, then return it. The parameter is assumed to be either `--arg=value` or `--arg value`.
fn arg_value<'a, T: Deref<Target = str>>(
    args: &'a [T],
    find_arg: &str,
    pred: impl Fn(&str) -> bool,
) -> Option<&'a str> {
    let mut args = args.iter().map(Deref::deref);
    while let Some(arg) = args.next() {
        let mut arg = arg.splitn(2, '=');
        if arg.next() != Some(find_arg) {
            continue;
        }

        match arg.next().or_else(|| args.next()) {
            Some(v) if pred(v) => return Some(v),
            _ => {},
        }
    }
    None
}

/// Reads the environment and returns arguments
pub fn read_env(mut orig_args: Vec<String>) -> Vec<String> {
    // Get the sysroot, looking from most specific to this invocation to the least:
    // - command line
    // - runtime environment
    //    - SYSROOT
    //    - RUSTUP_HOME, MULTIRUST_HOME, RUSTUP_TOOLCHAIN, MULTIRUST_TOOLCHAIN
    // - sysroot from rustc in the path
    // - compile-time environment
    //    - SYSROOT
    //    - RUSTUP_HOME, MULTIRUST_HOME, RUSTUP_TOOLCHAIN, MULTIRUST_TOOLCHAIN
    let sys_root_arg = arg_value(&orig_args, "--sysroot", |_| true);
    let have_sys_root_arg = sys_root_arg.is_some();
    let sys_root = sys_root_arg
        .map(PathBuf::from)
        .or_else(|| std::env::var("SYSROOT").ok().map(PathBuf::from))
        .or_else(|| {
            let home = std::env::var("RUSTUP_HOME")
                .or_else(|_| std::env::var("MULTIRUST_HOME"))
                .ok();
            let toolchain = std::env::var("RUSTUP_TOOLCHAIN")
                .or_else(|_| std::env::var("MULTIRUST_TOOLCHAIN"))
                .ok();
            toolchain_path(home, toolchain)
        })
        .or_else(|| {
            Command::new("rustc")
                .arg("--print")
                .arg("sysroot")
                .output()
                .ok()
                .and_then(|out| String::from_utf8(out.stdout).ok())
                .map(|s| PathBuf::from(s.trim()))
        })
        .or_else(|| option_env!("SYSROOT").map(PathBuf::from))
        .or_else(|| {
            let home = option_env!("RUSTUP_HOME")
                .or(option_env!("MULTIRUST_HOME"))
                .map(ToString::to_string);
            let toolchain = option_env!("RUSTUP_TOOLCHAIN")
                .or(option_env!("MULTIRUST_TOOLCHAIN"))
                .map(ToString::to_string);
            toolchain_path(home, toolchain)
        })
        .map(|pb| pb.to_string_lossy().to_string())
        .expect(
            "need to specify SYSROOT env var during clippy compilation, or use rustup or multirust",
        );

    if orig_args.iter().any(|a| a == "--version" || a == "-V") {
        let version_info = rustc_tools_util::get_version_info!();
        println!("{}", version_info);
        exit(0);
    }

    // Setting RUSTC_WRAPPER causes Cargo to pass 'rustc' as the first argument.
    // We're invoking the compiler programmatically, so we ignore this/
    let wrapper_mode =
        orig_args.get(1).map(Path::new).and_then(Path::file_stem) == Some("rustc".as_ref());

    if wrapper_mode {
        // we still want to be able to invoke it normally though
        orig_args.remove(1);
    }

    // this conditional check for the --sysroot flag is there so users can call
    // `clippy_driver` directly
    // without having to pass --sysroot or anything
    let mut args: Vec<String> = orig_args.clone();
    if !have_sys_root_arg {
        args.extend(vec!["--sysroot".into(), sys_root]);
    };

    args
}

/// Reads the environment and returns CLI arguments to be used in tests
pub fn read_test_env() -> Vec<String> {
    // Use only the program name
    let mut orig_args: Vec<String> = vec![env::args().next().unwrap()];

    // Get the sysroot, looking from most specific to this invocation to the least:
    // - command line
    // - runtime environment
    //    - SYSROOT
    //    - RUSTUP_HOME, MULTIRUST_HOME, RUSTUP_TOOLCHAIN, MULTIRUST_TOOLCHAIN
    // - sysroot from rustc in the path
    // - compile-time environment
    //    - SYSROOT
    //    - RUSTUP_HOME, MULTIRUST_HOME, RUSTUP_TOOLCHAIN, MULTIRUST_TOOLCHAIN
    let sys_root_arg = arg_value(&orig_args, "--sysroot", |_| true);
    let have_sys_root_arg = sys_root_arg.is_some();
    let sys_root = sys_root_arg
        .map(PathBuf::from)
        .or_else(|| std::env::var("SYSROOT").ok().map(PathBuf::from))
        .or_else(|| {
            let home = std::env::var("RUSTUP_HOME")
                .or_else(|_| std::env::var("MULTIRUST_HOME"))
                .ok();
            let toolchain = std::env::var("RUSTUP_TOOLCHAIN")
                .or_else(|_| std::env::var("MULTIRUST_TOOLCHAIN"))
                .ok();
            toolchain_path(home, toolchain)
        })
        .or_else(|| {
            Command::new("rustc")
                .arg("--print")
                .arg("sysroot")
                .output()
                .ok()
                .and_then(|out| String::from_utf8(out.stdout).ok())
                .map(|s| PathBuf::from(s.trim()))
        })
        .or_else(|| option_env!("SYSROOT").map(PathBuf::from))
        .or_else(|| {
            let home = option_env!("RUSTUP_HOME")
                .or(option_env!("MULTIRUST_HOME"))
                .map(ToString::to_string);
            let toolchain = option_env!("RUSTUP_TOOLCHAIN")
                .or(option_env!("MULTIRUST_TOOLCHAIN"))
                .map(ToString::to_string);
            toolchain_path(home, toolchain)
        })
        .map(|pb| pb.to_string_lossy().to_string())
        .expect(
            "need to specify SYSROOT env var during clippy compilation, or use rustup or multirust",
        );

    if orig_args.iter().any(|a| a == "--version" || a == "-V") {
        let version_info = rustc_tools_util::get_version_info!();
        println!("{}", version_info);
        exit(0);
    }

    // Setting RUSTC_WRAPPER causes Cargo to pass 'rustc' as the first argument.
    // We're invoking the compiler programmatically, so we ignore this/
    let wrapper_mode =
        orig_args.get(1).map(Path::new).and_then(Path::file_stem) == Some("rustc".as_ref());

    if wrapper_mode {
        // we still want to be able to invoke it normally though
        orig_args.remove(1);
    }

    // this conditional check for the --sysroot flag is there so users can call
    // `clippy_driver` directly
    // without having to pass --sysroot or anything
    let mut args: Vec<String> = orig_args.clone();
    if !have_sys_root_arg {
        args.extend(vec!["--sysroot".into(), sys_root]);
    };

    args
}
