use crate::cli;
/// Interface to `rustc`, runs different stages of the compiler and collects results
use rustc_data_structures::sync;
use rustc_driver;
use rustc_interface;
use rustc_lint::{EarlyLintPass, LateLintPass};
use rustc_session::DiagnosticOutput;
use std::{
    io::{BufWriter, Write},
    mem,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

pub mod error_handling;

// We use function pointers rather than resorting to lazy_static and
// having closures+boxes for function types "(Box<dyn Fn() -> ...> +
// Send + Sync)".
//
// We can't generalize these because Rust doesn't have higher-kinded
// types that can range over traits
pub type EarlyPass = dyn EarlyLintPass + sync::Send + sync::Sync + 'static;
pub type LatePass = dyn for<'tcx> LateLintPass<'tcx> + sync::Send + sync::Sync + 'static;
pub type EarlyCallback = fn() -> Box<EarlyPass>;
pub type LateCallback =
    fn() -> Box<dyn for<'tcx> LateLintPass<'tcx> + sync::Send + sync::Sync + 'static>;

/// A writer implementation backed by a Vec
struct DiagnosticsWriter {
    backing_store: &'static Mutex<Vec<u8>>,
}

impl Write for DiagnosticsWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.backing_store.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Callbacks for registering lints with `rustc`
pub struct DriverCallbacks {
    pub pre_expansion_passes: Vec<EarlyCallback>,
    pub after_parsing_passes: Vec<EarlyCallback>,
    pub after_typeck_passes: Vec<LateCallback>,
    diagnostics_writer: Option<BufWriter<DiagnosticsWriter>>,
    pub config_cb: Option<for<'cfg> fn(&'cfg mut rustc_interface::Config)>,
}

impl DriverCallbacks {
    pub fn new() -> Self {
        DriverCallbacks {
            pre_expansion_passes: Vec::new(),
            after_parsing_passes: Vec::new(),
            after_typeck_passes: Vec::new(),
            diagnostics_writer: None,
            config_cb: None,
        }
    }

    pub fn redirect_errors_to(&mut self, backing_store: &'static Mutex<Vec<u8>>) -> &mut Self {
        self.diagnostics_writer = Some(BufWriter::new(DiagnosticsWriter { backing_store }));
        self
    }
}

impl rustc_driver::Callbacks for DriverCallbacks {
    fn config(&mut self, cfg: &mut rustc_interface::Config) {
        // Set stderr
        if let Some(writer) = self.diagnostics_writer.take() {
            cfg.diagnostic_output = DiagnosticOutput::Raw(Box::new(writer));
        }

        let pre_expansion_passes = self.pre_expansion_passes.clone();
        let after_parsing_passes = self.after_parsing_passes.clone();
        let after_typeck_passes = self.after_typeck_passes.clone();

        // Register our declared lints before existing lints
        let prev_lints = mem::replace(&mut cfg.register_lints, None);
        cfg.register_lints = Some(Box::new(move |sess, lint_store| {
            for p in pre_expansion_passes.clone() {
                lint_store.register_pre_expansion_pass(Box::new(move || p()));
            }
            for p in after_parsing_passes.clone() {
                lint_store.register_early_pass(p);
            }
            for p in after_typeck_passes.clone() {
                lint_store.register_late_pass(p);
            }
            if let Some(lints) = &prev_lints {
                lints(sess, lint_store);
            }
        }));
        self.config_cb.as_mut().map(|f| f(cfg));
    }
}

pub fn run_compiler_with_setup<SetupFn: FnOnce(&mut DriverCallbacks)>(
    mut args: Vec<String>,
    extra_args: &Vec<&str>,
    passes: Vec<LateCallback>,
    setup: SetupFn,
) -> (i32, Duration) {
    args = cli::read_env(args);
    let before_compile = Instant::now();
    let exit_code = rustc_driver::catch_with_exit_code(move || {
        // Add extra arguments to the compiler for our use case
        args.append(
            &mut vec!["--crate-type", "lib", "-A", "warnings"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        );

        // Add the given arguments
        args.append(&mut extra_args.iter().map(|s| s.to_string()).collect());

        // Run the compiler with the printer callbacks
        let mut callbacks = DriverCallbacks::new();
        // disable the passes for testing
        callbacks.after_typeck_passes = passes;
        setup(&mut callbacks);
        let mut compiler = rustc_driver::RunCompiler::new(&args, &mut callbacks);
        // don't emit anything from the compiler
        compiler.set_emitter(None);
        compiler.run()
    });
    let compile_time = before_compile.elapsed();

    if cfg!(profile_compiler_runs) {
        println!("rustc exited with code {}", exit_code);
        println!("elapsed time: {} ms", compile_time.as_millis());
    }

    (exit_code, compile_time)
}

pub fn run_compiler_frontend(
    extra_args: &Vec<&str>,
    passes: Vec<EarlyCallback>,
) -> (i32, Duration) {
    let before_compile = Instant::now();
    let exit_code = rustc_driver::catch_with_exit_code(move || {
        let orig_args: Vec<String> = std::env::args().collect();
        let mut args = cli::read_env(orig_args);

        // Add extra arguments to the compiler for our use case
        args.append(
            &mut vec!["--crate-type", "lib", "-A", "warnings"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        );

        // Add the given arguments
        args.append(&mut extra_args.iter().map(|s| s.to_string()).collect());

        // Run the compiler with the printer callbacks
        let mut callbacks = DriverCallbacks::new();
        // disable the passes for testing
        callbacks.after_parsing_passes = passes;
        let mut compiler = rustc_driver::RunCompiler::new(&args, &mut callbacks);
        // don't emit anything from the compiler
        compiler.set_emitter(None);
        compiler.run()
    });
    let compile_time = before_compile.elapsed();

    if cfg!(profile_compiler_runs) {
        println!("rustc exited with code {}", exit_code);
        println!("elapsed time: {} ms", compile_time.as_millis());
    }

    (exit_code, compile_time)
}

pub fn run_compiler(extra_args: &Vec<&str>, passes: Vec<LateCallback>) -> (i32, Duration) {
    let orig_args: Vec<String> = std::env::args().collect();
    let args = cli::read_env(orig_args);
    run_compiler_with_setup(args, extra_args, passes, |_| {})
}
