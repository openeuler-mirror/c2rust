#![feature(box_patterns)]
#![feature(rustc_private)]
#![feature(str_split_once)]
#![feature(bindings_after_at)]
pub extern crate ahash;
pub extern crate colored;
pub extern crate lazy_static;
extern crate log;
extern crate regex;
pub extern crate ron;
pub extern crate rustc_ast;
extern crate rustc_data_structures;
pub extern crate rustc_driver;
pub extern crate rustc_errors;
pub extern crate rustc_hir;
pub extern crate rustc_interface;
pub extern crate rustc_lint;
pub extern crate rustc_middle;
extern crate rustc_parse;
pub extern crate rustc_serialize;
pub extern crate rustc_session;
pub extern crate rustc_span;
pub extern crate rustc_target;
pub extern crate rustc_tools_util;
pub extern crate serde;
pub extern crate serde_json;
extern crate string_cache;
pub use string_cache::DefaultAtom as Atom;

use std::path::PathBuf;

pub mod analysis;
pub mod cli;
pub mod compiler_interface;
pub mod config;
pub mod constants;
pub mod io;
pub mod ptr_arithmetic;
pub mod ptr_provenance;
mod refslice;
pub mod solver;
pub mod types;
pub mod util;

/// Common configuration for all the tools
pub struct Config {
    /// Output file path, if any given
    pub output_path: Option<PathBuf>,
    pub output_mode: io::OutputMode,
}

/// Use interned strings for names, we use `Name` instead of `Symbol`
/// to prevent clashes with [`Symbol`] used and defined by rustc.
pub type Name = Atom;
