use crate::Config;
use rustc_span::source_map::FileLoader;
/// File I/O
use std::io;
use std::{
    collections::HashMap,
    fs,
    fs::OpenOptions,
    io::{Error, ErrorKind, Write},
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OutputMode {
    /// Overwrite the file with the fixes
    Overwrite,
    /// Write to a new file
    NewFile,
    /// Write human-readable patches
    DebugLog,
    /// Back-up the original file
    BackupOrig,
}

impl OutputMode {
    fn overwrite(self) -> bool {
        self == OutputMode::Overwrite
    }
    fn output_path(self, path: &Path, config: &Config) -> Option<PathBuf> {
        match self {
            OutputMode::Overwrite => Some(path.to_owned()),
            OutputMode::NewFile => Some(path.with_extension("fixed.rs")),
            _ => config.output_path.clone(),
        }
    }
    fn open_output(self, path: &Path, config: &Config) -> io::Result<Box<dyn Write>> {
        Ok(if let Some(path) = self.output_path(path, config) {
            Box::new(OpenOptions::new().write(true).truncate(true).open(path)?)
        } else {
            // No output is given, write to stdout
            Box::new(io::stdout())
        })
    }
}

/// File I/O operations
pub struct FileIO<'a> {
    config: &'a Config,
}

impl<'a> FileIO<'a> {
    pub fn new(config: &'a Config) -> FileIO<'a> {
        FileIO { config }
    }

    pub fn read_file(&self, path: &Path) -> io::Result<String> {
        fs::read_to_string(path)
    }

    pub fn write_file(&self, path: &Path, s: &str) -> io::Result<()> {
        let mut writer = self.config.output_mode.open_output(path, self.config)?;
        writer.write(s.as_bytes())?;
        Ok(())
    }
}

pub struct InMemoryFileLoader {
    pub files: HashMap<PathBuf, String>,
}

impl InMemoryFileLoader {
    pub fn new() -> Self {
        InMemoryFileLoader {
            files: HashMap::default(),
        }
    }
}

impl FileLoader for InMemoryFileLoader {
    fn file_exists(&self, path: &Path) -> bool {
        self.files.contains_key(path)
    }

    fn read_file(&self, path: &Path) -> std::io::Result<String> {
        self.files.get(path).map(|s| s.clone()).ok_or(Error::new(
            ErrorKind::NotFound,
            "The requested file is not found in in-memory storage",
        ))
    }
}

/// A file loader combinator, tries the main loader, if it fails
/// tries the backup one.
pub struct ChainFileLoader {
    pub main: Box<dyn FileLoader + Send + Sync>,
    pub backup: Box<dyn FileLoader + Send + Sync>,
}

impl FileLoader for ChainFileLoader {
    fn file_exists(&self, path: &Path) -> bool {
        self.main.file_exists(path) || self.backup.file_exists(path)
    }

    fn read_file(&self, path: &Path) -> io::Result<String> {
        self.main
            .read_file(path)
            .or_else(|_| self.backup.read_file(path))
    }
}
