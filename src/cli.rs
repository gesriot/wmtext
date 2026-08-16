use std::collections::BTreeSet;
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

use crate::model::Severity;

const DEFAULT_EXTENSIONS: &str = "md,markdown,txt,rst,adoc,org,tex,html,htm,xml,json,jsonl,yaml,yml,toml,csv,tsv,log,ini,cfg,conf,rs,py,js,jsx,ts,tsx,go,java,kt,kts,c,cc,cpp,h,hpp,cs,swift,rb,php,sh,zsh,bash,fish";

#[derive(Debug, Parser)]
#[command(
    name = "wmtext",
    version,
    about = "Detect observable watermark and steganography signals in text",
    long_about = "A local, read-only scanner for Unicode and surface-level text signals. It does not claim to detect proprietary statistical watermarks without provider keys or a provider detector."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Scan files or directories without modifying them.
    Scan(ScanArgs),
    /// Sanitize deterministic Unicode/text carriers in one UTF-8 file.
    Sanitize(SanitizeArgs),
    /// Print the built-in rules and their interpretation limits.
    Rules,
}

#[derive(Debug, Args)]
pub struct ScanArgs {
    /// Files or directories to scan.
    #[arg(required = true)]
    pub paths: Vec<PathBuf>,

    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
    pub format: OutputFormat,

    /// Return exit code 1 when this severity or higher is found.
    #[arg(long, value_enum, default_value_t = Severity::Warning)]
    pub fail_on: Severity,

    /// Include hidden files when walking directories.
    #[arg(long)]
    pub hidden: bool,

    /// Ignore .gitignore and related ignore files.
    #[arg(long)]
    pub no_ignore: bool,

    /// Maximum file size in bytes.
    #[arg(long, default_value_t = 8 * 1024 * 1024)]
    pub max_bytes: u64,

    /// Maximum number of findings retained per file.
    #[arg(long, default_value_t = 200)]
    pub max_findings: usize,

    /// Comma-separated extensions used during directory walks. Explicit files are always considered.
    #[arg(long, default_value = DEFAULT_EXTENSIONS)]
    pub extensions: String,
}

#[derive(Debug, Args)]
pub struct SanitizeArgs {
    /// UTF-8 text or source-code file to sanitize.
    pub input: PathBuf,

    /// Write the sanitized content to a new path.
    #[arg(short, long, conflicts_with_all = ["in_place", "dry_run"])]
    pub output: Option<PathBuf>,

    /// Replace the input and create INPUT.bak when changes are needed.
    #[arg(long, conflicts_with_all = ["output", "dry_run"])]
    pub in_place: bool,

    /// Report proposed operations without writing a file.
    #[arg(long, conflicts_with_all = ["output", "in_place"])]
    pub dry_run: bool,

    /// Allow --output to replace an existing file. Never overwrites an in-place backup.
    #[arg(long)]
    pub force: bool,

    /// Remove trailing ASCII spaces/tabs, preserving Markdown hard breaks of exactly two spaces.
    #[arg(long)]
    pub strip_trailing_whitespace: bool,

    /// Maximum input size in bytes.
    #[arg(long, default_value_t = 8 * 1024 * 1024)]
    pub max_bytes: u64,

    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
    pub format: OutputFormat,
}

impl ScanArgs {
    pub fn extension_set(&self) -> BTreeSet<String> {
        self.extensions
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| value.trim_start_matches('.').to_ascii_lowercase())
            .collect()
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
pub enum OutputFormat {
    #[default]
    Human,
    Json,
}
