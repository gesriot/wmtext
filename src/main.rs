mod cli;
mod model;
mod render;
mod sanitizer;
mod scanner;
mod unicode_context;
mod unicode_rules;

use std::process::ExitCode;

use clap::Parser;

use crate::cli::{Cli, Command};
use crate::model::Severity;
use crate::sanitizer::{SanitizeOptions, SanitizeRequest, sanitize_file};
use crate::scanner::{ScanOptions, scan_paths};

fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Command::Scan(args) => {
            let options = ScanOptions {
                include_hidden: args.hidden,
                respect_ignore_files: !args.no_ignore,
                max_bytes: args.max_bytes,
                max_findings_per_file: args.max_findings,
                extensions: args.extension_set(),
            };

            let report = scan_paths(&args.paths, &options);

            let rendered = match args.format {
                cli::OutputFormat::Human => render::human(&report),
                cli::OutputFormat::Json => match render::json(&report) {
                    Ok(value) => value,
                    Err(error) => {
                        eprintln!("wmtext: could not serialize JSON report: {error}");
                        return ExitCode::from(2);
                    }
                },
            };
            println!("{rendered}");

            if !report.errors.is_empty() {
                return ExitCode::from(2);
            }

            if args.fail_on == Severity::Never {
                return ExitCode::SUCCESS;
            }

            if report.has_severity_at_least(args.fail_on) {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Command::Sanitize(args) => {
            let report = match sanitize_file(&SanitizeRequest {
                input: &args.input,
                output: args.output.as_deref(),
                in_place: args.in_place,
                dry_run: args.dry_run,
                force: args.force,
                max_bytes: args.max_bytes,
                options: SanitizeOptions {
                    strip_trailing_whitespace: args.strip_trailing_whitespace,
                },
            }) {
                Ok(report) => report,
                Err(error) => {
                    eprintln!("wmtext: {error}");
                    return ExitCode::from(2);
                }
            };

            let rendered = match args.format {
                cli::OutputFormat::Human => render::sanitize_human(&report),
                cli::OutputFormat::Json => match serde_json::to_string_pretty(&report) {
                    Ok(value) => value,
                    Err(error) => {
                        eprintln!("wmtext: could not serialize JSON report: {error}");
                        return ExitCode::from(2);
                    }
                },
            };
            println!("{rendered}");
            ExitCode::SUCCESS
        }
        Command::Rules => {
            println!("{}", render::rules());
            ExitCode::SUCCESS
        }
    }
}
