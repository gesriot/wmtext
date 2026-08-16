use std::collections::{BTreeSet, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use ignore::WalkBuilder;

use crate::model::{
    FileReport, FileStatus, ScanError, ScanReport, Severity, StatisticalStatus, Summary, ToolInfo,
};
use crate::unicode_rules::analyze_text;

#[derive(Debug)]
pub struct ScanOptions {
    pub include_hidden: bool,
    pub respect_ignore_files: bool,
    pub max_bytes: u64,
    pub max_findings_per_file: usize,
    pub extensions: BTreeSet<String>,
}

pub fn scan_paths(paths: &[PathBuf], options: &ScanOptions) -> ScanReport {
    let mut report = ScanReport {
        schema_version: 1,
        tool: ToolInfo {
            name: "wmtext",
            version: env!("CARGO_PKG_VERSION"),
        },
        statistical_watermark_status: StatisticalStatus {
            status: "indeterminate",
            reason: "A provider detector or the watermark algorithm, tokenizer, configuration, and key are required.",
        },
        summary: Summary::default(),
        files: Vec::new(),
        errors: Vec::new(),
    };

    let mut candidates = Vec::new();
    let mut seen = HashSet::new();

    for path in paths {
        if path.is_file() {
            push_candidate(path, &mut candidates, &mut seen);
        } else if path.is_dir() {
            collect_directory(
                path,
                options,
                &mut candidates,
                &mut seen,
                &mut report.errors,
            );
        } else {
            report.errors.push(ScanError {
                path: display_path(path),
                message: "Path does not exist or is not a regular file/directory".to_owned(),
            });
        }
    }

    candidates.sort();
    report.summary.files_considered = candidates.len();

    for path in candidates {
        match scan_file(&path, options) {
            Ok(file_report) => report.files.push(file_report),
            Err(error) => report.errors.push(error),
        }
    }

    summarize(&mut report);
    report
}

fn collect_directory(
    root: &Path,
    options: &ScanOptions,
    candidates: &mut Vec<PathBuf>,
    seen: &mut HashSet<PathBuf>,
    errors: &mut Vec<ScanError>,
) {
    let mut builder = WalkBuilder::new(root);
    builder
        .hidden(!options.include_hidden)
        .follow_links(false)
        .git_ignore(options.respect_ignore_files)
        .git_global(options.respect_ignore_files)
        .git_exclude(options.respect_ignore_files)
        .ignore(options.respect_ignore_files)
        .parents(options.respect_ignore_files)
        .filter_entry(|entry| {
            entry.depth() == 0
                || !entry.file_type().is_some_and(|kind| kind.is_dir())
                || !is_default_excluded_directory(entry.file_name().to_string_lossy().as_ref())
        });

    for entry in builder.build() {
        match entry {
            Ok(entry) => {
                if !entry.file_type().is_some_and(|kind| kind.is_file()) {
                    continue;
                }
                let path = entry.path();
                if has_allowed_extension(path, &options.extensions) {
                    push_candidate(path, candidates, seen);
                }
            }
            Err(error) => errors.push(ScanError {
                path: display_path(root),
                message: error.to_string(),
            }),
        }
    }
}

fn push_candidate(path: &Path, candidates: &mut Vec<PathBuf>, seen: &mut HashSet<PathBuf>) {
    let normalized = path.to_path_buf();
    if seen.insert(normalized.clone()) {
        candidates.push(normalized);
    }
}

fn has_allowed_extension(path: &Path, extensions: &BTreeSet<String>) -> bool {
    path.extension()
        .and_then(|value| value.to_str())
        .map(str::to_ascii_lowercase)
        .is_some_and(|value| extensions.contains(&value))
}

fn is_default_excluded_directory(name: &str) -> bool {
    matches!(
        name,
        ".git" | ".hg" | ".svn" | "target" | "node_modules" | "vendor" | ".venv" | "__pycache__"
    )
}

fn scan_file(path: &Path, options: &ScanOptions) -> Result<FileReport, ScanError> {
    let metadata = fs::metadata(path).map_err(|error| ScanError {
        path: display_path(path),
        message: format!("Could not read metadata: {error}"),
    })?;
    let size_bytes = metadata.len();

    if size_bytes > options.max_bytes {
        return Ok(FileReport {
            path: display_path(path),
            size_bytes,
            status: FileStatus::SkippedTooLarge,
            encoding: None,
            metrics: None,
            findings: Vec::new(),
            findings_truncated: 0,
            note: Some(format!("File exceeds --max-bytes ({})", options.max_bytes)),
        });
    }

    let bytes = fs::read(path).map_err(|error| ScanError {
        path: display_path(path),
        message: format!("Could not read file: {error}"),
    })?;

    if looks_binary(&bytes) {
        return Ok(FileReport {
            path: display_path(path),
            size_bytes,
            status: FileStatus::SkippedBinary,
            encoding: None,
            metrics: None,
            findings: Vec::new(),
            findings_truncated: 0,
            note: Some("NUL byte detected in the initial sample".to_owned()),
        });
    }

    let (content, encoding, byte_base) = if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        (bytes.as_slice(), "utf-8-bom", 0)
    } else {
        (bytes.as_slice(), "utf-8", 0)
    };

    let text = match std::str::from_utf8(content) {
        Ok(text) => text,
        Err(error) => {
            return Ok(FileReport {
                path: display_path(path),
                size_bytes,
                status: FileStatus::SkippedNonUtf8,
                encoding: None,
                metrics: None,
                findings: Vec::new(),
                findings_truncated: 0,
                note: Some(format!("Invalid UTF-8 at byte {}", error.valid_up_to())),
            });
        }
    };

    let analysis = analyze_text(text, byte_base, options.max_findings_per_file);
    let status = if analysis.findings.is_empty() {
        FileStatus::NoSupportedSurfaceSignalDetected
    } else {
        FileStatus::SurfaceFindingsPresent
    };

    Ok(FileReport {
        path: display_path(path),
        size_bytes,
        status,
        encoding: Some(encoding),
        metrics: Some(analysis.metrics),
        findings: analysis.findings,
        findings_truncated: analysis.truncated,
        note: None,
    })
}

fn looks_binary(bytes: &[u8]) -> bool {
    bytes.iter().take(8 * 1024).any(|byte| *byte == 0)
}

fn summarize(report: &mut ScanReport) {
    for file in &report.files {
        match file.status {
            FileStatus::NoSupportedSurfaceSignalDetected | FileStatus::SurfaceFindingsPresent => {
                report.summary.files_scanned += 1;
            }
            FileStatus::SkippedTooLarge
            | FileStatus::SkippedBinary
            | FileStatus::SkippedNonUtf8 => report.summary.files_skipped += 1,
        }

        if !file.findings.is_empty() {
            report.summary.files_with_findings += 1;
        }
        report.summary.findings_truncated += file.findings_truncated;

        for finding in &file.findings {
            report.summary.findings_total += 1;
            match finding.severity {
                Severity::Info => report.summary.findings_info += 1,
                Severity::Warning => report.summary.findings_warning += 1,
                Severity::High => report.summary.findings_high += 1,
                Severity::Never => {}
            }
        }
    }
}

fn display_path(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use super::{is_default_excluded_directory, looks_binary};

    #[test]
    fn nul_marks_binary_content() {
        assert!(looks_binary(b"hello\0world"));
        assert!(!looks_binary(b"hello\nworld"));
    }

    #[test]
    fn generated_dependency_directories_are_excluded() {
        assert!(is_default_excluded_directory("target"));
        assert!(is_default_excluded_directory("node_modules"));
        assert!(!is_default_excluded_directory("src"));
    }
}
