use std::fmt::Write;

use crate::model::{FileStatus, ScanReport};
use crate::sanitizer::SanitizeReport;

pub fn json(report: &ScanReport) -> serde_json::Result<String> {
    serde_json::to_string_pretty(report)
}

pub fn human(report: &ScanReport) -> String {
    let mut output = String::new();
    let summary = &report.summary;

    writeln!(
        output,
        "wmtext {} – read-only text signal scan",
        report.tool.version
    )
    .unwrap();
    writeln!(
        output,
        "Statistical watermark: {} ({})",
        report.statistical_watermark_status.status, report.statistical_watermark_status.reason
    )
    .unwrap();
    writeln!(output).unwrap();

    for file in &report.files {
        match file.status {
            FileStatus::NoSupportedSurfaceSignalDetected => {
                writeln!(
                    output,
                    "OK   {} – no supported surface signal detected",
                    file.path
                )
                .unwrap();
            }
            FileStatus::SurfaceFindingsPresent => {
                writeln!(
                    output,
                    "FIND {} – {} finding(s)",
                    file.path,
                    file.findings.len()
                )
                .unwrap();
                for finding in &file.findings {
                    let codepoint = finding
                        .codepoint
                        .as_deref()
                        .map(|value| format!(" {value}"))
                        .unwrap_or_default();
                    writeln!(
                        output,
                        "  [{}] {}:{}:{} {}{} – {}",
                        finding.severity.label(),
                        file.path,
                        finding.line,
                        finding.column,
                        finding.rule_id,
                        codepoint,
                        finding.message
                    )
                    .unwrap();
                    writeln!(output, "         context: {}", finding.context).unwrap();
                }
                if file.findings_truncated > 0 {
                    writeln!(
                        output,
                        "  ... {} additional finding(s) truncated",
                        file.findings_truncated
                    )
                    .unwrap();
                }
            }
            FileStatus::SkippedTooLarge
            | FileStatus::SkippedBinary
            | FileStatus::SkippedNonUtf8 => {
                writeln!(
                    output,
                    "SKIP {} – {}",
                    file.path,
                    file.note.as_deref().unwrap_or("unsupported input")
                )
                .unwrap();
            }
        }
    }

    for error in &report.errors {
        writeln!(output, "ERROR {} – {}", error.path, error.message).unwrap();
    }

    writeln!(output).unwrap();
    writeln!(
        output,
        "Summary: {} considered, {} scanned, {} skipped, {} with findings; {} retained findings ({} info, {} warning, {} high)",
        summary.files_considered,
        summary.files_scanned,
        summary.files_skipped,
        summary.files_with_findings,
        summary.findings_total,
        summary.findings_info,
        summary.findings_warning,
        summary.findings_high
    )
    .unwrap();

    if summary.findings_total == 0 && report.errors.is_empty() {
        writeln!(
            output,
            "Conclusion: no supported surface signal was detected. Proprietary statistical watermark detection remains indeterminate."
        )
        .unwrap();
    } else {
        writeln!(
            output,
            "Conclusion: findings are observable text anomalies, not provider attribution."
        )
        .unwrap();
    }

    output.trim_end().to_owned()
}

pub fn sanitize_human(report: &SanitizeReport) -> String {
    let mut output = String::new();
    writeln!(
        output,
        "wmtext {} – deterministic text sanitation",
        report.version
    )
    .unwrap();
    writeln!(output, "Input: {}", report.input_path).unwrap();
    if report.dry_run {
        writeln!(output, "Mode: dry-run (nothing written)").unwrap();
    } else if let Some(path) = &report.output_path {
        writeln!(output, "Output: {path}").unwrap();
    }
    if let Some(path) = &report.backup_path {
        writeln!(output, "Backup: {path}").unwrap();
    }
    writeln!(output, "Changed: {}", report.changed).unwrap();
    writeln!(output, "Removed: {}", report.stats.removed_count).unwrap();

    for operation in &report.operations {
        let codepoint = operation
            .codepoint
            .as_deref()
            .map(|value| format!(" {value}"))
            .unwrap_or_default();
        writeln!(
            output,
            "  {:?} {}:{}:{} {}{} – {}",
            operation.action,
            report.input_path,
            operation.line,
            operation.column,
            operation.kind,
            codepoint,
            operation.reason
        )
        .unwrap();
    }
    if report.operations_truncated > 0 {
        writeln!(
            output,
            "  ... {} additional operation(s) truncated",
            report.operations_truncated
        )
        .unwrap();
    }
    writeln!(output, "Note: {}", report.note).unwrap();
    output.trim_end().to_owned()
}

pub fn rules() -> &'static str {
    "Built-in rules:\n\
  unicode.format_control             unexpected invisible format controls\n\
  unicode.control_character          unexpected C0/C1 controls\n\
  unicode.joiner                     context-aware ZWJ/ZWNJ review\n\
  unicode.bidi_control                bidi embeddings, overrides, and isolates\n\
  unicode.tag_character               invisible Unicode tag payload characters\n\
  unicode.variation_selector_channel  unusual variation-selector use or density\n\
  unicode.non_ascii_spaces            aggregate non-ASCII whitespace distribution\n\
  text.trailing_whitespace            aggregate trailing-space/tab channel\n\
  unicode.mixed_script_token          Latin/Cyrillic/Greek mixed-token heuristic\n\
  unicode.combining_mark_run          unusually long combining-mark run\n\
  unicode.private_use                 private-use codepoints requiring review\n\
  unicode.non_nfc                     informational NFC normalization check\n\n\
Sanitize removes every recognized invisible/format and private-use character. Non-ASCII spaces are preserved.\n\n\
Every rule reports an observable surface property. None identifies an AI provider."
}
