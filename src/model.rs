use clap::ValueEnum;
use serde::Serialize;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Warning,
    High,
    Never,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Self::Info => "INFO",
            Self::Warning => "WARN",
            Self::High => "HIGH",
            Self::Never => "NEVER",
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ScanReport {
    pub schema_version: u32,
    pub tool: ToolInfo,
    pub statistical_watermark_status: StatisticalStatus,
    pub summary: Summary,
    pub files: Vec<FileReport>,
    pub errors: Vec<ScanError>,
}

impl ScanReport {
    pub fn has_severity_at_least(&self, threshold: Severity) -> bool {
        self.files.iter().any(|file| {
            file.findings
                .iter()
                .any(|finding| finding.severity >= threshold)
        })
    }
}

#[derive(Debug, Serialize)]
pub struct ToolInfo {
    pub name: &'static str,
    pub version: &'static str,
}

#[derive(Debug, Serialize)]
pub struct StatisticalStatus {
    pub status: &'static str,
    pub reason: &'static str,
}

#[derive(Debug, Default, Serialize)]
pub struct Summary {
    pub files_considered: usize,
    pub files_scanned: usize,
    pub files_with_findings: usize,
    pub files_skipped: usize,
    pub findings_total: usize,
    pub findings_info: usize,
    pub findings_warning: usize,
    pub findings_high: usize,
    pub findings_truncated: usize,
}

#[derive(Debug, Serialize)]
pub struct FileReport {
    pub path: String,
    pub size_bytes: u64,
    pub status: FileStatus,
    pub encoding: Option<&'static str>,
    pub metrics: Option<TextMetrics>,
    pub findings: Vec<Finding>,
    pub findings_truncated: usize,
    pub note: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FileStatus {
    NoSupportedSurfaceSignalDetected,
    SurfaceFindingsPresent,
    SkippedTooLarge,
    SkippedBinary,
    SkippedNonUtf8,
}

#[derive(Debug, Default, Serialize)]
pub struct TextMetrics {
    pub unicode_scalar_count: usize,
    pub line_count: usize,
    pub ascii_space_count: usize,
    pub non_ascii_space_count: usize,
    pub format_control_count: usize,
    pub variation_selector_count: usize,
    pub unicode_tag_count: usize,
    pub mixed_script_token_count: usize,
    pub trailing_whitespace_line_count: usize,
    pub trailing_space_count: usize,
    pub trailing_tab_count: usize,
    pub padded_blank_line_count: usize,
    pub nfc_normalized: bool,
}

#[derive(Debug, Serialize)]
pub struct Finding {
    pub rule_id: &'static str,
    pub category: &'static str,
    pub severity: Severity,
    pub message: String,
    pub codepoint: Option<String>,
    pub unicode_name: Option<String>,
    pub byte_offset: usize,
    pub char_offset: usize,
    pub line: usize,
    pub column: usize,
    pub context: String,
    pub interpretation: &'static str,
}

#[derive(Debug, Serialize)]
pub struct ScanError {
    pub path: String,
    pub message: String,
}
