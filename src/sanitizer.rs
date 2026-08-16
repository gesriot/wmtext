use std::collections::{BTreeMap, HashSet};
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::unicode_context::{CarrierKind, RecommendedAction, classify_text};

const MAX_RECORDED_OPERATIONS: usize = 1_000;

#[derive(Clone, Copy, Debug, Serialize)]
pub struct SanitizeOptions {
    pub strip_trailing_whitespace: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SanitizeAction {
    Remove,
}

#[derive(Debug, Serialize)]
pub struct SanitizeOperation {
    pub action: SanitizeAction,
    pub kind: &'static str,
    pub codepoint: Option<String>,
    pub byte_offset: usize,
    pub char_offset: usize,
    pub line: usize,
    pub column: usize,
    pub reason: &'static str,
}

#[derive(Debug, Default, Serialize)]
pub struct SanitizeStats {
    pub input_char_count: usize,
    pub output_char_count: usize,
    pub removed_count: usize,
    pub removed_by_kind: BTreeMap<&'static str, usize>,
}

#[derive(Debug, Serialize)]
pub struct SanitizeReport {
    pub schema_version: u32,
    pub tool: &'static str,
    pub version: &'static str,
    pub input_path: String,
    pub output_path: Option<String>,
    pub backup_path: Option<String>,
    pub dry_run: bool,
    pub changed: bool,
    pub input_bytes: usize,
    pub output_bytes: usize,
    pub options: SanitizeOptions,
    pub stats: SanitizeStats,
    pub operations: Vec<SanitizeOperation>,
    pub operations_truncated: usize,
    pub note: &'static str,
}

struct TextSanitizeResult {
    text: String,
    stats: SanitizeStats,
    operations: Vec<SanitizeOperation>,
    operations_truncated: usize,
}

pub struct SanitizeRequest<'a> {
    pub input: &'a Path,
    pub output: Option<&'a Path>,
    pub in_place: bool,
    pub dry_run: bool,
    pub force: bool,
    pub max_bytes: u64,
    pub options: SanitizeOptions,
}

pub fn sanitize_file(request: &SanitizeRequest<'_>) -> Result<SanitizeReport, String> {
    validate_request(request)?;

    let metadata = fs::metadata(request.input)
        .map_err(|error| format!("could not read input metadata: {error}"))?;
    if !metadata.is_file() {
        return Err("input is not a regular file".to_owned());
    }
    if metadata.len() > request.max_bytes {
        return Err(format!(
            "input exceeds --max-bytes ({} > {})",
            metadata.len(),
            request.max_bytes
        ));
    }

    let bytes =
        fs::read(request.input).map_err(|error| format!("could not read input: {error}"))?;
    if bytes.iter().take(8 * 1024).any(|byte| *byte == 0) {
        return Err("input looks binary (NUL byte in initial sample)".to_owned());
    }

    let text = std::str::from_utf8(&bytes)
        .map_err(|error| format!("input is not valid UTF-8 at byte {}", error.valid_up_to()))?;

    let result = sanitize_text(text, 0, request.options);
    let output_bytes = result.text.as_bytes().to_vec();
    let changed = output_bytes != bytes;

    let mut output_path = None;
    let mut backup_path = None;
    if !request.dry_run {
        if request.in_place {
            if changed {
                let backup = backup_name(request.input);
                if backup.exists() {
                    return Err(format!(
                        "refusing to overwrite existing backup: {}",
                        backup.display()
                    ));
                }
                fs::copy(request.input, &backup).map_err(|error| {
                    format!("could not create backup {}: {error}", backup.display())
                })?;
                fs::write(request.input, &output_bytes).map_err(|error| {
                    format!(
                        "could not write input after backup was created at {}: {error}",
                        backup.display()
                    )
                })?;
                backup_path = Some(display_path(&backup));
            }
            output_path = Some(display_path(request.input));
        } else if let Some(path) = request.output {
            write_output(path, &output_bytes, request.force)?;
            output_path = Some(display_path(path));
        }
    }

    Ok(SanitizeReport {
        schema_version: 1,
        tool: "wmtext",
        version: env!("CARGO_PKG_VERSION"),
        input_path: display_path(request.input),
        output_path,
        backup_path,
        dry_run: request.dry_run,
        changed,
        input_bytes: bytes.len(),
        output_bytes: output_bytes.len(),
        options: request.options,
        stats: result.stats,
        operations: result.operations,
        operations_truncated: result.operations_truncated,
        note: "Deterministic Unicode/text sanitation only; statistical watermark status remains indeterminate.",
    })
}

fn validate_request(request: &SanitizeRequest<'_>) -> Result<(), String> {
    if request.dry_run {
        if request.output.is_some() || request.in_place {
            return Err("--dry-run cannot be combined with --output or --in-place".to_owned());
        }
        return Ok(());
    }
    if request.in_place == request.output.is_some() {
        return Err("choose exactly one of --output or --in-place (or use --dry-run)".to_owned());
    }
    if let Some(output) = request.output
        && output == request.input
    {
        return Err("use --in-place when the output path equals the input path".to_owned());
    }
    Ok(())
}

fn sanitize_text(text: &str, byte_base: usize, options: SanitizeOptions) -> TextSanitizeResult {
    let chars: Vec<char> = text.chars().collect();
    let decisions = classify_text(text);
    let trailing = if options.strip_trailing_whitespace {
        trailing_whitespace_indices(&chars)
    } else {
        HashSet::new()
    };

    let mut result = String::with_capacity(text.len());
    let mut stats = SanitizeStats {
        input_char_count: chars.len(),
        ..SanitizeStats::default()
    };
    let mut operations = Vec::new();
    let mut operations_truncated = 0;
    let mut line = 1;
    let mut column = 1;

    for (index, ((local_byte_offset, ch), decision)) in text
        .char_indices()
        .zip(decisions.iter().copied())
        .enumerate()
    {
        let remove_for_trailing = trailing.contains(&index);
        let remove = remove_for_trailing
            || decision
                .kind
                .is_some_and(|kind| kind != CarrierKind::ExoticSpace);

        if remove {
            let kind = if remove_for_trailing {
                "trailing_whitespace"
            } else {
                decision.kind.map_or("format_control", CarrierKind::label)
            };
            stats.removed_count += 1;
            *stats.removed_by_kind.entry(kind).or_default() += 1;
            record_operation(
                &mut operations,
                &mut operations_truncated,
                SanitizeOperation {
                    action: SanitizeAction::Remove,
                    kind,
                    codepoint: Some(format!("U+{:04X}", ch as u32)),
                    byte_offset: local_byte_offset + byte_base,
                    char_offset: index,
                    line,
                    column,
                    reason: if remove_for_trailing {
                        "trailing ASCII whitespace was explicitly requested for removal"
                    } else if decision.action == RecommendedAction::Keep {
                        "project policy removes all recognized invisible/format and private-use characters"
                    } else {
                        decision.reason
                    },
                },
            );
        } else {
            result.push(ch);
        }

        if ch == '\n' {
            line += 1;
            column = 1;
        } else {
            column += 1;
        }
    }

    stats.output_char_count = result.chars().count();
    TextSanitizeResult {
        text: result,
        stats,
        operations,
        operations_truncated,
    }
}

fn trailing_whitespace_indices(chars: &[char]) -> HashSet<usize> {
    let mut removals = HashSet::new();
    let mut line_start = 0;

    for index in 0..=chars.len() {
        if index < chars.len() && chars[index] != '\n' {
            continue;
        }
        let mut content_end = index;
        if content_end > line_start && chars[content_end - 1] == '\r' {
            content_end -= 1;
        }
        let mut trailing_start = content_end;
        while trailing_start > line_start && matches!(chars[trailing_start - 1], ' ' | '\t') {
            trailing_start -= 1;
        }
        if trailing_start < content_end {
            let suffix = &chars[trailing_start..content_end];
            let is_markdown_hard_break = trailing_start > line_start
                && suffix.len() == 2
                && suffix.iter().all(|ch| *ch == ' ');
            if !is_markdown_hard_break {
                removals.extend(trailing_start..content_end);
            }
        }
        line_start = index.saturating_add(1);
    }
    removals
}

fn record_operation(
    operations: &mut Vec<SanitizeOperation>,
    truncated: &mut usize,
    operation: SanitizeOperation,
) {
    if operations.len() < MAX_RECORDED_OPERATIONS {
        operations.push(operation);
    } else {
        *truncated += 1;
    }
}

fn backup_name(path: &Path) -> PathBuf {
    let mut value: OsString = path.as_os_str().to_owned();
    value.push(".bak");
    PathBuf::from(value)
}

fn write_output(path: &Path, bytes: &[u8], force: bool) -> Result<(), String> {
    if force {
        return fs::write(path, bytes)
            .map_err(|error| format!("could not write output {}: {error}", path.display()));
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("could not create output {}: {error}", path.display()))?;
    file.write_all(bytes)
        .map_err(|error| format!("could not write output {}: {error}", path.display()))
}

fn display_path(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use super::{SanitizeOptions, sanitize_text};

    const DEFAULT: SanitizeOptions = SanitizeOptions {
        strip_trailing_whitespace: false,
    };

    #[test]
    fn removes_floating_and_emoji_format_characters() {
        let input = "a\u{200D}b 👨\u{200D}👩 ⚖\u{FE0F}";
        let result = sanitize_text(input, 0, DEFAULT);
        assert_eq!(result.text, "ab 👨👩 ⚖");
        assert_eq!(result.stats.removed_count, 3);
    }

    #[test]
    fn removes_multilingual_load_bearing_invisibles() {
        let input = "می\u{200C}روم क्\u{200D}ष ᠠ\u{180B}ᠡ ក\u{17B4}ខ ᄀ\u{115F}ᅡ";
        let result = sanitize_text(input, 0, DEFAULT);
        assert_eq!(result.text, "میروم क्ष ᠠᠡ កខ 가");
        assert_eq!(result.stats.removed_count, 5);
    }

    #[test]
    fn removes_complete_and_incomplete_flag_tags() {
        let complete = "🏴\u{E0067}\u{E0062}\u{E0073}\u{E0063}\u{E0074}\u{E007F}";
        assert_eq!(sanitize_text(complete, 0, DEFAULT).text, "🏴");
        assert_eq!(sanitize_text("🏴\u{E0067}\u{E0062}", 0, DEFAULT).text, "🏴");
    }

    #[test]
    fn removes_private_use_and_ambiguous_invisibles_but_preserves_spaces() {
        let input =
            "\u{FEFF}a\u{E000}b\u{2003}c soft\u{00AD}hyphen \u{034F}\u{200B}\u{2060}\u{2062}";
        assert_eq!(
            sanitize_text(input, 0, DEFAULT).text,
            "ab\u{2003}c softhyphen "
        );
    }

    #[test]
    fn trailing_cleanup_preserves_markdown_hard_breaks() {
        let options = SanitizeOptions {
            strip_trailing_whitespace: true,
        };
        let result = sanitize_text("one \ntwo  \n   \n", 0, options);
        assert_eq!(result.text, "one\ntwo  \n\n");
    }
}
