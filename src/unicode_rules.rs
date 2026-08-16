use unicode_normalization::UnicodeNormalization;

use crate::model::{Finding, Severity, TextMetrics};
use crate::unicode_context::{CarrierKind, classify_text};

const INTERPRETATION: &str =
    "Observable surface anomaly only; it does not identify an AI provider or prove a watermark.";

pub struct TextAnalysis {
    pub metrics: TextMetrics,
    pub findings: Vec<Finding>,
    pub truncated: usize,
}

#[derive(Clone, Copy)]
struct Scalar {
    ch: char,
    local_byte_offset: usize,
    byte_offset: usize,
    char_offset: usize,
    line: usize,
    column: usize,
}

pub fn analyze_text(text: &str, byte_base: usize, max_findings: usize) -> TextAnalysis {
    let scalars = collect_scalars(text, byte_base);
    let contextual_decisions = classify_text(text);
    let mut metrics = TextMetrics {
        unicode_scalar_count: scalars.len(),
        line_count: if text.is_empty() {
            0
        } else {
            text.bytes().filter(|byte| *byte == b'\n').count() + 1
        },
        ascii_space_count: text.chars().filter(|ch| *ch == ' ').count(),
        nfc_normalized: text.nfc().eq(text.chars()),
        ..TextMetrics::default()
    };
    let mut collector = FindingCollector::new(max_findings);
    let mut non_ascii_spaces = Vec::new();
    let mut variation_selectors = Vec::new();

    for (index, scalar) in scalars.iter().copied().enumerate() {
        let cp = scalar.ch as u32;
        let decision = contextual_decisions[index];

        if is_non_ascii_space(cp) {
            metrics.non_ascii_space_count += 1;
            non_ascii_spaces.push(scalar);
        }

        if is_variation_selector(cp) {
            metrics.variation_selector_count += 1;
        }

        if is_unexpected_control(cp) {
            metrics.format_control_count += 1;
            collector.push(codepoint_finding(
                text,
                scalar,
                "unicode.control_character",
                "control_character",
                Severity::High,
                "Unexpected C0/C1 control character is embedded in text",
            ));
            continue;
        }

        let Some(kind) = decision.kind else {
            continue;
        };

        if !matches!(kind, CarrierKind::ExoticSpace | CarrierKind::PrivateUse) {
            metrics.format_control_count += 1;
        }

        match kind {
            CarrierKind::ExoticSpace => {}
            CarrierKind::Tag if decision.contextually_valid => {
                metrics.unicode_tag_count += 1;
                collector.push(codepoint_finding(
                    text,
                    scalar,
                    "unicode.tag_character",
                    "unicode_tag",
                    Severity::Info,
                    decision.reason,
                ));
            }
            CarrierKind::Tag => {
                metrics.unicode_tag_count += 1;
                collector.push(codepoint_finding(
                    text,
                    scalar,
                    "unicode.tag_character",
                    "unicode_tag",
                    Severity::High,
                    decision.reason,
                ));
            }
            CarrierKind::VariationSelector if decision.contextually_valid => {
                collector.push(codepoint_finding(
                    text,
                    scalar,
                    "unicode.variation_selector_channel",
                    "variation_selector",
                    Severity::Info,
                    decision.reason,
                ));
            }
            CarrierKind::VariationSelector => variation_selectors.push(scalar),
            CarrierKind::Joiner if decision.contextually_valid => {
                collector.push(codepoint_finding(
                    text,
                    scalar,
                    "unicode.joiner",
                    "zero_width_joiner",
                    Severity::Info,
                    decision.reason,
                ));
            }
            CarrierKind::Joiner => collector.push(codepoint_finding(
                text,
                scalar,
                "unicode.joiner",
                "zero_width_joiner",
                Severity::Warning,
                decision.reason,
            )),
            CarrierKind::Bidi => collector.push(codepoint_finding(
                text,
                scalar,
                "unicode.bidi_control",
                "bidi_control",
                if decision.contextually_valid {
                    Severity::Info
                } else {
                    Severity::Warning
                },
                decision.reason,
            )),
            CarrierKind::PrivateUse => collector.push(codepoint_finding(
                text,
                scalar,
                "unicode.private_use",
                "private_use",
                Severity::Warning,
                decision.reason,
            )),
            CarrierKind::SoftHyphen => collector.push(codepoint_finding(
                text,
                scalar,
                "unicode.format_control",
                "format_control",
                Severity::Info,
                decision.reason,
            )),
            CarrierKind::FormatControl | CarrierKind::ScriptFormat => {
                if decision.contextually_valid {
                    collector.push(codepoint_finding(
                        text,
                        scalar,
                        "unicode.format_control",
                        "format_control",
                        Severity::Info,
                        decision.reason,
                    ));
                } else {
                    let (severity, message) = classified_format_control(cp)
                        .unwrap_or((Severity::Warning, decision.reason));
                    collector.push(codepoint_finding(
                        text,
                        scalar,
                        "unicode.format_control",
                        "format_control",
                        severity,
                        message,
                    ));
                }
            }
        }
    }

    analyze_spaces(
        text,
        &non_ascii_spaces,
        metrics.ascii_space_count,
        &mut collector,
    );
    analyze_variation_selectors(text, &variation_selectors, &mut collector);
    analyze_mixed_scripts(text, &scalars, &mut metrics, &mut collector);
    analyze_combining_runs(text, &scalars, &mut collector);
    analyze_trailing_whitespace(text, byte_base, &mut metrics, &mut collector);

    if !metrics.nfc_normalized {
        let scalar = scalars.first().copied().unwrap_or(Scalar {
            ch: '\0',
            local_byte_offset: 0,
            byte_offset: byte_base,
            char_offset: 0,
            line: 1,
            column: 1,
        });
        collector.push(Finding {
            rule_id: "unicode.non_nfc",
            category: "normalization",
            severity: Severity::Info,
            message: "Text is not normalized to Unicode NFC".to_owned(),
            codepoint: None,
            unicode_name: None,
            byte_offset: scalar.byte_offset,
            char_offset: scalar.char_offset,
            line: scalar.line,
            column: scalar.column,
            context: context_at(text, scalar.local_byte_offset),
            interpretation: INTERPRETATION,
        });
    }

    TextAnalysis {
        metrics,
        findings: collector.findings,
        truncated: collector.truncated,
    }
}

fn collect_scalars(text: &str, byte_base: usize) -> Vec<Scalar> {
    let mut line = 1;
    let mut column = 1;
    let mut scalars = Vec::with_capacity(text.chars().count());

    for (char_offset, (byte_offset, ch)) in text.char_indices().enumerate() {
        scalars.push(Scalar {
            ch,
            local_byte_offset: byte_offset,
            byte_offset: byte_offset + byte_base,
            char_offset,
            line,
            column,
        });

        if ch == '\n' {
            line += 1;
            column = 1;
        } else {
            column += 1;
        }
    }

    scalars
}

fn analyze_spaces(
    text: &str,
    spaces: &[Scalar],
    ascii_spaces: usize,
    collector: &mut FindingCollector,
) {
    if spaces.is_empty() {
        return;
    }

    let total = ascii_spaces + spaces.len();
    let ratio = spaces.len() as f64 / total.max(1) as f64;
    let severity = if spaces.len() >= 4 && ratio >= 0.02 {
        Severity::Warning
    } else {
        Severity::Info
    };
    let first = spaces[0];
    collector.push(Finding {
        rule_id: "unicode.non_ascii_spaces",
        category: "whitespace_channel",
        severity,
        message: format!(
            "Found {} non-ASCII space characters ({:.2}% of space-like characters)",
            spaces.len(),
            ratio * 100.0
        ),
        codepoint: Some(format_codepoint(first.ch)),
        unicode_name: Some(unicode_name(first.ch)),
        byte_offset: first.byte_offset,
        char_offset: first.char_offset,
        line: first.line,
        column: first.column,
        context: context_at(text, first.local_byte_offset),
        interpretation: INTERPRETATION,
    });
}

fn analyze_variation_selectors(text: &str, selectors: &[Scalar], collector: &mut FindingCollector) {
    if selectors.is_empty() {
        return;
    }

    let first = selectors[0];
    let severity = if selectors.len() >= 4 {
        Severity::High
    } else {
        Severity::Warning
    };
    collector.push(Finding {
        rule_id: "unicode.variation_selector_channel",
        category: "variation_selector",
        severity,
        message: format!(
            "Found {} variation selector(s) outside a recognized emoji, CJK, or Mongolian context",
            selectors.len()
        ),
        codepoint: Some(format_codepoint(first.ch)),
        unicode_name: Some(unicode_name(first.ch)),
        byte_offset: first.byte_offset,
        char_offset: first.char_offset,
        line: first.line,
        column: first.column,
        context: context_at(text, first.local_byte_offset),
        interpretation: INTERPRETATION,
    });
}

fn analyze_mixed_scripts(
    text: &str,
    scalars: &[Scalar],
    metrics: &mut TextMetrics,
    collector: &mut FindingCollector,
) {
    let mut start = None;

    for index in 0..=scalars.len() {
        let continues = scalars
            .get(index)
            .is_some_and(|scalar| scalar.ch.is_alphabetic());

        if continues {
            start.get_or_insert(index);
            continue;
        }

        let Some(token_start) = start.take() else {
            continue;
        };
        let token = &scalars[token_start..index];
        let mut scripts = 0_u8;
        for scalar in token {
            scripts |= script_bit(scalar.ch);
        }
        let relevant_scripts = scripts & 0b111;
        if relevant_scripts.count_ones() < 2 {
            continue;
        }

        metrics.mixed_script_token_count += 1;
        let first = token[0];
        let token_text: String = token.iter().map(|scalar| scalar.ch).collect();
        collector.push(Finding {
            rule_id: "unicode.mixed_script_token",
            category: "homoglyph_heuristic",
            severity: Severity::Warning,
            message: format!(
                "Token mixes Latin, Cyrillic, or Greek scripts: {}",
                visible_text(&token_text)
            ),
            codepoint: None,
            unicode_name: None,
            byte_offset: first.byte_offset,
            char_offset: first.char_offset,
            line: first.line,
            column: first.column,
            context: context_at(text, first.local_byte_offset),
            interpretation: INTERPRETATION,
        });
    }
}

fn analyze_combining_runs(text: &str, scalars: &[Scalar], collector: &mut FindingCollector) {
    let mut index = 0;
    while index < scalars.len() {
        if !is_combining_mark(scalars[index].ch as u32) {
            index += 1;
            continue;
        }
        let start = index;
        while index < scalars.len() && is_combining_mark(scalars[index].ch as u32) {
            index += 1;
        }
        let count = index - start;
        if count <= 3 {
            continue;
        }
        let first = scalars[start];
        collector.push(Finding {
            rule_id: "unicode.combining_mark_run",
            category: "combining_marks",
            severity: Severity::Warning,
            message: format!("Suspicious run of {count} combining marks"),
            codepoint: Some(format_codepoint(first.ch)),
            unicode_name: Some("COMBINING MARK".to_owned()),
            byte_offset: first.byte_offset,
            char_offset: first.char_offset,
            line: first.line,
            column: first.column,
            context: context_at(text, first.local_byte_offset),
            interpretation: INTERPRETATION,
        });
    }
}

fn analyze_trailing_whitespace(
    text: &str,
    byte_base: usize,
    metrics: &mut TextMetrics,
    collector: &mut FindingCollector,
) {
    let mut byte_cursor = 0;
    let mut first = None;
    let mut nonblank_single_space_lines = 0;
    let mut markdown_hard_break_lines = 0;
    let mut other_nonblank_lines = 0;

    for (line_index, raw_line) in text.split_inclusive('\n').enumerate() {
        let without_lf = raw_line.strip_suffix('\n').unwrap_or(raw_line);
        let content = without_lf.strip_suffix('\r').unwrap_or(without_lf);
        let trimmed = content.trim_end_matches([' ', '\t']);
        let suffix = &content[trimmed.len()..];

        if suffix.is_empty() {
            byte_cursor += raw_line.len();
            continue;
        }

        let spaces = suffix.bytes().filter(|byte| *byte == b' ').count();
        let tabs = suffix.bytes().filter(|byte| *byte == b'\t').count();
        let padded_blank = trimmed.is_empty();

        metrics.trailing_whitespace_line_count += 1;
        metrics.trailing_space_count += spaces;
        metrics.trailing_tab_count += tabs;
        if padded_blank {
            metrics.padded_blank_line_count += 1;
        } else if tabs == 0 && spaces == 1 {
            nonblank_single_space_lines += 1;
        } else if tabs == 0 && spaces == 2 {
            markdown_hard_break_lines += 1;
        } else {
            other_nonblank_lines += 1;
        }

        if first.is_none() {
            let local_byte_offset = byte_cursor + trimmed.len();
            first = Some((
                local_byte_offset,
                text[..local_byte_offset].chars().count(),
                line_index + 1,
                trimmed.chars().count() + 1,
                trailing_whitespace_context(content, trimmed.len()),
            ));
        }

        byte_cursor += raw_line.len();
    }

    let Some((local_byte_offset, char_offset, line, column, context)) = first else {
        return;
    };

    let severity = if metrics.trailing_tab_count > 0
        || nonblank_single_space_lines >= 4
        || other_nonblank_lines > 0
    {
        Severity::Warning
    } else {
        Severity::Info
    };

    collector.push(Finding {
        rule_id: "text.trailing_whitespace",
        category: "whitespace_channel",
        severity,
        message: format!(
            "Trailing whitespace appears on {} line(s): {} single-space content line(s), {} Markdown hard-break line(s), {} other content line(s), {} padded blank line(s)",
            metrics.trailing_whitespace_line_count,
            nonblank_single_space_lines,
            markdown_hard_break_lines,
            other_nonblank_lines,
            metrics.padded_blank_line_count
        ),
        codepoint: Some(if metrics.trailing_tab_count > 0 {
            "U+0009".to_owned()
        } else {
            "U+0020".to_owned()
        }),
        unicode_name: Some(if metrics.trailing_tab_count > 0 {
            "CHARACTER TABULATION".to_owned()
        } else {
            "SPACE".to_owned()
        }),
        byte_offset: local_byte_offset + byte_base,
        char_offset,
        line,
        column,
        context,
        interpretation: INTERPRETATION,
    });
}

fn trailing_whitespace_context(content: &str, suffix_byte_offset: usize) -> String {
    let prefix: String = content[..suffix_byte_offset]
        .chars()
        .rev()
        .take(32)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    let mut result = visible_text(&prefix);
    for ch in content[suffix_byte_offset..].chars() {
        match ch {
            ' ' => result.push_str("<SPACE>"),
            '\t' => result.push_str("<TAB>"),
            value => result.push(value),
        }
    }
    result
}

fn codepoint_finding(
    text: &str,
    scalar: Scalar,
    rule_id: &'static str,
    category: &'static str,
    severity: Severity,
    message: &str,
) -> Finding {
    Finding {
        rule_id,
        category,
        severity,
        message: message.to_owned(),
        codepoint: Some(format_codepoint(scalar.ch)),
        unicode_name: Some(unicode_name(scalar.ch)),
        byte_offset: scalar.byte_offset,
        char_offset: scalar.char_offset,
        line: scalar.line,
        column: scalar.column,
        context: context_at(text, scalar.local_byte_offset),
        interpretation: INTERPRETATION,
    }
}

fn classified_format_control(cp: u32) -> Option<(Severity, &'static str)> {
    match cp {
        0x200B => Some((
            Severity::High,
            "Zero-width space is invisible in rendered text",
        )),
        0x2060 => Some((
            Severity::Warning,
            "Word joiner is invisible in rendered text",
        )),
        0x2061..=0x2064 => Some((
            Severity::High,
            "Invisible mathematical operator can carry hidden distinctions",
        )),
        0x00AD => Some((Severity::Info, "Soft hyphen is normally invisible")),
        0x034F => Some((Severity::Warning, "Combining grapheme joiner is invisible")),
        0x061C | 0x200E | 0x200F => Some((
            Severity::Info,
            "Directional mark may be legitimate in bidirectional text",
        )),
        0x180E => Some((
            Severity::High,
            "Mongolian vowel separator is normally invisible",
        )),
        0xFEFF => Some((
            Severity::High,
            "Unexpected byte-order-mark character appears inside decoded text",
        )),
        0xFFF9..=0xFFFB => Some((
            Severity::High,
            "Interlinear annotation control is invisible or display-affecting",
        )),
        _ => None,
    }
}

fn is_joiner(cp: u32) -> bool {
    matches!(cp, 0x200C | 0x200D)
}

fn is_bidi_control(cp: u32) -> bool {
    matches!(cp, 0x202A..=0x202E | 0x2066..=0x2069)
}

fn is_unicode_tag(cp: u32) -> bool {
    matches!(cp, 0xE0000..=0xE007F)
}

fn is_variation_selector(cp: u32) -> bool {
    matches!(cp, 0xFE00..=0xFE0F | 0xE0100..=0xE01EF)
}

fn is_non_ascii_space(cp: u32) -> bool {
    matches!(
        cp,
        0x00A0 | 0x1680 | 0x2000..=0x200A | 0x202F | 0x205F | 0x3000
    )
}

fn is_combining_mark(cp: u32) -> bool {
    matches!(
        cp,
        0x0300..=0x036F
            | 0x1AB0..=0x1AFF
            | 0x1DC0..=0x1DFF
            | 0x20D0..=0x20FF
            | 0xFE20..=0xFE2F
    )
}

fn script_bit(ch: char) -> u8 {
    let cp = ch as u32;
    if ch.is_ascii_alphabetic() || matches!(cp, 0x00C0..=0x024F | 0x1E00..=0x1EFF) {
        0b001
    } else if matches!(cp, 0x0370..=0x03FF | 0x1F00..=0x1FFF) {
        0b010
    } else if matches!(cp, 0x0400..=0x052F | 0x2DE0..=0x2DFF | 0xA640..=0xA69F) {
        0b100
    } else {
        0b1000
    }
}

fn format_codepoint(ch: char) -> String {
    format!("U+{:04X}", ch as u32)
}

fn unicode_name(ch: char) -> String {
    let cp = ch as u32;
    match cp {
        0x00A0 => "NO-BREAK SPACE".to_owned(),
        0x00AD => "SOFT HYPHEN".to_owned(),
        0x034F => "COMBINING GRAPHEME JOINER".to_owned(),
        0x061C => "ARABIC LETTER MARK".to_owned(),
        0x180E => "MONGOLIAN VOWEL SEPARATOR".to_owned(),
        0x200B => "ZERO WIDTH SPACE".to_owned(),
        0x200C => "ZERO WIDTH NON-JOINER".to_owned(),
        0x200D => "ZERO WIDTH JOINER".to_owned(),
        0x200E => "LEFT-TO-RIGHT MARK".to_owned(),
        0x200F => "RIGHT-TO-LEFT MARK".to_owned(),
        0x202A => "LEFT-TO-RIGHT EMBEDDING".to_owned(),
        0x202B => "RIGHT-TO-LEFT EMBEDDING".to_owned(),
        0x202C => "POP DIRECTIONAL FORMATTING".to_owned(),
        0x202D => "LEFT-TO-RIGHT OVERRIDE".to_owned(),
        0x202E => "RIGHT-TO-LEFT OVERRIDE".to_owned(),
        0x202F => "NARROW NO-BREAK SPACE".to_owned(),
        0x2060 => "WORD JOINER".to_owned(),
        0x2061 => "FUNCTION APPLICATION".to_owned(),
        0x2062 => "INVISIBLE TIMES".to_owned(),
        0x2063 => "INVISIBLE SEPARATOR".to_owned(),
        0x2064 => "INVISIBLE PLUS".to_owned(),
        0x2066 => "LEFT-TO-RIGHT ISOLATE".to_owned(),
        0x2067 => "RIGHT-TO-LEFT ISOLATE".to_owned(),
        0x2068 => "FIRST STRONG ISOLATE".to_owned(),
        0x2069 => "POP DIRECTIONAL ISOLATE".to_owned(),
        0xFEFF => "ZERO WIDTH NO-BREAK SPACE".to_owned(),
        0xFE00..=0xFE0F => format!("VARIATION SELECTOR-{}", cp - 0xFE00 + 1),
        0xE0100..=0xE01EF => format!("VARIATION SELECTOR-{}", cp - 0xE0100 + 17),
        0xE0000 => "TAG BASE".to_owned(),
        0xE0001 => "LANGUAGE TAG".to_owned(),
        0xE0020..=0xE007E => format!("TAG CHARACTER U+{cp:04X}"),
        0xE007F => "CANCEL TAG".to_owned(),
        _ => format!("UNICODE CHARACTER U+{cp:04X}"),
    }
}

fn is_unexpected_control(cp: u32) -> bool {
    matches!(cp, 0x0000..=0x001F | 0x007F..=0x009F) && !matches!(cp, 0x0009 | 0x000A | 0x000D)
}

fn context_at(text: &str, byte_offset: usize) -> String {
    if text.is_empty() {
        return String::new();
    }
    let offset = byte_offset.min(text.len());
    let char_index = text[..offset].chars().count();
    let chars: Vec<char> = text.chars().collect();
    let start = char_index.saturating_sub(16);
    let end = (char_index + 17).min(chars.len());
    visible_text(&chars[start..end].iter().collect::<String>())
}

fn visible_text(value: &str) -> String {
    let mut result = String::new();
    for ch in value.chars() {
        match ch {
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            value
                if value.is_control()
                    || classified_format_control(value as u32).is_some()
                    || is_joiner(value as u32)
                    || is_bidi_control(value as u32)
                    || is_unicode_tag(value as u32)
                    || is_variation_selector(value as u32) =>
            {
                result.push_str(&format!("<{}>", format_codepoint(value)));
            }
            value if is_non_ascii_space(value as u32) => {
                result.push_str(&format!("<{}>", format_codepoint(value)));
            }
            value => result.push(value),
        }
    }
    result
}

struct FindingCollector {
    max: usize,
    findings: Vec<Finding>,
    truncated: usize,
}

impl FindingCollector {
    fn new(max: usize) -> Self {
        Self {
            max,
            findings: Vec::new(),
            truncated: 0,
        }
    }

    fn push(&mut self, finding: Finding) {
        if self.findings.len() < self.max {
            self.findings.push(finding);
        } else {
            self.truncated += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::analyze_text;
    use crate::model::Severity;

    #[test]
    fn clean_ascii_text_has_no_findings() {
        let result = analyze_text("ordinary markdown\n", 0, 100);
        assert!(result.findings.is_empty());
        assert!(result.metrics.nfc_normalized);
    }

    #[test]
    fn zero_width_space_is_high_severity() {
        let text = format!("hello{}world", char::from_u32(0x200B).unwrap());
        let result = analyze_text(&text, 0, 100);
        assert!(result.findings.iter().any(|finding| {
            finding.rule_id == "unicode.format_control" && finding.severity == Severity::High
        }));
    }

    #[test]
    fn mixed_latin_and_cyrillic_token_is_reported() {
        let text = format!("p{}ypal", char::from_u32(0x0430).unwrap());
        let result = analyze_text(&text, 0, 100);
        assert!(
            result
                .findings
                .iter()
                .any(|finding| finding.rule_id == "unicode.mixed_script_token")
        );
    }

    #[test]
    fn ordinary_emoji_selector_is_informational() {
        let text = format!(
            "{}{}",
            char::from_u32(0x2764).unwrap(),
            char::from_u32(0xFE0F).unwrap()
        );
        let result = analyze_text(&text, 0, 100);
        assert!(result.findings.iter().any(|finding| {
            finding.rule_id == "unicode.variation_selector_channel"
                && finding.severity == Severity::Info
        }));
    }

    #[test]
    fn unicode_tag_character_is_high_severity() {
        let text = format!("a{}b", char::from_u32(0xE0061).unwrap());
        let result = analyze_text(&text, 0, 100);
        assert!(result.findings.iter().any(|finding| {
            finding.rule_id == "unicode.tag_character" && finding.severity == Severity::High
        }));
    }

    #[test]
    fn byte_offsets_include_utf8_bom_without_breaking_context() {
        let text = format!("é{}x", char::from_u32(0x200B).unwrap());
        let result = analyze_text(&text, 3, 100);
        let finding = result
            .findings
            .iter()
            .find(|finding| finding.rule_id == "unicode.format_control")
            .unwrap();
        assert_eq!(finding.byte_offset, 5);
        assert!(finding.context.contains("U+200B"));
    }

    #[test]
    fn emoji_joiner_is_informational() {
        let text = format!(
            "{}{}{}",
            char::from_u32(0x1F469).unwrap(),
            char::from_u32(0x200D).unwrap(),
            char::from_u32(0x1F4BB).unwrap()
        );
        let result = analyze_text(&text, 0, 100);
        assert!(result.findings.iter().any(|finding| {
            finding.rule_id == "unicode.joiner" && finding.severity == Severity::Info
        }));
    }

    #[test]
    fn complete_flag_tags_are_informational() {
        let text = "🏴\u{E0067}\u{E0062}\u{E0073}\u{E0063}\u{E0074}\u{E007F}";
        let result = analyze_text(text, 0, 100);
        assert!(result.findings.iter().any(|finding| {
            finding.rule_id == "unicode.tag_character" && finding.severity == Severity::Info
        }));
    }

    #[test]
    fn private_use_character_requires_review() {
        let result = analyze_text("a\u{E000}b", 0, 100);
        assert!(result.findings.iter().any(|finding| {
            finding.rule_id == "unicode.private_use" && finding.severity == Severity::Warning
        }));
    }

    #[test]
    fn floating_emoji_selector_is_reported() {
        let result = analyze_text("a\u{FE0F}b", 0, 100);
        assert!(result.findings.iter().any(|finding| {
            finding.rule_id == "unicode.variation_selector_channel"
                && finding.severity == Severity::Warning
        }));
    }

    #[test]
    fn dense_non_ascii_spaces_are_warning() {
        let nbsp = char::from_u32(0x00A0).unwrap();
        let text = format!("one{nbsp}two{nbsp}three{nbsp}four{nbsp}five");
        let result = analyze_text(&text, 0, 100);
        assert!(result.findings.iter().any(|finding| {
            finding.rule_id == "unicode.non_ascii_spaces" && finding.severity == Severity::Warning
        }));
    }

    #[test]
    fn supplementary_variation_selector_payload_is_high() {
        let selector = char::from_u32(0xE0100).unwrap();
        let text = format!("x{selector}{selector}{selector}{selector}");
        let result = analyze_text(&text, 0, 100);
        assert!(result.findings.iter().any(|finding| {
            finding.rule_id == "unicode.variation_selector_channel"
                && finding.severity == Severity::High
        }));
    }

    #[test]
    fn unexpected_ascii_control_is_high() {
        let text = "left\u{0001}right";
        let result = analyze_text(text, 0, 100);
        assert!(result.findings.iter().any(|finding| {
            finding.rule_id == "unicode.control_character" && finding.severity == Severity::High
        }));
    }

    #[test]
    fn repeated_single_trailing_spaces_are_warning() {
        let text = "one \ntwo \nthree \nfour \n";
        let result = analyze_text(text, 0, 100);
        assert_eq!(result.metrics.trailing_whitespace_line_count, 4);
        assert_eq!(result.metrics.trailing_space_count, 4);
        assert!(result.findings.iter().any(|finding| {
            finding.rule_id == "text.trailing_whitespace"
                && finding.severity == Severity::Warning
                && finding.context.ends_with("<SPACE>")
        }));
    }

    #[test]
    fn one_markdown_hard_break_is_informational() {
        let text = "line one  \nline two\n";
        let result = analyze_text(text, 0, 100);
        assert!(result.findings.iter().any(|finding| {
            finding.rule_id == "text.trailing_whitespace" && finding.severity == Severity::Info
        }));
    }

    #[test]
    fn findings_are_capped() {
        let zwsp = char::from_u32(0x200B).unwrap();
        let text: String = std::iter::repeat_n(zwsp, 20).collect();
        let result = analyze_text(&text, 0, 3);
        assert_eq!(result.findings.len(), 3);
        assert_eq!(result.truncated, 17);
    }
}
