use std::collections::HashSet;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CarrierKind {
    SoftHyphen,
    FormatControl,
    Bidi,
    Joiner,
    Tag,
    VariationSelector,
    ScriptFormat,
    PrivateUse,
    ExoticSpace,
}

impl CarrierKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::SoftHyphen => "soft_hyphen",
            Self::FormatControl => "format_control",
            Self::Bidi => "bidi",
            Self::Joiner => "joiner",
            Self::Tag => "tag_character",
            Self::VariationSelector => "variation_selector",
            Self::ScriptFormat => "script_format",
            Self::PrivateUse => "private_use",
            Self::ExoticSpace => "exotic_space",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecommendedAction {
    Keep,
    Remove,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CharDecision {
    pub kind: Option<CarrierKind>,
    pub action: RecommendedAction,
    pub contextually_valid: bool,
    pub reason: &'static str,
}

impl CharDecision {
    const fn ordinary() -> Self {
        Self {
            kind: None,
            action: RecommendedAction::Keep,
            contextually_valid: true,
            reason: "ordinary text",
        }
    }

    const fn preserve(kind: CarrierKind, reason: &'static str) -> Self {
        Self {
            kind: Some(kind),
            action: RecommendedAction::Keep,
            contextually_valid: true,
            reason,
        }
    }

    const fn report_only(kind: CarrierKind, reason: &'static str) -> Self {
        Self {
            kind: Some(kind),
            action: RecommendedAction::Keep,
            contextually_valid: false,
            reason,
        }
    }

    const fn remove(kind: CarrierKind, reason: &'static str) -> Self {
        Self {
            kind: Some(kind),
            action: RecommendedAction::Remove,
            contextually_valid: false,
            reason,
        }
    }
}

pub fn classify_text(text: &str) -> Vec<CharDecision> {
    let chars: Vec<char> = text.chars().collect();
    let valid_flag_tags = valid_flag_tag_indices(&chars);
    let valid_bidi_embeddings = valid_bidi_embedding_indices(&chars);
    let mut decisions = Vec::with_capacity(chars.len());
    let mut previous_base = None;

    for (index, ch) in chars.iter().copied().enumerate() {
        let previous_input = index
            .checked_sub(1)
            .and_then(|value| chars.get(value).copied());
        let next_input = chars.get(index + 1).copied();
        let decision = classify_char(
            ch,
            previous_base,
            previous_input,
            next_input,
            valid_flag_tags.contains(&index),
            valid_bidi_embeddings.contains(&index),
        );

        if decision.action == RecommendedAction::Keep && !is_glue(ch as u32) {
            previous_base = Some(ch);
        }
        decisions.push(decision);
    }

    decisions
}

fn classify_char(
    ch: char,
    previous_base: Option<char>,
    previous_input: Option<char>,
    next_input: Option<char>,
    valid_flag_tag: bool,
    valid_bidi_embedding: bool,
) -> CharDecision {
    let cp = ch as u32;

    if is_unexpected_control(cp) {
        return CharDecision::remove(
            CarrierKind::FormatControl,
            "unexpected C0/C1 control is embedded in text",
        );
    }

    if is_exotic_space(cp) {
        return CharDecision::report_only(
            CarrierKind::ExoticSpace,
            "non-ASCII space is preserved unless normalization is requested",
        );
    }

    if valid_bidi_embedding {
        return CharDecision::preserve(
            CarrierKind::Bidi,
            "paired legacy bidi embedding is load-bearing",
        );
    }
    if is_preservable_bidi(cp) {
        return CharDecision::preserve(
            CarrierKind::Bidi,
            "directional mark or isolate may be load-bearing in mixed-direction text",
        );
    }

    if let Some(previous) = previous_input {
        let previous_cp = previous as u32;
        if is_supplementary_variation_selector(cp) && is_cjk_ideograph(previous_cp) {
            return CharDecision::preserve(
                CarrierKind::VariationSelector,
                "CJK ideographic variation selector follows an ideograph",
            );
        }
        if is_mongolian_fvs(cp) && is_mongolian_base(previous_cp) {
            return CharDecision::preserve(
                CarrierKind::VariationSelector,
                "Mongolian variation selector follows a Mongolian base",
            );
        }
        if matches!(cp, 0xFE00..=0xFE0D) && is_cjk_ideograph(previous_cp) {
            return CharDecision::preserve(
                CarrierKind::VariationSelector,
                "standardized variation selector follows a CJK ideograph",
            );
        }
        if matches!(cp, 0xFE0E | 0xFE0F) && is_emoji_base(previous_cp) {
            return CharDecision::preserve(
                CarrierKind::VariationSelector,
                "emoji presentation selector follows an emoji-capable base",
            );
        }
    }

    if cp == 0x200D
        && previous_base.is_some_and(|value| is_emoji_base(value as u32))
        && next_input.is_some_and(|value| is_emoji_base(value as u32))
    {
        return CharDecision::preserve(
            CarrierKind::Joiner,
            "zero-width joiner connects an emoji sequence",
        );
    }

    if matches!(cp, 0x200C | 0x200D)
        && previous_input
            .and_then(|value| joining_script(value as u32))
            .is_some_and(|script| {
                next_input
                    .and_then(|value| joining_script(value as u32))
                    .is_some_and(|next_script| next_script == script)
            })
    {
        return CharDecision::preserve(
            CarrierKind::Joiner,
            "joiner is between letters or marks from the same joining script",
        );
    }

    if is_tag(cp) && valid_flag_tag {
        return CharDecision::preserve(
            CarrierKind::Tag,
            "tag character belongs to a complete subdivision-flag sequence",
        );
    }

    if is_mongolian_fvs(cp) && previous_base.is_some_and(|value| is_mongolian_letter(value as u32))
    {
        return CharDecision::preserve(
            CarrierKind::VariationSelector,
            "Mongolian selector remains bound to the preceding letter",
        );
    }
    if matches!(cp, 0x17B4 | 0x17B5)
        && previous_base.is_some_and(|value| is_khmer_letter(value as u32))
    {
        return CharDecision::preserve(
            CarrierKind::ScriptFormat,
            "Khmer inherent vowel follows a Khmer letter",
        );
    }
    if matches!(cp, 0x115F | 0x1160)
        && previous_base.is_some_and(|value| is_hangul_jamo(value as u32))
    {
        return CharDecision::preserve(
            CarrierKind::ScriptFormat,
            "Hangul filler follows a jamo base",
        );
    }
    if is_orthographic_format(cp) {
        return CharDecision::preserve(
            CarrierKind::ScriptFormat,
            "script-specific format character has an orthographic role",
        );
    }

    if is_private_use(cp) {
        return CharDecision::report_only(
            CarrierKind::PrivateUse,
            "private-use characters have no portable interpretation and require review",
        );
    }
    if cp == 0x00AD {
        return CharDecision::report_only(
            CarrierKind::SoftHyphen,
            "soft hyphen can be legitimate discretionary hyphenation and requires review",
        );
    }
    if matches!(cp, 0x200C | 0x200D) {
        return CharDecision::remove(
            CarrierKind::Joiner,
            "joiner is not in a recognized emoji or same-script context",
        );
    }
    if is_tag(cp) {
        return CharDecision::remove(
            CarrierKind::Tag,
            "tag character is outside a complete subdivision-flag sequence",
        );
    }
    if is_variation_selector(cp) || matches!(cp, 0x180B..=0x180D) {
        return CharDecision::remove(
            CarrierKind::VariationSelector,
            "variation selector is not bound to a recognized base",
        );
    }
    if is_bidi(cp) {
        return CharDecision::remove(
            CarrierKind::Bidi,
            "bidi override, deprecated control, or unpaired embedding changes display order",
        );
    }
    if matches!(cp, 0x115F | 0x1160 | 0x17B4 | 0x17B5) {
        return CharDecision::remove(
            CarrierKind::ScriptFormat,
            "script-specific invisible is outside a recognized load-bearing context",
        );
    }
    if is_ambiguous_format(cp) {
        return CharDecision::report_only(
            CarrierKind::FormatControl,
            "invisible character can be load-bearing in typography or specialized notation and requires review",
        );
    }

    CharDecision::ordinary()
}

fn valid_flag_tag_indices(chars: &[char]) -> HashSet<usize> {
    let mut valid = HashSet::new();
    let mut index = 0;
    while index < chars.len() {
        if chars[index] as u32 != 0x1F3F4 {
            index += 1;
            continue;
        }
        let mut cursor = index + 1;
        while cursor < chars.len() && matches!(chars[cursor] as u32, 0xE0020..=0xE007E) {
            cursor += 1;
        }
        if cursor > index + 1 && cursor < chars.len() && chars[cursor] as u32 == 0xE007F {
            valid.extend(index + 1..=cursor);
            index = cursor + 1;
        } else {
            index += 1;
        }
    }
    valid
}

fn valid_bidi_embedding_indices(chars: &[char]) -> HashSet<usize> {
    let mut valid = HashSet::new();
    let mut stack = Vec::new();
    for (index, ch) in chars.iter().copied().enumerate() {
        match ch as u32 {
            cp @ (0x202A | 0x202B | 0x202D | 0x202E) => stack.push((cp, index)),
            0x202C => {
                if let Some((opener, opener_index)) = stack.pop()
                    && matches!(opener, 0x202A | 0x202B)
                {
                    valid.insert(opener_index);
                    valid.insert(index);
                }
            }
            _ => {}
        }
    }
    valid
}

fn joining_script(cp: u32) -> Option<u8> {
    if !is_joining_letter_or_mark(cp) {
        return None;
    }
    match cp {
        0x0600..=0x08FF => Some(1),
        0x0900..=0x0DFF => Some(2),
        0x0F00..=0x109F => Some(3),
        0x1780..=0x17FF => Some(4),
        0x1800..=0x18AF => Some(5),
        _ => None,
    }
}

fn is_joining_letter_or_mark(cp: u32) -> bool {
    char::from_u32(cp).is_some_and(char::is_alphabetic)
        || matches!(
            cp,
            0x0610..=0x061A
                | 0x064B..=0x065F
                | 0x0670
                | 0x06D6..=0x06ED
                | 0x08D3..=0x08FF
                | 0x0900..=0x0903
                | 0x093A..=0x094D
                | 0x0951..=0x0957
                | 0x0962..=0x0963
                | 0x0981..=0x0983
                | 0x09BC
                | 0x09BE..=0x09CD
                | 0x09D7
                | 0x09E2..=0x09E3
                | 0x0A01..=0x0A03
                | 0x0A3C
                | 0x0A3E..=0x0A4D
                | 0x0A81..=0x0A83
                | 0x0ABC
                | 0x0ABE..=0x0ACD
                | 0x0B01..=0x0B03
                | 0x0B3C
                | 0x0B3E..=0x0B4D
                | 0x0BBE..=0x0BCD
                | 0x0C00..=0x0C04
                | 0x0C3C..=0x0C56
                | 0x0C81..=0x0C83
                | 0x0CBC..=0x0CCD
                | 0x0D00..=0x0D03
                | 0x0D3B..=0x0D4D
                | 0x0F18..=0x0F19
                | 0x0F35
                | 0x0F37
                | 0x0F39
                | 0x0F71..=0x0F84
                | 0x1780..=0x17D3
                | 0x180B..=0x180D
                | 0x1885..=0x1886
                | 0x18A9
        )
}

fn is_glue(cp: u32) -> bool {
    matches!(
        cp,
        0x200C | 0x200D | 0xFE0E | 0xFE0F | 0x180B..=0x180D | 0x17B4 | 0x17B5 | 0x115F | 0x1160 | 0xE0020..=0xE007F
    ) || is_variation_selector(cp)
}

fn is_preservable_bidi(cp: u32) -> bool {
    matches!(cp, 0x061C | 0x200E | 0x200F | 0x2066..=0x2069)
}

fn is_bidi(cp: u32) -> bool {
    matches!(cp, 0x061C | 0x200E | 0x200F | 0x202A..=0x202E | 0x2066..=0x206F)
}

fn is_tag(cp: u32) -> bool {
    matches!(cp, 0xE0000..=0xE007F)
}

fn is_variation_selector(cp: u32) -> bool {
    matches!(cp, 0xFE00..=0xFE0F | 0xE0100..=0xE01EF)
}

fn is_supplementary_variation_selector(cp: u32) -> bool {
    matches!(cp, 0xE0100..=0xE01EF)
}

fn is_mongolian_fvs(cp: u32) -> bool {
    matches!(cp, 0x180B..=0x180D)
}

fn is_private_use(cp: u32) -> bool {
    matches!(cp, 0xE000..=0xF8FF | 0xF0000..=0xFFFFD | 0x100000..=0x10FFFD)
}

fn is_exotic_space(cp: u32) -> bool {
    matches!(
        cp,
        0x00A0 | 0x1680 | 0x2000..=0x200A | 0x202F | 0x205F | 0x3000
    )
}

fn is_orthographic_format(cp: u32) -> bool {
    matches!(
        cp,
        0x0600..=0x0605
            | 0x06DD
            | 0x070F
            | 0x0890..=0x0891
            | 0x08E2
            | 0x110BD
            | 0x110CD
            | 0x13430..=0x13455
    )
}

fn is_ambiguous_format(cp: u32) -> bool {
    matches!(
        cp,
        0x034F
            | 0x180E
            | 0x200B
            | 0x2060..=0x2064
            | 0xFEFF
            | 0xFFF9..=0xFFFB
            | 0x1BCA0..=0x1BCA3
            | 0x1D173..=0x1D17A
    )
}

fn is_unexpected_control(cp: u32) -> bool {
    matches!(cp, 0x0000..=0x001F | 0x007F..=0x009F) && !matches!(cp, 0x0009 | 0x000A | 0x000D)
}

fn is_emoji_base(cp: u32) -> bool {
    matches!(
        cp,
        0x1F000..=0x1FAFF
            | 0x2190..=0x27BF
            | 0x2B00..=0x2BFF
            | 0x00A9
            | 0x00AE
            | 0x2122
            | 0x3030
            | 0x303D
            | 0x3297
            | 0x3299
            | 0x0023
            | 0x002A
            | 0x0030..=0x0039
    )
}

fn is_cjk_ideograph(cp: u32) -> bool {
    matches!(
        cp,
        0x3400..=0x4DBF
            | 0x4E00..=0x9FFF
            | 0xF900..=0xFAFF
            | 0x20000..=0x323AF
    )
}

fn is_mongolian_base(cp: u32) -> bool {
    matches!(cp, 0x1800..=0x18AF)
}

fn is_mongolian_letter(cp: u32) -> bool {
    matches!(cp, 0x1820..=0x1878 | 0x1880..=0x1884 | 0x1887..=0x18A8)
}

fn is_khmer_letter(cp: u32) -> bool {
    matches!(cp, 0x1780..=0x17A2 | 0x17A5..=0x17B3)
}

fn is_hangul_jamo(cp: u32) -> bool {
    matches!(cp, 0x1100..=0x11FF | 0xA960..=0xA97C | 0xD7B0..=0xD7C6)
}

#[cfg(test)]
mod tests {
    use super::{CarrierKind, RecommendedAction, classify_text};

    fn decision_for(text: &str, target: char) -> super::CharDecision {
        text.chars()
            .zip(classify_text(text))
            .find_map(|(ch, decision)| (ch == target).then_some(decision))
            .expect("target character in fixture")
    }

    #[test]
    fn floating_joiner_is_removable() {
        let decision = decision_for("a\u{200D}b", '\u{200D}');
        assert_eq!(decision.kind, Some(CarrierKind::Joiner));
        assert_eq!(decision.action, RecommendedAction::Remove);
    }

    #[test]
    fn emoji_joiner_is_preserved() {
        let decision = decision_for("👨\u{200D}👩", '\u{200D}');
        assert_eq!(decision.action, RecommendedAction::Keep);
        assert!(decision.contextually_valid);
    }

    #[test]
    fn same_script_joiners_are_preserved() {
        for text in ["می\u{200C}روم", "क्\u{200D}ष"] {
            assert!(classify_text(text).iter().any(|decision| {
                decision.kind == Some(CarrierKind::Joiner)
                    && decision.action == RecommendedAction::Keep
            }));
        }
    }

    #[test]
    fn complete_flag_tags_are_preserved() {
        let text = "🏴\u{E0067}\u{E0062}\u{E0073}\u{E0063}\u{E0074}\u{E007F}";
        assert!(classify_text(text).iter().all(|decision| {
            decision.kind != Some(CarrierKind::Tag) || decision.action == RecommendedAction::Keep
        }));
    }

    #[test]
    fn incomplete_flag_tags_are_removable() {
        let text = "🏴\u{E0067}\u{E0062}";
        assert_eq!(
            classify_text(text)
                .iter()
                .filter(|decision| decision.kind == Some(CarrierKind::Tag))
                .filter(|decision| decision.action == RecommendedAction::Remove)
                .count(),
            2
        );
    }

    #[test]
    fn load_bearing_script_formats_are_preserved() {
        for text in ["ᠠ\u{180B}ᠡ", "ក\u{17B4}ខ", "ᄀ\u{115F}ᅡ"] {
            assert!(classify_text(text).iter().any(|decision| {
                matches!(
                    decision.kind,
                    Some(CarrierKind::VariationSelector | CarrierKind::ScriptFormat)
                ) && decision.action == RecommendedAction::Keep
            }));
        }
    }

    #[test]
    fn private_use_is_report_only_by_default() {
        let decision = decision_for("a\u{E000}b", '\u{E000}');
        assert_eq!(decision.kind, Some(CarrierKind::PrivateUse));
        assert_eq!(decision.action, RecommendedAction::Keep);
        assert!(!decision.contextually_valid);
    }
}
