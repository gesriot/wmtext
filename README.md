# wmtext

`wmtext` is a local Rust hygiene and security CLI for observable Unicode, whitespace, and steganography signals in UTF-8 text files. It is designed for coding agents and CI. Its scope is source code, documentation, configuration, logs, and other text; media provenance and file metadata are intentionally out of scope.

It intentionally does **not** claim to detect or remove proprietary token-sampling watermarks such as Google's production SynthID Text or any unpublished Anthropic scheme without the provider's detector or secret configuration.

## Threat model and hard limit

`wmtext` addresses observable properties of the stored text: Unicode code points, bidirectional controls, mixed scripts, unusual whitespace, normalization, and related surface channels. Its sanitizer changes those surface properties only.

A statistical or token-sampling watermark lives in the model's choices of words and tokens. In a repository, that signal could be carried by prose, comments, docstrings, user-facing strings, identifiers, README files, and design notes. Unicode sanitation and formatters such as `rustfmt` or Prettier do not substantially rewrite those choices, so they do not remove such a watermark.

Public descriptions of model-level marks that survive copy/paste and light editing are consistent with token-sampling watermarking, but the exact architecture of an unpublished provider scheme cannot be inferred conclusively from product wording alone. Until a provider publishes the algorithm, keys, or an official detector, its presence in an individual file remains indeterminate.

Therefore:

- `no_supported_surface_signal_detected` does not mean `watermark_free`;
- a sanitizer result with `changed: false` does not rule out a statistical watermark;
- a sanitizer result with `changed: true` does not establish that a statistical watermark was removed;
- `wmtext` must not be described as a Claude, Gemini, or generic AI-watermark remover.

Substantive rewriting can weaken some statistical watermarks, especially in long prose, but it changes content and style, is not verifiable without the matching detector, and may introduce a mark from the rewriting model. Rewriting is deliberately outside this project.

## Build

```bash
cargo build --release
```

The binary is written to `target/release/wmtext`.

## Usage

```bash
# Scan one Markdown file
wmtext scan response.md

# Recursively scan a repository, respecting ignore files
wmtext scan .

# Versioned scan JSON for an agent
wmtext scan corpus --format json

# Include hidden files and fail only on high-severity findings
wmtext scan . --hidden --fail-on high

# Show rules
wmtext rules

# Preview sanitation without writing
wmtext sanitize response.md --dry-run --format json

# Write a sanitized copy
wmtext sanitize response.md --output response.cleaned.md

# Replace the source and create response.md.bak if it changes
wmtext sanitize response.md --in-place
```

Explicit files are considered regardless of extension. Directory walks use a configurable text-extension allowlist, do not follow symlinks, and exclude common generated/dependency directories such as `target`, `node_modules`, and `.git`.

## Exit codes

- `0`: scan completed and no finding met `--fail-on`;
- `1`: at least one finding met `--fail-on`;
- `2`: operational error, such as an unreadable or missing path.

The default threshold is `warning`. Informational findings such as isolated typographic spaces do not fail the scan by default.

## Sanitation policy

The sanitizer is intentionally opinionated for Russian/English source code and documentation. It removes every recognized invisible/format character and every Unicode private-use character, including contextually valid uses:

- zero-width spaces, joiners, and non-joiners;
- bidi marks, embeddings, overrides, isolates, and terminators;
- variation selectors and emoji presentation selectors;
- Unicode tag characters, including complete subdivision-flag sequences;
- UTF-8 BOM/zero-width no-break space, soft hyphens, combining grapheme joiners, word joiners, and invisible mathematical operators;
- Mongolian/Khmer/Hangul and other script-specific invisible format characters;
- BMP and supplementary private-use characters;
- unexpected C0/C1 controls other than tab, LF, and CR.

This policy can change emoji sequences, bidirectional text, mathematical Unicode notation, non-English orthography, icon-font glyphs, and other specialized text. Those formats are outside the selected Russian/English project profile.

### Known tradeoffs

- Removing a leading UTF-8 BOM can make older Windows tools mis-detect Russian text as a legacy code page, even though modern editors and compilers normally handle BOM-less UTF-8 correctly.
- Private-use characters are used by Nerd Fonts, Powerline prompts, icon fonts, and some legacy/internal encodings; those glyphs are deliberately removed.
- U+2061–U+2064 can encode invisible function application, multiplication, separators, and addition in technical mathematics; removal may lose machine-readable mathematical distinctions while leaving rendering nearly unchanged.
- Variation selectors and ZWJ can affect symbols such as arrows, copyright/trademark signs, keycaps, and flags in addition to pictorial emoji.
- Bidi controls and script-specific joiners can be load-bearing in embedded RTL or non-Russian/English quotations.

The CLI intentionally does not implement NFKC, non-ASCII-space normalization, or global homoglyph replacement. Non-ASCII spaces are detected but preserved.

`--strip-trailing-whitespace` is the only optional cleanup pass. It removes trailing ASCII whitespace while preserving Markdown hard breaks of exactly two spaces.

The sanitizer never performs global Cyrillic/Greek-to-Latin homoglyph replacement. Mixed-script tokens are detected for review instead.

An output path, `--in-place`, or `--dry-run` must be selected explicitly. In-place sanitation creates `INPUT.bak` and refuses to overwrite an existing backup.

## Interpretation

`no_supported_surface_signal_detected` means exactly that: the current Unicode/surface rules found nothing. The JSON report always records statistical watermark detection as `indeterminate`.

The scanner never reports `is_ai`, `human_written`, `clean`, or `infected`.

## Current rules

- invisible and format controls;
- bidi controls;
- Unicode tag characters;
- variation-selector channels;
- context-aware ZWJ/ZWNJ review;
- context-aware emoji, flag-tag, CJK, Mongolian, Khmer, Hangul, and bidi handling;
- private-use character detection and removal;
- unusual non-ASCII whitespace distribution;
- trailing spaces and tabs with Markdown-aware severity;
- mixed Latin/Cyrillic/Greek tokens;
- long combining-mark runs;
- informational NFC normalization check.

See [`DEEP_RESEARCH_AI_WATERMARKS.md`](DEEP_RESEARCH_AI_WATERMARKS.md) for the validated threat model and limitations.
