use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

struct TempFile(PathBuf);

impl TempFile {
    fn create(bytes: &[u8]) -> Self {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("wmtext-cli-test-{}-{id}.md", std::process::id()));
        fs::write(&path, bytes).expect("write temporary CLI fixture");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn unused() -> Self {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        Self(std::env::temp_dir().join(format!("wmtext-cli-output-{}-{id}.md", std::process::id())))
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

#[test]
fn clean_file_exits_zero() {
    let fixture = TempFile::create(b"# Ordinary Markdown\n\nNo hidden characters.\n");
    let output = Command::new(env!("CARGO_BIN_EXE_wmtext"))
        .args(["scan", fixture.path().to_str().unwrap()])
        .output()
        .expect("run wmtext");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("no supported surface signal detected"));
    assert!(stdout.contains("Statistical watermark: indeterminate"));
}

#[test]
fn high_signal_exits_one_and_serializes_json() {
    let mut bytes = b"hello".to_vec();
    bytes.extend_from_slice("\u{200B}".as_bytes());
    bytes.extend_from_slice(b"world\n");
    let fixture = TempFile::create(&bytes);

    let output = Command::new(env!("CARGO_BIN_EXE_wmtext"))
        .args(["scan", fixture.path().to_str().unwrap(), "--format", "json"])
        .output()
        .expect("run wmtext");

    assert_eq!(output.status.code(), Some(1));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["schema_version"], 1);
    assert_eq!(
        json["statistical_watermark_status"]["status"],
        "indeterminate"
    );
    assert_eq!(json["summary"]["findings_high"], 1);
    assert_eq!(json["files"][0]["findings"][0]["codepoint"], "U+200B");
}

#[test]
fn missing_path_exits_two() {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let missing = std::env::temp_dir().join(format!(
        "wmtext-definitely-missing-{}-{id}.md",
        std::process::id()
    ));
    let output = Command::new(env!("CARGO_BIN_EXE_wmtext"))
        .args(["scan", missing.to_str().unwrap()])
        .output()
        .expect("run wmtext");

    assert_eq!(output.status.code(), Some(2));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Path does not exist"));
}

#[test]
fn sanitize_dry_run_reports_without_writing() {
    let fixture = TempFile::create("a\u{200D}b 👨\u{200D}👩\n".as_bytes());
    let before = fs::read(fixture.path()).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_wmtext"))
        .args([
            "sanitize",
            fixture.path().to_str().unwrap(),
            "--dry-run",
            "--format",
            "json",
        ])
        .output()
        .expect("run wmtext sanitize");

    assert!(output.status.success());
    assert_eq!(fs::read(fixture.path()).unwrap(), before);
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["changed"], true);
    assert_eq!(json["stats"]["removed_count"], 2);
    assert_eq!(json["operations"][0]["codepoint"], "U+200D");
}

#[test]
fn sanitize_writes_new_file_and_removes_all_format_characters() {
    let fixture = TempFile::create("a\u{200D}b 👨\u{200D}👩\n".as_bytes());
    let output_path = TempFile::unused();
    let output = Command::new(env!("CARGO_BIN_EXE_wmtext"))
        .args([
            "sanitize",
            fixture.path().to_str().unwrap(),
            "--output",
            output_path.path().to_str().unwrap(),
        ])
        .output()
        .expect("run wmtext sanitize");

    assert!(output.status.success());
    assert_eq!(fs::read_to_string(output_path.path()).unwrap(), "ab 👨👩\n");
}

#[test]
fn sanitize_requires_an_explicit_write_mode() {
    let fixture = TempFile::create(b"ordinary text\n");
    let output = Command::new(env!("CARGO_BIN_EXE_wmtext"))
        .args(["sanitize", fixture.path().to_str().unwrap()])
        .output()
        .expect("run wmtext sanitize");

    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("choose exactly one")
    );
}
