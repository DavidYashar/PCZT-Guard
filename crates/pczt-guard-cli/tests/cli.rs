//! The CLI as a script sees it: stdout, stderr and exit codes.

use std::{
    path::PathBuf,
    process::{Command, Output},
};

/// Writes fixture bytes to a file that lives for the duration of the test run.
fn fixture(name: &str, bytes: &[u8]) -> PathBuf {
    let dir = std::env::temp_dir().join("pczt-guard-cli-tests");
    std::fs::create_dir_all(&dir).expect("a temp directory");
    let path = dir.join(name);
    std::fs::write(&path, bytes).expect("the fixture is writable");
    path
}

fn check(path: &PathBuf, extra: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_pczt-guard"))
        .arg("check")
        .arg(path)
        .args(extra)
        .output()
        .expect("the binary runs")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

#[test]
fn an_honest_payment_exits_zero() {
    let path = fixture("honest.pczt", &xtask::honest().bytes);
    let output = check(&path, &[]);

    assert_eq!(output.status.code(), Some(0), "{}", stdout(&output));
    let text = stdout(&output);
    assert!(text.starts_with("SAFE"), "{text}");
    assert!(text.contains("1.00000000 ZEC"), "{text}");
    assert!(text.contains("[verified]"), "{text}");
    assert!(text.contains("fee"), "{text}");
}

#[test]
fn the_address_attack_exits_one_and_names_the_finding() {
    let path = fixture("attack.pczt", &xtask::address_deception().bytes);
    let output = check(&path, &[]);

    assert_eq!(output.status.code(), Some(1), "{}", stdout(&output));
    let text = stdout(&output);
    assert!(text.starts_with("UNSAFE"), "{text}");
    assert!(text.contains("AddressMismatch"), "{text}");
    assert!(text.contains("NOT verified"), "{text}");
}

#[test]
fn an_unlabeled_output_exits_two() {
    let path = fixture("unlabeled.pczt", &xtask::unlabeled().bytes);
    let output = check(&path, &[]);

    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
    assert!(stdout(&output).starts_with("CANNOT VERIFY"));
}

#[test]
fn an_unlabeled_output_can_be_allowed() {
    let path = fixture("unlabeled-allowed.pczt", &xtask::unlabeled().bytes);
    let output = check(&path, &["--allow-unlabeled-change"]);

    assert_eq!(output.status.code(), Some(0), "{}", stdout(&output));
}

#[test]
fn a_fee_drain_is_a_warning_by_default_and_a_failure_in_strict_mode() {
    let path = fixture("drain.pczt", &xtask::inflated_fee().bytes);

    let relaxed = check(&path, &[]);
    assert_eq!(relaxed.status.code(), Some(0), "{}", stdout(&relaxed));
    assert!(stdout(&relaxed).contains("HighFee"), "{}", stdout(&relaxed));
    assert!(stdout(&relaxed).contains("PL07"), "{}", stdout(&relaxed));

    let strict = check(&path, &["--strict"]);
    assert_eq!(strict.status.code(), Some(1), "{}", stdout(&strict));
    assert!(
        stdout(&strict).contains("strict mode"),
        "{}",
        stdout(&strict)
    );
}

#[test]
fn the_lints_are_listed() {
    let output = Command::new(env!("CARGO_BIN_EXE_pczt-guard"))
        .arg("lints")
        .output()
        .expect("the binary runs");

    assert_eq!(output.status.code(), Some(0));
    let text = stdout(&output);
    for id in ["PL01", "PL02", "PL03", "PL04", "PL06", "PL07"] {
        assert!(text.contains(id), "{id} missing from:\n{text}");
    }
    assert!(text.contains("PL05"), "the gap is disclosed: {text}");
}

#[test]
fn the_expected_network_is_enforced() {
    let path = fixture("network.pczt", &xtask::honest().bytes);

    let ok = check(&path, &["--expect-network", "test"]);
    assert_eq!(ok.status.code(), Some(0), "{}", stdout(&ok));

    let wrong = check(&path, &["--expect-network", "main"]);
    assert_eq!(wrong.status.code(), Some(1), "{}", stdout(&wrong));
    assert!(
        stdout(&wrong).contains("NetworkMismatch"),
        "{}",
        stdout(&wrong)
    );
}

#[test]
fn json_output_is_machine_readable() {
    let path = fixture("attack-json.pczt", &xtask::address_deception().bytes);
    let output = check(&path, &["--json"]);

    assert_eq!(output.status.code(), Some(1));
    let json: serde_json::Value =
        serde_json::from_str(&stdout(&output)).expect("the report is valid JSON");
    assert_eq!(json["verdict"], "UNSAFE");
    assert_eq!(json["network"], "test");
    assert_eq!(json["tx_version"], 6);
    assert_eq!(json["payments"][0]["bound"], false);
    assert!(
        json["findings"]
            .as_array()
            .expect("findings is an array")
            .iter()
            .any(|f| f["code"] == "ADDRESS_MISMATCH"),
        "{json}"
    );
}

#[test]
fn a_file_that_is_not_a_pczt_exits_three() {
    let path = fixture("garbage.pczt", b"this is not a transaction");
    let output = check(&path, &[]);

    assert_eq!(output.status.code(), Some(3));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("not a PCZT"), "{stderr}");
}

#[test]
fn a_viewing_key_turns_unlabelled_change_into_proven_change() {
    let path = fixture("change.pczt", &xtask::payment_with_change().bytes);

    let without = check(&path, &[]);
    assert_eq!(without.status.code(), Some(2), "{}", stdout(&without));

    let ufvk = xtask::owner_ufvk_encoded();
    let with = check(&path, &["--ufvk", &ufvk]);
    assert_eq!(with.status.code(), Some(0), "{}", stdout(&with));
    let text = stdout(&with);
    assert!(text.contains("[change, proven]"), "{text}");
}

#[test]
fn a_viewing_key_that_is_not_the_signers_makes_the_output_unsafe() {
    let path = fixture("change-not-ours.pczt", &xtask::payment_with_change().bytes);
    let ufvk = xtask::alice_ufvk_encoded();

    let output = check(&path, &["--ufvk", &ufvk]);
    assert_eq!(output.status.code(), Some(1), "{}", stdout(&output));
    assert!(
        stdout(&output).contains("NotOurOutput"),
        "{}",
        stdout(&output)
    );
}

#[test]
fn viewing_keys_can_come_from_a_file() {
    let path = fixture("change-file.pczt", &xtask::payment_with_change().bytes);
    let keys = fixture(
        "ufvks.txt",
        format!("# the demo wallet\n{}\n", xtask::owner_ufvk_encoded()).as_bytes(),
    );

    let output = check(
        &path,
        &["--ufvk-file", keys.to_str().expect("a UTF-8 path")],
    );
    assert_eq!(output.status.code(), Some(0), "{}", stdout(&output));
}

#[test]
fn a_malformed_viewing_key_is_a_usage_error() {
    let path = fixture("honest-ufvk.pczt", &xtask::honest().bytes);
    let output = check(&path, &["--ufvk", "uviewtest1notakey"]);

    assert_eq!(output.status.code(), Some(3));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("does not decode as a unified full viewing key"),
        "{stderr}"
    );
    // The value itself is never echoed, not even shortened: a phrase pasted into the wrong
    // flag must not leak into a log.
    assert!(!stderr.contains("uviewtest1notakey"), "{stderr}");
}

#[test]
fn a_control_character_label_cannot_repaint_the_report() {
    let path = fixture(
        "control-chars.pczt",
        &xtask::label_with_control_characters().bytes,
    );
    let output = check(&path, &[]);

    assert_eq!(output.status.code(), Some(1), "{}", stdout(&output));
    let text = stdout(&output);
    assert!(text.starts_with("UNSAFE"), "{text}");
    assert!(text.contains("LabelControlCharacters"), "{text}");
    assert!(
        !text.contains('\u{1b}'),
        "no raw escape byte may reach the terminal: {text:?}"
    );
    assert!(
        text.contains("\\u{1b}"),
        "it is shown escaped instead: {text}"
    );
}

#[test]
fn a_long_multibyte_label_does_not_panic() {
    let path = fixture("multibyte.pczt", &xtask::label_long_multibyte().bytes);
    let output = check(&path, &[]);

    // Exit code 101 is a Rust panic; anything else means the report was produced.
    assert_ne!(output.status.code(), Some(101), "{}", stdout(&output));
    assert_eq!(output.status.code(), Some(1), "{}", stdout(&output));
}

#[test]
fn an_invisible_bidi_override_cannot_reorder_the_report() {
    let path = fixture("bidi.pczt", &xtask::label_with_bidi_override().bytes);
    let output = check(&path, &[]);

    assert_eq!(output.status.code(), Some(1), "{}", stdout(&output));
    let text = stdout(&output);
    assert!(text.contains("LabelControlCharacters"), "{text}");
    // The override must never reach the terminal as itself: it would reverse the glyphs after
    // it, so the address on screen would not be the address in the file.
    assert!(
        !text.contains('\u{202E}') && !text.contains('\u{202C}'),
        "a raw bidi control reached the terminal: {text:?}"
    );
    assert!(text.contains("\\u{202e}"), "it is shown escaped: {text}");
}

#[test]
fn an_expired_pczt_is_refused() {
    let path = fixture("honest-expiry.pczt", &xtask::honest().bytes);
    let output = check(&path, &["--at-height", "9999999"]);

    assert_eq!(output.status.code(), Some(1), "{}", stdout(&output));
    assert!(stdout(&output).contains("Expired"), "{}", stdout(&output));
}

#[test]
fn a_missing_file_exits_three() {
    let path = PathBuf::from("does-not-exist.pczt");
    let output = check(&path, &[]);

    assert_eq!(output.status.code(), Some(3));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("cannot read"), "{stderr}");
}
