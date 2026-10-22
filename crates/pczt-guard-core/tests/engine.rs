//! The core engine against the generated fixtures.

use pczt_guard_core::{verify, FindingCode, Network, Options, Pool, Severity, Verdict};

fn honest() -> pczt_guard_core::Report {
    let payment = xtask::honest();
    verify(&payment.bytes, &Options::default()).expect("the fixture is a PCZT")
}

fn attack() -> pczt_guard_core::Report {
    let payment = xtask::address_deception();
    verify(&payment.bytes, &Options::default()).expect("the fixture is a PCZT")
}

/// The findings that decide the verdict, i.e. everything above information.
fn concerning(report: &pczt_guard_core::Report) -> Vec<&pczt_guard_core::Finding> {
    report
        .findings
        .iter()
        .filter(|f| f.severity >= Severity::CannotVerify)
        .collect()
}

#[test]
fn honest_fixture_is_safe() {
    let report = honest();
    assert_eq!(
        report.verdict,
        Verdict::Safe,
        "unexpected findings: {:#?}",
        report.findings
    );
    assert!(
        report.findings.iter().all(|f| f.severity == Severity::Info),
        "an honest PCZT should carry nothing but information: {:#?}",
        report.findings
    );
}

#[test]
fn report_describes_the_transaction() {
    let report = honest();
    assert_eq!(report.network, Network::Test);
    assert_eq!(report.tx_version, 6);
    assert_eq!(report.pools, vec![Pool::Ironwood]);

    // One real payment. The zero-valued padding output is not a payment.
    assert_eq!(report.payments.len(), 1, "{:#?}", report.payments);
    let payment = &report.payments[0];
    assert_eq!(payment.pool, Pool::Ironwood);
    assert_eq!(payment.value, Some(100_000_000));
    assert!(payment.bound, "the honest label matches what it pays");
    assert_eq!(
        payment.shown, payment.committed,
        "the honest fixture's label matches what it pays"
    );
}

#[test]
fn the_attack_is_caught() {
    // Stage 7. Every cryptographic check passes on this PCZT; the label is the only lie,
    // and it is the lie that decides where the money goes.
    let report = attack();
    assert_eq!(report.verdict, Verdict::Unsafe, "{:#?}", report.findings);

    let mismatch = report
        .findings
        .iter()
        .find(|f| f.code == FindingCode::AddressMismatch)
        .expect("an ADDRESS_MISMATCH finding");
    assert_eq!(mismatch.severity, Severity::Unsafe);
    assert_eq!(mismatch.pool, Some(Pool::Ironwood));

    // Nothing else is wrong with it: the attack is not detectable any other way.
    assert_eq!(concerning(&report).len(), 1, "{:#?}", report.findings);

    let line = &report.payments[0];
    assert!(!line.bound);
    assert_ne!(line.shown, line.committed);
    assert_eq!(line.value, Some(100_000_000));
}

#[test]
fn a_pczt_for_another_network_is_rejected() {
    let payment = xtask::honest();
    let options = Options {
        expected_network: Some(Network::Main),
        ..Options::default()
    };
    let report = verify(&payment.bytes, &options).expect("the fixture is a PCZT");

    assert_eq!(report.verdict, Verdict::Unsafe);
    let concerning = concerning(&report);
    assert_eq!(concerning.len(), 1, "{:#?}", report.findings);
    assert_eq!(concerning[0].code, FindingCode::NetworkMismatch);
    assert_eq!(concerning[0].severity, Severity::Unsafe);
}

#[test]
fn the_fee_is_computed() {
    let report = honest();
    // 100,010,000 in, 100,000,000 out.
    assert_eq!(report.fee, Some(10_000));
    assert!(
        !report.findings.iter().any(|f| f.severity >= Severity::Warn),
        "an ordinary fee is not worth a warning: {:#?}",
        report.findings
    );
}

#[test]
fn an_inflated_fee_is_flagged() {
    // 1 ZEC in, 0.01 ZEC out: 0.99 ZEC burned as fee, and nothing in the PCZT says so.
    let payment = xtask::inflated_fee();
    let report = verify(&payment.bytes, &Options::default()).expect("the fixture is a PCZT");

    assert_eq!(report.fee, Some(99_000_000));
    let warning = report
        .findings
        .iter()
        .find(|f| f.code == FindingCode::HighFee)
        .expect("a HIGH_FEE finding");
    assert_eq!(warning.severity, Severity::Warn);
    assert_eq!(
        report.verdict,
        Verdict::Safe,
        "a high fee is a warning, not proof of a lie"
    );
}

#[test]
fn a_redacted_recipient_still_allows_the_fee() {
    // Only the recipient is gone; the values that make up the fee are still there.
    let payment = xtask::redacted_recipient();
    let report = verify(&payment.bytes, &Options::default()).expect("the fixture is a PCZT");
    assert_eq!(report.fee, Some(10_000));
}

#[test]
fn a_redacted_value_leaves_the_fee_unknown() {
    let payment = xtask::redacted_value();
    let report = verify(&payment.bytes, &Options::default()).expect("the fixture is a PCZT");

    assert_eq!(report.fee, None, "the fee cannot be computed");
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.code == FindingCode::RedactedValue),
        "{:#?}",
        report.findings
    );
}

#[test]
fn a_real_devtool_pczt_verifies() {
    // Created by `zcash-devtool pczt create` on Testnet, post-NU6.3, 21 Oct 2026. Five
    // actions: one spend, one labelled payment of 0.01 TAZ, four change outputs of
    // 0.24743750 TAZ that `zcash_client_backend` deliberately leaves unlabelled.
    let bytes = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/ironwood-devtool-real.pczt"
    ))
    .expect("the recorded fixture exists");

    let report = verify(&bytes, &Options::default()).expect("a valid PCZT");
    assert_eq!(
        report.verdict,
        Verdict::CannotVerify,
        "unlabelled change must not read as safe"
    );
    assert!(
        report
            .findings
            .iter()
            .all(|f| f.code == FindingCode::UnlabeledOutput || f.severity == Severity::Info),
        "nothing else is wrong with it: {:#?}",
        report.findings
    );

    let options = Options {
        allow_unlabeled_change: true,
        ..Options::default()
    };
    let report = verify(&bytes, &options).expect("a valid PCZT");
    assert_eq!(report.verdict, Verdict::Safe, "{:#?}", report.findings);
    assert_eq!(report.payments.len(), 5, "{:#?}", report.payments);
    assert_eq!(report.payments.iter().filter(|p| p.bound).count(), 1);
    assert_eq!(report.fee, Some(25_000));
}

#[test]
fn a_labelled_output_of_your_own_is_reported_as_yours() {
    // `zcash-devtool generate-address` hands out further addresses of the same account, so a
    // "payment to my second address" decrypts with the same viewing key. The label still
    // matches, so nothing is dishonest — but the signer should be told the money stays home.
    let payment = xtask::payment(xtask::owner_address(), xtask::owner_address(), 10_000_000);
    let (_, fvk) = xtask::owner();
    let options = Options {
        ufvks: vec![fvk],
        ..Options::default()
    };
    let report = verify(&payment.bytes, &options).expect("the fixture is a PCZT");

    assert_eq!(report.verdict, Verdict::Safe, "{:#?}", report.findings);
    assert_eq!(report.payments[0].role, pczt_guard_core::Role::SelfTransfer);
    assert!(report.payments[0].bound);
}

#[test]
fn wallet_fields_do_not_disturb_trial_decryption() {
    // The wallet-shaped fixture carries ZIP 32 derivations and a proprietary blob as well as
    // encrypted change; the extra fields must not stop the change from being proven.
    let payment = xtask::wallet_shaped();
    let (_, fvk) = xtask::owner();
    let options = Options {
        ufvks: vec![fvk],
        ..Options::default()
    };
    let report = verify(&payment.bytes, &options).expect("the fixture is a PCZT");

    assert_eq!(report.verdict, Verdict::Safe, "{:#?}", report.findings);
    assert!(
        report
            .payments
            .iter()
            .any(|p| p.role == pczt_guard_core::Role::Change),
        "{:#?}",
        report.payments
    );
}

#[test]
fn a_label_with_control_characters_is_unsafe() {
    // The label is untrusted text that a human reads a verdict next to, so escape sequences
    // in it are an attempt to rewrite the report, not a typo.
    let payment = xtask::label_with_control_characters();
    let report = verify(&payment.bytes, &Options::default()).expect("the fixture is a PCZT");

    assert_eq!(report.verdict, Verdict::Unsafe, "{:#?}", report.findings);
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.code == FindingCode::LabelControlCharacters),
        "{:#?}",
        report.findings
    );
}

#[test]
fn a_proven_alien_output_survives_the_unlabeled_flag() {
    // `allow_unlabeled_change` exists to accept outputs nobody could check. A viewing key
    // *did* check this one and found it pays somebody else, so no flag may soften it.
    let payment = xtask::payment_with_change();
    for allow in [false, true] {
        let options = Options {
            ufvks: vec![xtask::alice_fvk()],
            allow_unlabeled_change: allow,
            ..Options::default()
        };
        let report = verify(&payment.bytes, &options).expect("the fixture is a PCZT");
        assert_eq!(
            report.verdict,
            Verdict::Unsafe,
            "allow_unlabeled_change={allow} must not rescue a proven alien output: {:#?}",
            report.findings
        );
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.code == FindingCode::NotOurOutput && f.severity == Severity::Unsafe),
            "{:#?}",
            report.findings
        );
    }
}

#[test]
fn an_empty_pczt_is_not_safe() {
    // A PCZT that spends nothing and pays nobody is an absence of a transaction. Reporting
    // SAFE would tell a gating signer that "no payments" is a checked payment, which is the
    // opposite of true — and a constructor, or anyone who can swap the file, can produce one.
    // The byte-sweep fuzzer found this class: mutations that emptied the bundles still came
    // back SAFE with a zero fee.
    let payment = xtask::empty();
    let report = verify(&payment.bytes, &Options::default()).expect("an empty PCZT still parses");

    assert_eq!(
        report.verdict,
        Verdict::CannotVerify,
        "{:#?}",
        report.findings
    );
    assert!(report.payments.is_empty());
    assert!(report.pools.is_empty());
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.code == FindingCode::EmptyTransaction),
        "{:#?}",
        report.findings
    );
}

#[test]
fn a_coin_type_naming_no_known_network_is_not_safe() {
    // `coin_type` is the PCZT's only statement about which chain it is for. Unknown values
    // must not read as safe: the signer would be committing to a transaction for a chain
    // nobody identified. `--expect-network` catches a *wrong* network; this catches an
    // unrecognised one when no expectation was given.
    //
    // The offset is found by scanning rather than hard-coded, so a serialization change
    // makes this test skip instead of firing on the wrong byte.
    let payment = xtask::honest();
    let base = &payment.bytes;

    for offset in 0..base.len().min(48) {
        let mut mutant = base.clone();
        if mutant[offset] == 0x7F {
            continue;
        }
        mutant[offset] = 0x7F;
        let Ok(report) = verify(&mutant, &Options::default()) else {
            continue;
        };
        if !matches!(report.network, Network::Other(_)) || report.pools.is_empty() {
            continue;
        }
        assert_ne!(
            report.verdict,
            Verdict::Safe,
            "byte {offset} set to 0x7f makes coin type {:?} with the bundles intact, and it \
             still read as SAFE",
            report.network
        );
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.code == FindingCode::UnknownNetwork),
            "{:#?}",
            report.findings
        );
        return;
    }
    eprintln!("no byte in the first 48 produced an unknown coin type; layout changed, skipped");
}

#[test]
fn garbage_is_not_a_pczt() {
    assert!(verify(b"not a pczt", &Options::default()).is_err());
}

#[test]
fn a_payment_with_change_cannot_be_verified_without_a_viewing_key() {
    // The shape every real wallet produces: `zcash_client_backend` labels only the outputs
    // that pay somebody else, so change reaches the signer with value and no address. Guard
    // cannot tell that apart from an attacker's hidden output, so it refuses to call it safe.
    let payment = xtask::payment_with_change();
    let report = verify(&payment.bytes, &Options::default()).expect("the fixture is a PCZT");

    assert_eq!(
        report.verdict,
        Verdict::CannotVerify,
        "{:#?}",
        report.findings
    );
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.code == FindingCode::UnlabeledOutput),
        "{:#?}",
        report.findings
    );

    // Both outputs are reported, and only the payment is bound to a label.
    assert_eq!(report.payments.len(), 2, "{:#?}", report.payments);
    assert_eq!(report.payments.iter().filter(|p| p.bound).count(), 1);
    assert!(report.fee.is_some());
}

#[test]
fn a_payment_with_change_can_be_allowed_explicitly() {
    let payment = xtask::payment_with_change();
    let options = Options {
        allow_unlabeled_change: true,
        ..Options::default()
    };
    let report = verify(&payment.bytes, &options).expect("the fixture is a PCZT");
    assert_eq!(report.verdict, Verdict::Safe, "{:#?}", report.findings);
    assert_eq!(report.payments.len(), 2);
}

#[test]
fn a_viewing_key_proves_unlabelled_change_is_yours() {
    // The flag above is a promise the signer cannot check. A viewing key turns the same
    // PCZT into a proof: trial-decrypting the unlabelled output succeeds, so it is this
    // wallet's change and its value can be shown.
    let payment = xtask::payment_with_change();
    let (_, fvk) = xtask::owner();
    let options = Options {
        ufvks: vec![fvk],
        ..Options::default()
    };
    let report = verify(&payment.bytes, &options).expect("the fixture is a PCZT");

    assert_eq!(report.verdict, Verdict::Safe, "{:#?}", report.findings);
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.code == FindingCode::OwnedChange),
        "the change should be reported as proven: {:#?}",
        report.findings
    );
    assert!(
        !report
            .findings
            .iter()
            .any(|f| f.code == FindingCode::UnlabeledOutput),
        "proven change is not an unlabelled mystery: {:#?}",
        report.findings
    );

    let change = report
        .payments
        .iter()
        .find(|p| p.role == pczt_guard_core::Role::Change)
        .expect("a change line");
    assert!(change.bound);
    assert_eq!(change.value, Some(59_990_000));
    assert_eq!(report.fee, Some(10_000));
}

#[test]
fn a_viewing_key_that_does_not_match_makes_the_output_unsafe() {
    // The strongest form of the check: with a key in hand, an output that does not decrypt
    // is provably paying somebody else. That upgrades a shrug into a refusal.
    let payment = xtask::payment_with_change();
    let options = Options {
        ufvks: vec![xtask::alice_fvk()],
        ..Options::default()
    };
    let report = verify(&payment.bytes, &options).expect("the fixture is a PCZT");

    assert_eq!(report.verdict, Verdict::Unsafe, "{:#?}", report.findings);
    let finding = report
        .findings
        .iter()
        .find(|f| f.code == FindingCode::NotOurOutput)
        .expect("a NOT_OUR_OUTPUT finding");
    assert_eq!(finding.severity, Severity::Unsafe);
}

#[test]
fn a_payment_to_you_labelled_as_somebody_else_is_caught() {
    // The reverse deception: the signer is shown a payment to somebody else, but the note
    // is encrypted to the signer's own key, so the funds never leave. A co-signer sees only
    // the label, so this is the fraud a FROST participant needs caught.
    let payment = xtask::payment(xtask::owner_address(), xtask::alice(), 10_000_000);
    let (_, fvk) = xtask::owner();
    let options = Options {
        ufvks: vec![fvk],
        ..Options::default()
    };
    let report = verify(&payment.bytes, &options).expect("the fixture is a PCZT");

    assert_eq!(report.verdict, Verdict::Unsafe, "{:#?}", report.findings);
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.code == FindingCode::SelfPaymentLabeledExternal),
        "{:#?}",
        report.findings
    );
}

/// The encoding a PCZT is written in, as the crate sees it.
fn encoding(payment: &xtask::Payment) -> pczt_guard_core::EncodingVersion {
    pczt::Pczt::parse(&payment.bytes)
        .expect("a valid PCZT")
        .serialize_with_version()
        .expect("encodable")
        .0
}

#[test]
fn the_v1_encoding_cannot_carry_a_post_nu6_3_transaction() {
    // PCZT v1 predates v6 transactions and the Ironwood bundle, and `pczt` enforces that
    // boundary itself: every transaction built after NU6.3 is v6, so a v1 PCZT can only
    // describe a pre-upgrade one. That is why Guard's fixtures are all v2, and why it is
    // impossible to construct a realistic v1 fixture with today's builders.
    let payment = xtask::honest();
    let parsed = pczt::Pczt::parse(&payment.bytes).expect("a valid PCZT");
    assert_eq!(encoding(&payment), pczt_guard_core::EncodingVersion::V2);
    assert!(
        pczt::v1::Pczt::try_from(parsed).is_err(),
        "a v6 PCZT must not be encodable as v1"
    );
}

#[test]
fn guard_reads_the_transaction_version_from_the_file_not_from_an_assumption() {
    // The pipeline takes `tx_version` from the PCZT's own global fields, so a v5 file would
    // be checked by the same stages; only the v6-specific Ironwood rule depends on it.
    let report = honest();
    assert_eq!(report.tx_version, 6);
    assert!(
        !report
            .findings
            .iter()
            .any(|f| f.code == FindingCode::InconsistentPczt),
        "a v6 PCZT with an Ironwood bundle is consistent: {:#?}",
        report.findings
    );
}

#[test]
fn a_wallet_shaped_pczt_verifies() {
    // What `zcash_client_backend` produces: change with no label, ZIP 32 derivations on the
    // spend and on the labelled output, and a proprietary blob. None of those may disturb
    // verification.
    let payment = xtask::wallet_shaped();
    let options = Options {
        allow_unlabeled_change: true,
        ..Options::default()
    };
    let report = verify(&payment.bytes, &options).expect("the fixture is a PCZT");

    assert_eq!(report.verdict, Verdict::Safe, "{:#?}", report.findings);
    assert_eq!(report.payments.len(), 2, "{:#?}", report.payments);
    assert_eq!(report.payments.iter().filter(|p| p.bound).count(), 1);
    assert!(report.fee.is_some());
}

#[test]
fn a_compacted_pczt_still_verifies() {
    // Compacting drops `cv_net` and `cmx`, so the parser has to re-derive them before any
    // check can run. Guard must agree with the un-compacted PCZT.
    let payment = xtask::wallet_shaped_compacted();
    assert_eq!(encoding(&payment), pczt_guard_core::EncodingVersion::V2);

    let options = Options {
        allow_unlabeled_change: true,
        ..Options::default()
    };
    let report = verify(&payment.bytes, &options).expect("the fixture is a PCZT");
    assert_eq!(report.verdict, Verdict::Safe, "{:#?}", report.findings);
    assert_eq!(report.payments.len(), 2);
}

/// Runs the engine over a fixture and returns (verdict, finding codes).
fn codes(payment: &xtask::Payment, options: &Options) -> (Verdict, Vec<FindingCode>) {
    let report = verify(&payment.bytes, options).expect("the fixture is a PCZT");
    (
        report.verdict,
        report.findings.iter().map(|f| f.code).collect(),
    )
}

#[test]
fn a_label_that_is_not_an_address_is_unsafe() {
    let payment = xtask::label_not_an_address();
    let (verdict, codes) = codes(&payment, &Options::default());
    assert_eq!(verdict, Verdict::Unsafe);
    assert!(codes.contains(&FindingCode::BadAddress), "{codes:?}");
}

#[test]
fn a_label_for_another_pool_is_unsafe() {
    let payment = xtask::label_wrong_pool();
    let (verdict, codes) = codes(&payment, &Options::default());
    assert_eq!(verdict, Verdict::Unsafe);
    assert!(codes.contains(&FindingCode::NoReceiverForPool), "{codes:?}");
}

#[test]
fn an_unlabeled_output_cannot_be_verified() {
    let payment = xtask::unlabeled();
    let (verdict, codes) = codes(&payment, &Options::default());
    assert_eq!(
        verdict,
        Verdict::CannotVerify,
        "an output the signer cannot describe is never a pass: {codes:?}"
    );
    assert!(codes.contains(&FindingCode::UnlabeledOutput), "{codes:?}");
}

#[test]
fn an_unlabeled_output_can_be_allowed_explicitly() {
    let payment = xtask::unlabeled();
    let options = Options {
        allow_unlabeled_change: true,
        ..Options::default()
    };
    let (verdict, _) = codes(&payment, &options);
    assert_eq!(verdict, Verdict::Safe);
}

#[test]
fn a_redacted_recipient_cannot_be_verified() {
    let payment = xtask::redacted_recipient();
    let report = verify(&payment.bytes, &Options::default()).expect("the fixture is a PCZT");

    assert_eq!(
        report.verdict,
        Verdict::CannotVerify,
        "redaction must never read as a pass: {:#?}",
        report.findings
    );
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.code == FindingCode::RedactedField),
        "{:#?}",
        report.findings
    );
    assert!(
        !report
            .findings
            .iter()
            .any(|f| f.severity == Severity::Unsafe),
        "nothing is proven wrong, only unprovable: {:#?}",
        report.findings
    );
}
