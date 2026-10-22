//! Reproduction of librustzcash#3155.
//!
//! PCZT Guard exists because of the assertion at the end of this file: the stock `pczt`
//! Signer signs a PCZT whose displayed address is not the address the money goes to.
//! Everything before it establishes that the tool cannot simply "verify harder": the
//! tampered PCZT passes every cryptographic check the Signer runs.

use orchard::keys::{FullViewingKey, SpendingKey};
use pczt::roles::{signer::Signer, verifier::Verifier};
use rand_core::UnwrapErr;
use xtask::{address_deception, honest, owner, Payment};

/// Runs every Orchard/Ironwood check the stock Signer runs, and returns the failures.
fn crypto_failures(payment: &Payment) -> Vec<String> {
    let pczt = pczt::Pczt::parse(&payment.bytes).expect("fixture is a valid PCZT");
    let mut failures = Vec::new();
    Verifier::new(pczt)
        .with_ironwood::<String, _>(|bundle| {
            for (index, action) in bundle.actions().iter().enumerate() {
                let (spend, output) = (action.spend(), action.output());
                if let Err(e) = action.verify_cv_net() {
                    failures.push(format!("action {index} cv_net: {e}"));
                }
                if let Err(e) = spend.verify_nullifier(None) {
                    failures.push(format!("action {index} nullifier: {e}"));
                }
                if let Err(e) = spend.verify_rk(None) {
                    failures.push(format!("action {index} rk: {e}"));
                }
                if let Err(e) = output.verify_note_commitment(spend) {
                    failures.push(format!("action {index} cmx: {e}"));
                }
            }
            Ok(())
        })
        .expect("the Ironwood bundle parses");
    failures
}

/// The address the recipient output actually commits to, as a Unified Address string.
fn committed_recipient(payment: &Payment) -> String {
    let pczt = pczt::Pczt::parse(&payment.bytes).expect("fixture is a valid PCZT");
    let mut found = None;
    Verifier::new(pczt)
        .with_ironwood::<String, _>(|bundle| {
            let output = bundle.actions()[payment.output_action].output();
            found = output.recipient().map(xtask::encode_address);
            Ok(())
        })
        .expect("the Ironwood bundle parses");
    found.expect("the recipient output keeps its recipient field")
}

#[test]
fn honest_payment_passes_every_check() {
    let payment = honest();
    assert!(
        crypto_failures(&payment).is_empty(),
        "honest fixture must have no crypto failures: {:?}",
        crypto_failures(&payment)
    );
    assert_eq!(
        payment.shown_address.as_deref(),
        Some(&*committed_recipient(&payment))
    );
}

#[test]
fn tampered_payment_passes_every_cryptographic_check() {
    // This is the part that makes the problem hard: there is nothing malformed to detect.
    // The commitments say Mallory, and they are correct commitments to Mallory.
    let payment = address_deception();
    assert!(
        crypto_failures(&payment).is_empty(),
        "the attack PCZT is internally consistent: {:?}",
        crypto_failures(&payment)
    );
}

#[test]
fn tampered_payment_lies_about_the_recipient() {
    // The one thing that can catch it: the label the user reads does not match the
    // recipient the value is committed to. This comparison is PCZT Guard's stage 7.
    let payment = address_deception();
    assert_ne!(
        payment.shown_address.as_deref(),
        Some(&*committed_recipient(&payment))
    );
    assert_eq!(payment.shown_address, honest().shown_address);
    assert_ne!(
        committed_recipient(&payment),
        committed_recipient(&honest()),
        "the attack pays somebody else"
    );
}

#[test]
fn stock_signer_signs_the_tampered_payment() {
    let payment = address_deception();
    let pczt = pczt::Pczt::parse(&payment.bytes).expect("fixture is a valid PCZT");

    let mut signer = Signer::new(pczt).expect("the PCZT is signable");
    let (sk, _fvk): (SpendingKey, FullViewingKey) = owner();
    let ask = orchard::keys::SpendAuthorizingKey::from(&sk);

    // No address check anywhere on this path: signer/mod.rs calls only
    // `spend.verify_nullifier(None)` before producing the spend authorization signature.
    signer
        .sign_ironwood(UnwrapErr(rand::rngs::SysRng), payment.spend_action, &ask)
        .expect("the stock Signer signs a PCZT that pays the attacker");
}
