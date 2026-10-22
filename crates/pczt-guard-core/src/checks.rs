//! Stages 3-5: re-derive what each shielded bundle claims about itself.
//!
//! These are the checks the `pczt` crate's helper methods already expose. PCZT Guard runs
//! all of them so that a signer gets one answer instead of having to remember which ones
//! a given signer implementation skipped.
//!
//! Two error classes matter here, and they produce different verdicts:
//!
//! * `Missing*` — the PCZT redacted a field a check needs. Nothing is proven wrong, so
//!   the result is [`Severity::CannotVerify`], never a pass.
//! * everything else — the PCZT asserts something false, so [`Severity::Unsafe`].

use orchard::note::ExtractedNoteCommitment;
use orchard::pczt::{Bundle as OrchardBundle, VerifyError as OrchardVerifyError};
use pczt::roles::verifier::{OrchardError, SaplingError};
use sapling::pczt::{Bundle as SaplingBundle, VerifyError as SaplingVerifyError};

use crate::report::{Finding, FindingCode, Pool, Severity};

/// Runs every Orchard-family check on one bundle.
///
/// The Ironwood bundle reuses the Orchard protocol types, so one function serves both.
/// The cross-address restriction is a no-op for Ironwood, whose bundle flags permit
/// cross-address transfers.
pub(crate) fn orchard_family(bundle: &OrchardBundle, pool: Pool) -> Vec<Finding> {
    let mut findings = Vec::new();

    if let Err(e) = bundle.verify_cross_address_restriction() {
        findings.push(orchard_finding(e, pool, None, "cross-address restriction"));
    }

    for (index, action) in bundle.actions().iter().enumerate() {
        let (spend, output) = (action.spend(), action.output());

        // The spec tells Signers to reject a PCZT carrying a `dummy_sk`. Every padded
        // bundle legitimately carries them on its zero-value dummy spends, so the
        // suspicious case is a spend that moves value and still exposes a spending key.
        if spend.value().map(|v| v.inner()) != Some(0) && spend.dummy_sk().is_some() {
            findings.push(Finding::new(
                FindingCode::DummySpendingKey,
                Severity::Unsafe,
                Some(pool),
                Some(index),
                "a spend that moves value carries a `dummy_sk` spending key, which a \
                 Signer must reject",
            ));
        }
        if let Err(e) = action.verify_cv_net() {
            findings.push(orchard_finding(e, pool, Some(index), "value commitment"));
        }
        if let Err(e) = spend.verify_nullifier(None) {
            findings.push(orchard_finding(e, pool, Some(index), "nullifier"));
        }
        if let Err(e) = spend.verify_rk(None) {
            findings.push(orchard_finding(
                e,
                pool,
                Some(index),
                "spend auth randomizer",
            ));
        }
        if let Err(e) = output.verify_note_commitment(spend) {
            findings.push(orchard_finding(e, pool, Some(index), "note commitment"));
        }
    }

    findings
}

/// Whether each spend's Merkle witness actually leads to the bundle's anchor.
///
/// This is the one part of "does this transaction belong to a real chain" that can be
/// checked offline: the anchor is a root the signer is about to commit to, and every spend
/// has to prove its note is in the tree that root describes. A witness pointing somewhere
/// else is a contradiction: no proof can be built for it, so the transaction can never be
/// mined.
///
/// An absent witness is not a contradiction. Constructors that defer the anchor to proving
/// time (ZIP 374) leave the anchor as an empty-tree placeholder and the witnesses empty,
/// and that is what real tooling emits, so it is reported as information rather than as
/// something the signer should act on.
pub(crate) fn orchard_anchor(bundle: &OrchardBundle, pool: Pool) -> Vec<Finding> {
    let mut findings = Vec::new();
    if *bundle.anchor_deferred() {
        return findings;
    }

    let anchor = *bundle.anchor();
    // ZIP 374 constructors leave the empty-tree root in place as a placeholder and install
    // the real anchor at proving time. `orchard` points out that this anchor cannot anchor
    // a real spend, so it identifies a placeholder exactly.
    if anchor == orchard::Anchor::empty_tree() {
        findings.push(Finding::new(
            FindingCode::MissingWitness,
            Severity::Info,
            Some(pool),
            None,
            "the anchor is the empty-tree placeholder, so the real anchor and Merkle witnesses \
             have not been installed yet (ZIP 374)",
        ));
        return findings;
    }

    let mut without_witness = 0usize;
    for (index, action) in bundle.actions().iter().enumerate() {
        let spend = action.spend();
        // A zero-value spend is ZIP 326 padding, with a fabricated witness; it cannot move
        // funds and is not what the signer needs reassuring about.
        if spend.value().map(|v| v.inner()) == Some(0) {
            continue;
        }
        let Some(path) = spend.witness() else {
            without_witness += 1;
            continue;
        };
        // The witness runs from the note being *spent* to the anchor, so the leaf it must
        // root is that note's commitment, not the output's.
        let Some(cmx) = spent_note_commitment(spend) else {
            findings.push(Finding::new(
                FindingCode::RedactedField,
                Severity::CannotVerify,
                Some(pool),
                Some(index),
                "the spent note's own fields are redacted, so its Merkle witness cannot be \
                 checked against the anchor",
            ));
            continue;
        };
        if path.root(cmx) != anchor {
            findings.push(Finding::new(
                FindingCode::AnchorMismatch,
                Severity::Unsafe,
                Some(pool),
                Some(index),
                "the spend's Merkle witness does not lead to the bundle's anchor, so no proof \
                 can be built for this action",
            ));
        }
    }

    if without_witness > 0 {
        findings.push(Finding::new(
            FindingCode::MissingWitness,
            Severity::Info,
            Some(pool),
            None,
            format!(
                "{without_witness} spend(s) carry no Merkle witness yet; witnesses are a Prover \
                 input that the Updater installs, so their absence does not weaken the signature"
            ),
        ));
    }
    findings
}

/// The commitment of the note a spend consumes, from the fields the PCZT exposes.
fn spent_note_commitment(spend: &orchard::pczt::Spend) -> Option<ExtractedNoteCommitment> {
    orchard::Note::from_parts(
        (*spend.recipient())?,
        (*spend.value())?,
        (*spend.rho())?,
        (*spend.rseed())?,
        *spend.note_version(),
    )
    .into_option()
    .map(|note| ExtractedNoteCommitment::from(note.commitment()))
}

/// Reports what the PCZT says about its zero-knowledge proof.
///
/// Guard does not verify proofs, and saying so is more useful than silence: a proof is
/// absent at signing time by design, because the Prover runs *after* the Signer, and the
/// network is what verifies it afterwards.
pub(crate) fn orchard_proof(bundle: &OrchardBundle, pool: Pool) -> Vec<Finding> {
    match bundle.zkproof() {
        None => vec![Finding::new(
            FindingCode::ProofAbsent,
            Severity::Info,
            Some(pool),
            None,
            "the bundle has no proof yet, which is expected: the Prover adds it after signing",
        )],
        Some(_) => vec![Finding::new(
            FindingCode::ProofUnverified,
            Severity::CannotVerify,
            Some(pool),
            None,
            "the bundle carries a proof, and PCZT Guard does not verify zero-knowledge proofs; \
             the chain verifies it before the transaction can be mined",
        )],
    }
}

/// Runs every Sapling check on one bundle.
pub(crate) fn sapling(bundle: &SaplingBundle) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (index, spend) in bundle.spends().iter().enumerate() {
        if let Err(e) = spend.verify_cv() {
            findings.push(sapling_finding(e, index, "value commitment"));
        }
        if let Err(e) = spend.verify_nullifier(None) {
            findings.push(sapling_finding(e, index, "nullifier"));
        }
        if let Err(e) = spend.verify_rk(None) {
            findings.push(sapling_finding(e, index, "spend auth randomizer"));
        }
    }

    for (index, output) in bundle.outputs().iter().enumerate() {
        if let Err(e) = output.verify_cv() {
            findings.push(sapling_finding(e, index, "value commitment"));
        }
        if let Err(e) = output.verify_note_commitment() {
            findings.push(sapling_finding(e, index, "note commitment"));
        }
    }

    findings
}

/// An Orchard-family bundle that would not parse into its protocol-level form.
pub(crate) fn orchard_parse_error<E: std::fmt::Debug>(
    pool: Pool,
    error: OrchardError<E>,
) -> Finding {
    Finding::new(
        FindingCode::BundleUnparseable,
        Severity::Unsafe,
        Some(pool),
        None,
        format!(
            "the {} bundle could not be parsed: {error:?}",
            pool_name(pool)
        ),
    )
}

/// A Sapling bundle that would not parse into its protocol-level form.
pub(crate) fn sapling_parse_error<E: std::fmt::Debug>(error: SaplingError<E>) -> Finding {
    Finding::new(
        FindingCode::BundleUnparseable,
        Severity::Unsafe,
        Some(Pool::Sapling),
        None,
        format!("the sapling bundle could not be parsed: {error:?}"),
    )
}

fn orchard_finding(
    error: OrchardVerifyError,
    pool: Pool,
    index: Option<usize>,
    check: &str,
) -> Finding {
    let (code, severity) = orchard_class(&error);
    Finding::new(
        code,
        severity,
        Some(pool),
        index,
        format!("{}: {error:?}", describe(check, index)),
    )
}

fn sapling_finding(error: SaplingVerifyError, index: usize, check: &str) -> Finding {
    let (code, severity) = sapling_class(&error);
    Finding::new(
        code,
        severity,
        Some(Pool::Sapling),
        Some(index),
        format!("{}: {error:?}", describe(check, Some(index))),
    )
}

fn describe(check: &str, index: Option<usize>) -> String {
    match index {
        Some(i) => format!("{check} on action {i}"),
        None => format!("{check} on bundle"),
    }
}

fn orchard_class(error: &OrchardVerifyError) -> (FindingCode, Severity) {
    use OrchardVerifyError::*;
    match error {
        MissingRandomSeed
        | MissingRecipient
        | MissingRho
        | MissingValue
        | MissingValueCommitTrapdoor
        | MissingSpendAuthRandomizer
        | MissingFullViewingKey => (FindingCode::RedactedField, Severity::CannotVerify),
        InvalidValueCommitment => (FindingCode::ValueCommitment, Severity::Unsafe),
        InvalidNullifier => (FindingCode::Nullifier, Severity::Unsafe),
        InvalidRandomizedVerificationKey => (FindingCode::SpendAuthRandomizer, Severity::Unsafe),
        InvalidExtractedNoteCommitment | InvalidOutputNote | InvalidSpendNote => {
            (FindingCode::NoteCommitment, Severity::Unsafe)
        }
        DisallowedCrossAddressTransfer => (FindingCode::CrossAddressTransfer, Severity::Unsafe),
        MismatchedFullViewingKey | WrongFvkForNote => {
            (FindingCode::WrongViewingKey, Severity::Unsafe)
        }
        _ => (FindingCode::InconsistentPczt, Severity::Unsafe),
    }
}

fn sapling_class(error: &SaplingVerifyError) -> (FindingCode, Severity) {
    use SaplingVerifyError::*;
    match error {
        MissingRandomSeed
        | MissingRecipient
        | MissingValue
        | MissingValueCommitTrapdoor
        | MissingSpendAuthRandomizer
        | MissingWitness
        | MissingProofGenerationKey => (FindingCode::RedactedField, Severity::CannotVerify),
        InvalidValueCommitment => (FindingCode::ValueCommitment, Severity::Unsafe),
        InvalidNullifier => (FindingCode::Nullifier, Severity::Unsafe),
        InvalidRandomizedVerificationKey => (FindingCode::SpendAuthRandomizer, Severity::Unsafe),
        InvalidExtractedNoteCommitment => (FindingCode::NoteCommitment, Severity::Unsafe),
        MismatchedFullViewingKey | WrongFvkForNote => {
            (FindingCode::WrongViewingKey, Severity::Unsafe)
        }
        _ => (FindingCode::InconsistentPczt, Severity::Unsafe),
    }
}

pub(crate) fn pool_name(pool: Pool) -> &'static str {
    match pool {
        Pool::Transparent => "transparent",
        Pool::Sapling => "sapling",
        Pool::Orchard => "orchard",
        Pool::Ironwood => "ironwood",
    }
}

/// A transparent input or output whose scripts do not hold together.
pub(crate) fn transparent_item_error(
    error: transparent::pczt::VerifyError,
    direction: &str,
    index: usize,
) -> Finding {
    Finding::new(
        FindingCode::InconsistentPczt,
        Severity::Unsafe,
        Some(Pool::Transparent),
        Some(index),
        format!("transparent {direction} {index}: {error:?}"),
    )
}

/// A transparent bundle that would not parse into its protocol-level form.
pub(crate) fn transparent_parse_error<E: std::fmt::Debug>(
    error: pczt::roles::verifier::TransparentError<E>,
) -> Finding {
    Finding::new(
        FindingCode::BundleUnparseable,
        Severity::Unsafe,
        Some(Pool::Transparent),
        None,
        format!("the transparent bundle could not be parsed: {error:?}"),
    )
}
