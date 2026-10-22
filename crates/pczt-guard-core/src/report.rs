//! The verdict PCZT Guard returns, and the findings it is built from.

use serde::Serialize;

/// The one question a signer asks: should I sign this?
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Verdict {
    /// Everything the PCZT claims was re-derived and matched.
    Safe,
    /// At least one claim is false, or the PCZT contradicts itself.
    Unsafe,
    /// Nothing is provably wrong, but something needed for a check is missing, so the
    /// PCZT cannot be trusted either. Never treated as a pass.
    CannotVerify,
}

/// How much a single finding should worry a signer.
///
/// Ordered: a report's overall severity is the maximum of its findings.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Severity {
    /// Worth knowing, no action needed.
    Info,
    /// A privacy leak or a smell. Does not block signing unless strict mode is on.
    Warn,
    /// A required field is missing or redacted, so a check was skipped.
    CannotVerify,
    /// A check failed. Do not sign.
    Unsafe,
}

/// The value pool a finding belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Pool {
    Transparent,
    Sapling,
    Orchard,
    Ironwood,
}

/// The network a PCZT claims to be for, from its `coin_type` global field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Network {
    Main,
    /// Testnet and regtest both use coin type 1, so they cannot be told apart here.
    Test,
    Other(u32),
}

impl Network {
    pub(crate) fn from_coin_type(coin_type: u32) -> Self {
        match coin_type {
            0 => Network::Main,
            1 => Network::Test,
            other => Network::Other(other),
        }
    }
}

/// A stable identifier for what went wrong, so callers can branch on it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FindingCode {
    /// The PCZT's own fields contradict each other.
    InconsistentPczt,
    /// The PCZT says it is for a different network than the signer expected.
    NetworkMismatch,
    /// A bundle could not be parsed into its protocol-level form.
    BundleUnparseable,
    /// A field a check needs was absent or redacted.
    RedactedField,
    /// `cv_net` is not the value commitment of the amounts it claims.
    ValueCommitment,
    /// The nullifier is not the nullifier of the note it claims.
    Nullifier,
    /// The randomized verification key does not match the spend authorizing key.
    SpendAuthRandomizer,
    /// The note commitment does not commit to the claimed note.
    NoteCommitment,
    /// A cross-address transfer where the pool forbids one.
    CrossAddressTransfer,
    /// The note does not belong to the supplied viewing key.
    WrongViewingKey,
    /// The PCZT carries a dummy spend key, which a Signer must reject.
    DummySpendingKey,
    /// The address shown to the user is not the address the value is committed to.
    AddressMismatch,
    /// `user_address` is not a decodable Zcash address.
    BadAddress,
    /// `user_address` cannot receive in the pool the output belongs to.
    NoReceiverForPool,
    /// An output moves value but carries no `user_address` to show the signer.
    UnlabeledOutput,
    /// The PCZT has no spends and no outputs in any pool, so there is nothing to sign.
    EmptyTransaction,
    /// The PCZT's `coin_type` names no network Guard knows, so it cannot say which chain
    /// this transaction is for.
    UnknownNetwork,
    /// An output with no `user_address` was trial-decrypted with the supplied viewing key,
    /// so it is provably this wallet's own change rather than somebody else's payment.
    OwnedChange,
    /// An output carrying value is not encrypted to any supplied viewing key, so it is
    /// paying somebody other than the signer.
    NotOurOutput,
    /// `user_address` describes a payment to somebody else, but the note is encrypted to
    /// the signer's own viewing key, so the value never leaves the wallet.
    SelfPaymentLabeledExternal,
    /// `user_address` is an address for a different network than the PCZT.
    LabelNetworkMismatch,
    /// `user_address` contains control or invisible formatting characters, which a terminal
    /// or a browser may act on (repaint the verdict, or reorder the glyphs) rather than show.
    LabelControlCharacters,
    /// A spend's Merkle witness does not lead to the bundle's anchor.
    AnchorMismatch,
    /// A spend has no Merkle witness although the anchor is not deferred.
    MissingWitness,
    /// The PCZT carries no bundle proof yet: proofs are added by the Prover, after signing.
    ProofAbsent,
    /// A proof is present but PCZT Guard was asked not to verify it, or cannot.
    ProofUnverified,
    /// The PCZT's expiry height has already passed, so it can never be mined.
    Expired,
    /// The PCZT sets no expiry height, so it stays valid until its notes are spent.
    NoExpiry,
    /// The values do not add up: the transaction creates value, or a bundle contradicts
    /// its own actions.
    ValueImbalance,
    /// The fee is far above what a transaction of this shape should cost.
    HighFee,
    /// A value needed to compute the fee was redacted.
    RedactedValue,
    /// The bundle's anchor and witnesses are deferred to proving time (ZIP 374).
    DeferredAnchor,
    /// The transaction spends transparent inputs, linking it to public history.
    TransparentInputLink,
    /// A transparent output is probably this wallet's change, which is public on chain.
    TransparentChangeLink,
    /// Value crosses the Orchard↔Ironwood turnstile, so the crossing amount is public.
    TurnstileCrossing,
    /// An amount visible to everyone is distinctive enough to be a fingerprint.
    UniqueAmount,
    /// The transaction touches pools that are otherwise unlinked, which links them.
    MixedPools,
}

impl FindingCode {
    /// The privacy lint this finding belongs to, if any.
    pub fn lint_id(self) -> Option<&'static str> {
        match self {
            FindingCode::TransparentInputLink => Some("PL01"),
            FindingCode::TransparentChangeLink => Some("PL02"),
            FindingCode::TurnstileCrossing => Some("PL03"),
            FindingCode::UniqueAmount => Some("PL04"),
            FindingCode::MixedPools => Some("PL06"),
            FindingCode::HighFee => Some("PL07"),
            _ => None,
        }
    }
}

/// One thing PCZT Guard noticed about the PCZT.
#[derive(Clone, Debug, Serialize)]
pub struct Finding {
    pub code: FindingCode,
    pub severity: Severity,
    /// The privacy lint this finding belongs to (`PL01`…), when it is one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lint: Option<&'static str>,
    /// Absent for transaction-wide findings.
    pub pool: Option<Pool>,
    /// Index of the action (shielded) or input/output (transparent) concerned.
    pub index: Option<usize>,
    pub detail: String,
}

impl Finding {
    pub(crate) fn new(
        code: FindingCode,
        severity: Severity,
        pool: Option<Pool>,
        index: Option<usize>,
        detail: impl Into<String>,
    ) -> Self {
        Finding {
            code,
            severity,
            lint: code.lint_id(),
            pool,
            index,
            detail: detail.into(),
        }
    }
}

/// What an output is for, as far as the signer can tell.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// A payment to somebody else, described by `user_address`.
    External,
    /// This wallet's own change: no label, but proven by trial-decrypting the note with
    /// its viewing key.
    Change,
    /// An output this wallet owns that *does* carry a label — a transfer to another of the
    /// signer's own addresses. Proven the same way, and worth surfacing because the label
    /// alone cannot tell the signer the money never leaves.
    SelfTransfer,
}

/// A payment the transaction makes, as the PCZT describes it.
#[derive(Clone, Debug, Serialize)]
pub struct PaymentLine {
    pub pool: Pool,
    /// The value, in zatoshis. Absent when the PCZT redacted it and no viewing key
    /// recovered it.
    pub value: Option<u64>,
    /// The address the user is shown (`user_address`), if any.
    pub shown: Option<String>,
    /// The address the value is actually committed to, if not redacted.
    pub committed: Option<String>,
    /// Whether `shown` was proven to contain the committed receiver.
    pub bound: bool,
    /// Whether this output is a proven external payment or proven change.
    pub role: Role,
}

/// What PCZT Guard learned about a PCZT.
#[derive(Clone, Debug, Serialize)]
pub struct Report {
    pub verdict: Verdict,
    pub network: Network,
    pub tx_version: u32,
    /// The consensus branch id the PCZT was built for.
    pub branch_id: u32,
    /// Pools that carry data, in canonical order.
    pub pools: Vec<Pool>,
    pub payments: Vec<PaymentLine>,
    /// The transaction fee in zatoshis, when every value it depends on was present.
    pub fee: Option<u64>,
    pub findings: Vec<Finding>,
}

impl Report {
    /// Builds a report, deriving the verdict from the severity of its findings.
    ///
    /// In strict mode a warning is enough to block signing, because a privacy leak is not
    /// something a user can undo afterwards.
    pub(crate) fn from_draft(draft: Draft) -> Self {
        let worst = draft.findings.iter().map(|f| f.severity).max();
        let verdict = match worst {
            Some(Severity::Unsafe) => Verdict::Unsafe,
            Some(Severity::CannotVerify) => Verdict::CannotVerify,
            Some(Severity::Warn) if draft.strict => Verdict::Unsafe,
            _ => Verdict::Safe,
        };
        Report {
            verdict,
            network: draft.network,
            tx_version: draft.tx_version,
            branch_id: draft.branch_id,
            pools: draft.pools,
            payments: draft.payments,
            fee: draft.fee,
            findings: draft.findings,
        }
    }
}

/// Zatoshis to ZEC, with the eight decimals people expect to see on a receipt.
pub(crate) fn zec(zats: u64) -> String {
    format!("{}.{:08} ZEC", zats / 100_000_000, zats % 100_000_000)
}

/// Everything gathered while verifying, ready to become a [`Report`].
pub(crate) struct Draft {
    pub network: Network,
    pub tx_version: u32,
    pub branch_id: u32,
    pub pools: Vec<Pool>,
    pub payments: Vec<PaymentLine>,
    pub fee: Option<u64>,
    pub findings: Vec<Finding>,
    pub strict: bool,
}
