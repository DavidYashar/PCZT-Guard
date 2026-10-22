//! Privacy lints: things that are valid but leak.
//!
//! These never say a PCZT is dishonest; they say it is a bad idea. Everything here is
//! `Warn` or `Info`, so the verdict stays `Safe` unless the signer asked for
//! [`crate::Options::strict`], where a warning is enough to block signing — a leak cannot
//! be undone after the fact, which is not true of a rejected signature.
//!
//! ## What is not covered, and why
//!
//! * **PL05, a memo that a transparent recipient silently discards.** A PCZT carries no
//!   record of the sender's intent, and the memo lives inside the encrypted note, so this
//!   needs a viewing key to see. It is not implementable from the bytes alone.
//! * Anything about *which* shielded output is change. A viewing key answers that; the
//!   committed receivers do not.

use crate::report::{zec, Finding, FindingCode, Severity};

/// A transparent output, reduced to what the lints need.
#[derive(Clone, Copy, Debug)]
pub(crate) struct TransparentOutput {
    pub value: u64,
    /// Whether the PCZT carries a BIP 32 derivation for it, which means it is the
    /// wallet's own output rather than the payee's.
    pub is_wallet_owned: bool,
}

/// The shape of the transaction, as far as privacy is concerned.
#[derive(Clone, Debug, Default)]
pub(crate) struct Privacy {
    pub transparent_inputs: usize,
    pub transparent_outputs: Vec<TransparentOutput>,
    pub sapling_actions: usize,
    pub orchard_actions: usize,
    pub ironwood_actions: usize,
}

/// An amount that is not a round multiple of this is distinctive enough to stand out.
const ROUND_AMOUNT_ZATS: u64 = 1_000_000;

pub(crate) fn evaluate(privacy: &Privacy) -> Vec<Finding> {
    let mut findings = Vec::new();

    // PL01 — transparent inputs are public, and they are the inputs that link a shielded
    // transaction to everything else those coins ever did.
    if privacy.transparent_inputs > 0 {
        findings.push(Finding::new(
            FindingCode::TransparentInputLink,
            Severity::Warn,
            None,
            None,
            format!(
                "the transaction spends {} transparent input(s), which publishes its link to \
                 those coins' history",
                privacy.transparent_inputs
            ),
        ));
    }

    // PL02 — a transparent output the wallet controls is change, and change is public.
    let owned: Vec<&TransparentOutput> = privacy
        .transparent_outputs
        .iter()
        .filter(|output| output.is_wallet_owned)
        .collect();
    if !owned.is_empty() {
        findings.push(Finding::new(
            FindingCode::TransparentChangeLink,
            Severity::Warn,
            None,
            None,
            format!(
                "{} transparent output(s) belong to this wallet, so its change is public",
                owned.len()
            ),
        ));
    }

    // PL03 — the Orchard→Ironwood turnstile publishes the amount that crosses it.
    let crossing = (privacy.sapling_actions > 0 || privacy.orchard_actions > 0)
        && privacy.ironwood_actions > 0;
    if crossing {
        findings.push(Finding::new(
            FindingCode::TurnstileCrossing,
            Severity::Info,
            None,
            None,
            "value crosses the Orchard/Ironwood turnstile in this transaction, so the amount \
             that crosses is visible to everyone"
                .to_string(),
        ));
    }

    // PL04 — an amount everyone can see is a fingerprint when it is not a round number.
    for output in &privacy.transparent_outputs {
        if output.value % ROUND_AMOUNT_ZATS != 0 {
            findings.push(Finding::new(
                FindingCode::UniqueAmount,
                Severity::Info,
                None,
                None,
                format!(
                    "{} leaving to a transparent address is not a round number, and a \
                     distinctive amount is a fingerprint",
                    zec(output.value)
                ),
            ));
        }
    }

    // PL06 — touching two shielded pools in one transaction links them.
    let shielded_pools = [
        privacy.sapling_actions > 0,
        privacy.orchard_actions > 0,
        privacy.ironwood_actions > 0,
    ]
    .iter()
    .filter(|in_use| **in_use)
    .count();
    if shielded_pools > 1 {
        findings.push(Finding::new(
            FindingCode::MixedPools,
            Severity::Info,
            None,
            None,
            format!(
                "the transaction touches {shielded_pools} shielded pools, which links what \
                 would otherwise be unlinkable"
            ),
        ));
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ironwood_only() -> Privacy {
        Privacy {
            ironwood_actions: 2,
            ..Privacy::default()
        }
    }

    #[test]
    fn a_simple_shielded_payment_has_no_lints() {
        assert!(evaluate(&ironwood_only()).is_empty());
    }

    #[test]
    fn transparent_inputs_are_a_warning() {
        let privacy = Privacy {
            transparent_inputs: 2,
            ..ironwood_only()
        };
        let findings = evaluate(&privacy);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, FindingCode::TransparentInputLink);
        assert_eq!(findings[0].severity, Severity::Warn);
        assert_eq!(findings[0].code.lint_id(), Some("PL01"));
    }

    #[test]
    fn transparent_change_is_a_warning() {
        let privacy = Privacy {
            transparent_outputs: vec![TransparentOutput {
                value: 5_000_000,
                is_wallet_owned: true,
            }],
            ..ironwood_only()
        };
        let findings = evaluate(&privacy);
        assert!(findings
            .iter()
            .any(|f| f.code == FindingCode::TransparentChangeLink));
    }

    #[test]
    fn a_turnstile_crossing_is_informational() {
        let privacy = Privacy {
            orchard_actions: 2,
            ..ironwood_only()
        };
        let findings = evaluate(&privacy);
        assert!(findings
            .iter()
            .any(|f| f.code == FindingCode::TurnstileCrossing));
        assert!(findings.iter().any(|f| f.code == FindingCode::MixedPools));
        assert!(findings.iter().all(|f| f.severity <= Severity::Info));
    }

    #[test]
    fn a_distinctive_public_amount_is_informational() {
        let privacy = Privacy {
            transparent_outputs: vec![TransparentOutput {
                value: 123_456_789,
                is_wallet_owned: false,
            }],
            ..ironwood_only()
        };
        let findings = evaluate(&privacy);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, FindingCode::UniqueAmount);
        assert!(findings[0].detail.contains("1.23456789 ZEC"));
    }

    #[test]
    fn a_round_public_amount_is_left_alone() {
        let privacy = Privacy {
            transparent_outputs: vec![TransparentOutput {
                value: 100_000_000,
                is_wallet_owned: false,
            }],
            ..ironwood_only()
        };
        assert!(evaluate(&privacy).is_empty());
    }
}
