//! Stage 9: do the values add up, and is the fee sane?
//!
//! Two different questions, both about money:
//!
//! * **Balance.** A bundle that declares one net value while its actions sum to another is
//!   lying to somebody — the Prover, the Signer, or the user reading the fee. Either way a
//!   signer should not sign it.
//! * **Fee.** Value that disappears without going anywhere is the fee. A fee far larger
//!   than the transaction warrants is a drain, and it is invisible unless someone computes
//!   it.
//!
//! Everything here is skipped, not guessed, when a value is redacted: the result is an
//! informational finding, never a pass and never a failure.

use orchard::value::{Sign, ValueSum};

use crate::report::{Finding, FindingCode, Pool, Severity};

/// ZIP 317's marginal fee per action.
const MARGINAL_FEE: u64 = 5_000;
/// ZIP 317 charges at least this many actions' worth.
const GRACE_ACTIONS: u64 = 2;
/// A fee this many times the conventional fee is worth warning about.
const HIGH_FEE_MULTIPLE: u64 = 10;

/// Running totals over every pool in the transaction.
#[derive(Debug, Default)]
pub(crate) struct Tally {
    input: i128,
    output: i128,
    /// Set when any value the totals need was redacted.
    incomplete: bool,
    actions: u64,
}

impl Tally {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn spend(&mut self, value: Option<u64>) {
        self.add(value, true);
    }

    pub(crate) fn output(&mut self, value: Option<u64>) {
        self.add(value, false);
    }

    fn add(&mut self, value: Option<u64>, is_input: bool) {
        match value {
            Some(value) => {
                if is_input {
                    self.input += i128::from(value);
                } else {
                    self.output += i128::from(value);
                }
            }
            None => self.incomplete = true,
        }
    }

    pub(crate) fn count_actions(&mut self, actions: u64) {
        self.actions = self.actions.saturating_add(actions);
    }

    /// The transaction fee, if every value it depends on was present.
    fn fee(&self) -> Option<i128> {
        (!self.incomplete).then_some(self.input - self.output)
    }

    /// What ZIP 317 would charge for a transaction of this shape.
    pub(crate) fn conventional_fee(&self) -> u64 {
        MARGINAL_FEE * self.actions.max(GRACE_ACTIONS)
    }
}

/// Turns the totals into the fee, and into findings if anything is wrong.
pub(crate) fn evaluate(tally: &Tally) -> (Vec<Finding>, Option<u64>) {
    let Some(fee) = tally.fee() else {
        return (
            vec![Finding::new(
                FindingCode::RedactedValue,
                Severity::Info,
                None,
                None,
                "the fee cannot be computed because at least one value is redacted".to_string(),
            )],
            None,
        );
    };

    if fee < 0 {
        return (
            vec![Finding::new(
                FindingCode::ValueImbalance,
                Severity::Unsafe,
                None,
                None,
                format!(
                    "the outputs exceed the inputs by {} zats: this transaction creates value",
                    -fee
                ),
            )],
            None,
        );
    }

    let fee = fee as u64;
    let conventional = tally.conventional_fee();
    let mut findings = Vec::new();
    if fee > conventional.saturating_mul(HIGH_FEE_MULTIPLE) {
        findings.push(Finding::new(
            FindingCode::HighFee,
            Severity::Warn,
            None,
            None,
            format!(
                "the fee is {}, {:.0}× the {} ZIP 317 charges for {} actions",
                crate::report::zec(fee),
                fee as f64 / conventional as f64,
                crate::report::zec(conventional),
                tally.actions
            ),
        ));
    }

    (findings, Some(fee))
}

/// The net value an Orchard-family bundle declares, as a signed integer.
pub(crate) fn orchard_declared(value_sum: &ValueSum) -> i128 {
    let (magnitude, sign) = value_sum.magnitude_sign();
    match sign {
        Sign::Positive => i128::from(magnitude),
        Sign::Negative => -i128::from(magnitude),
    }
}

/// Compares a bundle's declared net value against the net its own actions imply.
///
/// Returns `None` when a value is redacted, because then nothing is being contradicted.
pub(crate) fn balance_check(
    pool: Pool,
    declared: i128,
    spends: &[Option<u64>],
    outputs: &[Option<u64>],
) -> Option<Finding> {
    if spends.iter().chain(outputs).any(Option::is_none) {
        return None;
    }

    let sum =
        |values: &[Option<u64>]| -> i128 { values.iter().flatten().map(|v| i128::from(*v)).sum() };
    let computed = sum(spends) - sum(outputs);

    (declared != computed).then(|| {
        Finding::new(
            FindingCode::ValueImbalance,
            Severity::Unsafe,
            Some(pool),
            None,
            format!(
                "the bundle declares a net value of {declared} zats but its actions sum to {computed}"
            ),
        )
    })
}

/// ZIP 374: a v6+ PCZT may be signed before its anchors and witnesses exist.
pub(crate) fn deferred_anchor(pool: Pool) -> Finding {
    Finding::new(
        FindingCode::DeferredAnchor,
        Severity::Info,
        Some(pool),
        None,
        "the anchor and witnesses are deferred to proving time (ZIP 374); the Prover must \
         install them, and this signature does not commit to them"
            .to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tally(input: Option<u64>, output: Option<u64>, actions: u64) -> Tally {
        let mut tally = Tally::new();
        tally.spend(input);
        tally.output(output);
        tally.count_actions(actions);
        tally
    }

    #[test]
    fn the_fee_is_input_minus_output_when_nothing_is_redacted() {
        let (findings, fee) = evaluate(&tally(Some(100_000_000), Some(99_990_000), 2));
        assert_eq!(fee, Some(10_000));
        assert!(findings.is_empty());
    }

    #[test]
    fn more_output_than_input_creates_value() {
        let (findings, fee) = evaluate(&tally(Some(1), Some(2), 2));
        assert_eq!(fee, None);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, FindingCode::ValueImbalance);
        assert_eq!(findings[0].severity, Severity::Unsafe);
    }

    #[test]
    fn a_fee_far_above_the_conventional_one_is_a_warning_not_a_failure() {
        let (findings, fee) = evaluate(&tally(Some(100_000_000), Some(1_000_000), 2));
        assert_eq!(fee, Some(99_000_000));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, FindingCode::HighFee);
        assert_eq!(findings[0].severity, Severity::Warn);
    }

    #[test]
    fn a_redacted_value_makes_the_fee_unknown_rather_than_zero() {
        let (findings, fee) = evaluate(&tally(Some(100_000_000), None, 2));
        assert_eq!(fee, None);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, FindingCode::RedactedValue);
        assert_eq!(findings[0].severity, Severity::Info);
    }

    #[test]
    fn a_generous_fee_within_the_multiple_is_accepted() {
        // 4 actions: conventional is 20,000; 10x that is 200,000.
        let (findings, _) = evaluate(&tally(Some(1_000_000), Some(800_000), 4));
        assert!(findings.is_empty(), "{findings:#?}");
    }
}
