//! Stage 7: does the address the user is shown match the address the money goes to?
//!
//! This is the check the stock Signer does not perform (librustzcash#3155). Every other
//! check in PCZT Guard proves the PCZT is internally consistent; this one proves it is
//! *honest*.
//!
//! The comparison is on raw receiver bytes, never on strings: `user_address` is parsed into
//! a [`ZcashAddress`], and the address has to contain the exact receiver that the output's
//! note commitment was built over. A Unified Address is matched on the receiver for the
//! pool being checked, so a UA that carries an Orchard receiver satisfies an Ironwood
//! output (Ironwood shares the Orchard receiver).
//!
//! [`ZcashAddress`]: zcash_address::ZcashAddress

use zcash_address::{unified::Receiver, ZcashAddress};
use zcash_protocol::consensus::NetworkType;

use crate::ownership::Ownership;
use crate::report::{zec, Finding, FindingCode, PaymentLine, Pool, Role, Severity};

/// One output, reduced to the facts stage 7 needs.
pub(crate) struct LabeledOutput<'a> {
    /// Value in zatoshis. `None` when the PCZT redacted it.
    pub value: Option<u64>,
    /// The receiver the value is committed to. `None` when redacted.
    pub receiver: Option<Receiver>,
    /// How to print the committed receiver when explaining a mismatch.
    pub committed_display: Option<String>,
    /// The address the user is shown, verbatim from the PCZT.
    pub user_address: Option<&'a str>,
    /// What trial decryption with the signer's viewing keys proved about this output.
    pub ownership: Ownership,
}

/// Binds every output's label to its committed receiver.
///
/// Returns the findings and one [`PaymentLine`] per output that carries value. Zero-value
/// outputs are padding and are left out entirely: they cannot move funds, and including
/// them would flag every honest transaction.
pub(crate) fn bind(
    pool: Pool,
    allow_unlabeled: bool,
    network: NetworkType,
    outputs: Vec<LabeledOutput<'_>>,
) -> (Vec<Finding>, Vec<PaymentLine>) {
    let mut findings = Vec::new();
    let mut payments = Vec::new();

    for output in outputs {
        // A value recovered by trial decryption is the note's real value, so it can stand
        // in for a redacted one.
        let ownership = output.ownership;
        let value = match (output.value, ownership) {
            (None, Ownership::Ours { value }) => Some(value),
            (declared, _) => declared,
        };
        if value == Some(0) {
            continue;
        }

        let mut bound = false;
        let mut role = Role::External;
        match (output.receiver, output.user_address) {
            (None, shown) => {
                findings.push(Finding::new(
                    FindingCode::RedactedField,
                    Severity::CannotVerify,
                    Some(pool),
                    None,
                    format!(
                        "the recipient is redacted, so the address {} cannot be checked",
                        describe_label(shown)
                    ),
                ));
            }
            (Some(_), None) => match ownership {
                Ownership::Ours { value } => {
                    bound = true;
                    role = Role::Change;
                    findings.push(Finding::new(
                        FindingCode::OwnedChange,
                        Severity::Info,
                        Some(pool),
                        None,
                        format!(
                            "{} of change, proven by trial-decrypting it with the supplied viewing key",
                            zec(value)
                        ),
                    ));
                }
                Ownership::NotOurs => {
                    // With a key in hand this is a *proof*, not a gap, so no flag may soften
                    // it. `allow_unlabeled` exists to accept outputs nobody could check
                    // (`Unknown` below); using it here would let a caller switch off the
                    // finding that the whole viewing-key feature exists to produce.
                    findings.push(Finding::new(
                        FindingCode::NotOurOutput,
                        Severity::Unsafe,
                        Some(pool),
                        None,
                        format!(
                            "output carries {} zats, has no user_address, and is not encrypted to \
                             any supplied viewing key, so it is paying somebody else (if this \
                             wallet has more accounts, supply their viewing keys too)",
                            value.map_or("an unknown number of".to_string(), |v| v.to_string())
                        ),
                    ));
                }
                Ownership::Unknown => {
                    let severity = if allow_unlabeled {
                        Severity::Info
                    } else {
                        Severity::CannotVerify
                    };
                    findings.push(Finding::new(
                        FindingCode::UnlabeledOutput,
                        severity,
                        Some(pool),
                        None,
                        format!(
                            "output carries {} zats but no user_address, so it cannot be shown to the signer",
                            value.map_or("an unknown amount of".to_string(), |v| v.to_string())
                        ),
                    ));
                }
            },
            (Some(receiver), Some(shown)) => {
                let label = check_label(
                    pool,
                    network,
                    &receiver,
                    shown,
                    ownership,
                    output.committed_display.as_deref(),
                );
                findings.extend(label.findings);
                bound = label.bound;
                if label.self_transfer {
                    role = Role::SelfTransfer;
                }
            }
        }

        payments.push(PaymentLine {
            pool,
            value,
            shown: output.user_address.map(str::to_owned),
            committed: output.committed_display,
            bound,
            role,
        });
    }

    (findings, payments)
}

/// What checking one labelled output produced.
struct LabelCheck {
    findings: Vec<Finding>,
    /// Whether the label was proven to contain the committed receiver.
    bound: bool,
    /// Whether the output was also proven to belong to the signer.
    self_transfer: bool,
}

/// Judges one `user_address` against the receiver the value is committed to.
///
/// Written as a flat early-returning function because every branch is a different verdict,
/// and a nested match made it easy to add a case that silently fell through to "bound".
fn check_label(
    pool: Pool,
    network: NetworkType,
    receiver: &Receiver,
    shown: &str,
    ownership: Ownership,
    committed: Option<&str>,
) -> LabelCheck {
    let finding = |code, detail| LabelCheck {
        findings: vec![Finding::new(
            code,
            Severity::Unsafe,
            Some(pool),
            None,
            detail,
        )],
        bound: false,
        self_transfer: false,
    };

    // The label is free text from a file the signer did not write, and it is printed to a
    // terminal. A control character in it is not a typo: an `ESC[2K` / `ESC[3A` pair erases
    // the lines above and repaints the verdict, so the report can be made to read SAFE
    // while it says UNSAFE. There is nothing to compare either, because no address contains
    // control characters.
    if shown.chars().any(char::is_control) {
        return finding(
            FindingCode::LabelControlCharacters,
            format!(
                "user_address {shown:?} contains control characters, which can rewrite what a \
                 terminal shows for this report"
            ),
        );
    }

    let address = match ZcashAddress::try_from_encoded(shown) {
        Ok(address) => address,
        Err(e) => {
            return finding(
                FindingCode::BadAddress,
                format!("user_address {shown:?} does not decode: {e:?}"),
            )
        }
    };

    if let Some(actual) = label_network(&address) {
        if !same_network(actual, network) {
            return finding(
                FindingCode::LabelNetworkMismatch,
                format!(
                    "user_address {shown:?} is a {actual:?} address but this transaction is for \
                     {network:?}"
                ),
            );
        }
    }

    if !address.can_receive_as(pool_type(pool)) {
        return finding(
            FindingCode::NoReceiverForPool,
            format!("user_address {shown:?} cannot receive in the {pool:?} pool"),
        );
    }

    if address.matches_receiver(receiver) {
        return LabelCheck {
            findings: Vec::new(),
            bound: true,
            // A label that matches and is also ours is an honest self-transfer, which is
            // what change looks like when a wallet does label it.
            self_transfer: matches!(ownership, Ownership::Ours { .. }),
        };
    }

    match ownership {
        Ownership::Ours { value } => finding(
            FindingCode::SelfPaymentLabeledExternal,
            format!(
                "the user is shown {shown:?}, but the {} is encrypted to this wallet's own \
                 viewing key, so the funds never leave it",
                zec(value)
            ),
        ),
        _ => finding(
            FindingCode::AddressMismatch,
            format!(
                "the user is shown {shown:?} but the value is committed to {}",
                committed.unwrap_or("a different receiver")
            ),
        ),
    }
}

/// The network a parsed address belongs to, read back out of the address itself.
///
/// `ZcashAddress` keeps its network private and exposes no accessor, so this asks the
/// conversion machinery instead: every conversion method is handed the address's network,
/// and a converter that refuses carries it back in [`ConversionError::User`].
fn label_network(address: &ZcashAddress) -> Option<NetworkType> {
    use zcash_address::{ConversionError, TryFromAddress};

    struct NetworkProbe;

    impl TryFromAddress for NetworkProbe {
        type Error = NetworkType;

        fn try_from_sprout(
            net: NetworkType,
            _: [u8; 64],
        ) -> Result<Self, ConversionError<NetworkType>> {
            Err(ConversionError::User(net))
        }

        fn try_from_sapling(
            net: NetworkType,
            _: [u8; 43],
        ) -> Result<Self, ConversionError<NetworkType>> {
            Err(ConversionError::User(net))
        }

        fn try_from_unified(
            net: NetworkType,
            _: zcash_address::unified::Address,
        ) -> Result<Self, ConversionError<NetworkType>> {
            Err(ConversionError::User(net))
        }

        fn try_from_transparent_p2pkh(
            net: NetworkType,
            _: [u8; 20],
        ) -> Result<Self, ConversionError<NetworkType>> {
            Err(ConversionError::User(net))
        }

        fn try_from_transparent_p2sh(
            net: NetworkType,
            _: [u8; 20],
        ) -> Result<Self, ConversionError<NetworkType>> {
            Err(ConversionError::User(net))
        }

        fn try_from_tex(
            net: NetworkType,
            _: [u8; 20],
        ) -> Result<Self, ConversionError<NetworkType>> {
            Err(ConversionError::User(net))
        }
    }

    match address.clone().convert::<NetworkProbe>() {
        Err(ConversionError::User(net)) => Some(net),
        _ => None,
    }
}

/// Testnet and regtest addresses are interchangeable for the fields Guard compares.
fn same_network(a: NetworkType, b: NetworkType) -> bool {
    a == b
        || matches!(
            (a, b),
            (NetworkType::Test, NetworkType::Regtest) | (NetworkType::Regtest, NetworkType::Test)
        )
}

// Ironwood has no address typecode of its own: it reuses the Orchard receiver.
fn pool_type(pool: Pool) -> zcash_protocol::PoolType {
    use zcash_protocol::PoolType;
    match pool {
        Pool::Transparent => PoolType::TRANSPARENT,
        Pool::Sapling => PoolType::SAPLING,
        Pool::Orchard | Pool::Ironwood => PoolType::ORCHARD,
    }
}

fn describe_label(shown: Option<&str>) -> String {
    match shown {
        Some(s) => format!("{s:?}"),
        None => "(absent)".to_string(),
    }
}
