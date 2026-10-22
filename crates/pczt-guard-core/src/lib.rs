//! PCZT Guard — check the cheque before you sign it.
//!
//! An offline, key-free verifier for [PCZTs] (partially created Zcash transactions).
//! A signer runs [`verify`] on the bytes it was handed, before signing, and gets one of
//! three answers: [`Verdict::Safe`], [`Verdict::Unsafe`], or [`Verdict::CannotVerify`].
//!
//! The verifier never needs a spending key, never mutates the PCZT, and never touches the
//! network. Optional information (an expected network, a viewing key, expected payments)
//! makes the answer strictly stronger; nothing is assumed when it is absent.
//!
//! [PCZTs]: https://github.com/zcash/librustzcash/tree/main/pczt
//!
//! # Example
//!
//! ```no_run
//! # fn main() -> Result<(), pczt_guard_core::GuardError> {
//! let bytes = std::fs::read("payment.pczt").unwrap();
//! let report = pczt_guard_core::verify(&bytes, &pczt_guard_core::Options::default())?;
//! println!("{:?}", report.verdict);
//! # Ok(()) }
//! ```

mod binding;
mod checks;
mod ownership;
mod privacy;
mod report;
mod text;
mod value;

pub use report::{
    Finding, FindingCode, Network, PaymentLine, Pool, Report, Role, Severity, Verdict,
};
pub use text::{decode_text, has_display_hazard, is_display_hazard};

/// The PCZT encodings Guard can read. Re-exported so callers can assert on what they hold.
pub use pczt::EncodingVersion;

use binding::LabeledOutput;
use ownership::{Ownership, ViewingKeys};
use pczt::{roles::verifier::Verifier, Pczt};
use privacy::{Privacy, TransparentOutput};
use transparent::address::TransparentAddress;
use value::Tally;
use zcash_address::unified::{Address as UnifiedAddress, Encoding as _, Receiver, Revision, Uitem};
use zcash_protocol::{consensus::NetworkType, PoolType};

/// Inputs a signer can supply to make the verdict stronger.
#[derive(Clone, Debug, Default)]
pub struct Options {
    /// The network this signer expects. If set, a PCZT built for another network is
    /// rejected instead of silently signed.
    pub expected_network: Option<Network>,
    /// Treat an output that carries value but has no `user_address` as informational.
    ///
    /// Off by default: an unlabeled output is one the signer cannot describe to the user,
    /// which is what an attacker wants. Turn it on only for wallets that routinely omit
    /// change labels.
    pub allow_unlabeled_change: bool,
    /// Treat a warning (a privacy leak, a fee far above the conventional one) as a failure.
    pub strict: bool,
    /// The signer's own full viewing keys.
    ///
    /// Supplying one turns trial decryption on: an unlabelled output that decrypts is
    /// proven change, and one that does not is proven to be paying somebody else. Only the
    /// Orchard-family pools can be decrypted; a Sapling output stays unknown.
    ///
    /// A viewing key is not a spending key: it reveals this wallet's own notes and nothing
    /// else, and it is never needed to run the checks that do not involve ownership.
    pub ufvks: Vec<orchard::keys::FullViewingKey>,
    /// The chain height to compare the PCZT's expiry height against, when the caller knows
    /// it. Guard never learns it on its own, because it never touches the network.
    pub at_height: Option<u32>,
}

/// Why PCZT Guard could not produce a report at all.
#[derive(Debug)]
pub struct GuardError {
    detail: String,
}

impl std::fmt::Display for GuardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "the input is not a PCZT: {}", self.detail)
    }
}

impl std::error::Error for GuardError {}

/// What the pool passes accumulate as they run.
struct Ctx<'a> {
    network_type: NetworkType,
    allow_unlabeled_change: bool,
    keys: &'a ViewingKeys,
    findings: &'a mut Vec<Finding>,
    payments: &'a mut Vec<PaymentLine>,
    tally: &'a mut Tally,
    privacy: &'a mut Privacy,
}

/// Verifies a serialized PCZT.
///
/// Returns `Err` only when the bytes are not a PCZT at all. Every other problem becomes a
/// [`Finding`] attached to the returned [`Report`].
pub fn verify(bytes: &[u8], options: &Options) -> Result<Report, GuardError> {
    let pczt = Pczt::parse(bytes).map_err(|e| GuardError {
        detail: format!("{e:?}"),
    })?;

    let global = pczt.global();
    let network = Network::from_coin_type(*global.coin_type());
    let tx_version = *global.tx_version();
    let branch_id = *global.consensus_branch_id();

    let mut findings = stage_2_structure(&pczt, tx_version, network, options);
    let mut payments = Vec::new();
    let mut tally = Tally::new();
    let mut privacy = Privacy::default();

    let mut pools = Vec::new();
    if pczt.has_data_in_pool(PoolType::IRONWOOD) {
        pools.push(Pool::Ironwood);
    }
    if pczt.has_data_in_pool(PoolType::ORCHARD) {
        pools.push(Pool::Orchard);
    }
    if pczt.has_data_in_pool(PoolType::SAPLING) {
        pools.push(Pool::Sapling);
    }
    if pczt.has_data_in_pool(PoolType::TRANSPARENT) {
        pools.push(Pool::Transparent);
    }

    // A PCZT with nothing in it is not a safe transaction, it is an absence of one. Saying
    // SAFE would tell a signer that a report describing no payments is a report of a payment
    // that was checked, which is the opposite of true. A constructor, or an attacker who can
    // swap files, can produce exactly this.
    if pools.is_empty() {
        findings.push(Finding::new(
            FindingCode::EmptyTransaction,
            Severity::CannotVerify,
            None,
            None,
            "the PCZT spends nothing and pays nobody, so there is no transaction to sign",
        ));
    }

    {
        let keys = ViewingKeys::new(&options.ufvks);
        let mut ctx = Ctx {
            network_type: network_type(network),
            allow_unlabeled_change: options.allow_unlabeled_change,
            keys: &keys,
            findings: &mut findings,
            payments: &mut payments,
            tally: &mut tally,
            privacy: &mut privacy,
        };

        for pool in [Pool::Ironwood, Pool::Orchard, Pool::Sapling] {
            if !pools.contains(&pool) {
                continue;
            }
            if pool == Pool::Sapling {
                run_sapling(&pczt, &mut ctx);
            } else {
                run_orchard_family(&pczt, pool, &mut ctx);
            }
        }
        if pools.contains(&Pool::Transparent) {
            run_transparent(&pczt, &mut ctx);
        }
    }

    let (fee_findings, fee) = value::evaluate(&tally);
    findings.extend(fee_findings);
    findings.extend(privacy::evaluate(&privacy));

    Ok(Report::from_draft(report::Draft {
        network,
        tx_version,
        branch_id,
        pools,
        payments,
        fee,
        findings,
        strict: options.strict,
    }))
}

/// Stage 2: the transaction-wide fields, and whether they hold together.
fn stage_2_structure(
    pczt: &Pczt,
    tx_version: u32,
    network: Network,
    options: &Options,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    if let Some(expected) = options.expected_network {
        if expected != network {
            findings.push(Finding::new(
                FindingCode::NetworkMismatch,
                Severity::Unsafe,
                None,
                None,
                format!("the PCZT is for {network:?} but this signer expects {expected:?}"),
            ));
        }
    }

    // A PCZT whose `coin_type` names no network we know cannot be judged: the signer would be
    // committing to a transaction for a chain nobody identified. `--expect-network` catches a
    // *wrong* network; this catches an *unrecognised* one when no expectation was given.
    if let Network::Other(coin_type) = network {
        findings.push(Finding::new(
            FindingCode::UnknownNetwork,
            Severity::CannotVerify,
            None,
            None,
            format!(
                "the PCZT declares coin type {coin_type}, which is neither mainnet (0) nor \
                 testnet (1), so the chain it is for is unknown"
            ),
        ));
    }

    // Only a v6 or later transaction format can carry an Ironwood bundle. `pczt` refuses
    // to encode one otherwise, so this can only fire on hand-built bytes.
    if pczt.has_data_in_pool(PoolType::IRONWOOD) && tx_version < 6 {
        findings.push(Finding::new(
            FindingCode::InconsistentPczt,
            Severity::Unsafe,
            Some(Pool::Ironwood),
            None,
            format!("an Ironwood bundle requires tx version 6 or later, found {tx_version}"),
        ));
    }

    if let Some(at_height) = options.at_height {
        let expiry = *pczt.global().expiry_height();
        if expiry == 0 {
            findings.push(Finding::new(
                FindingCode::NoExpiry,
                Severity::Info,
                None,
                None,
                "the PCZT sets no expiry height, so it stays valid until its notes are spent",
            ));
        } else if expiry <= at_height {
            findings.push(Finding::new(
                FindingCode::Expired,
                Severity::Unsafe,
                None,
                None,
                format!(
                    "the expiry height {expiry} is not above the assumed chain height \
                     {at_height}, so this transaction can never be mined"
                ),
            ));
        }
    }

    findings
}

/// Stages 3 and 4: an Orchard-family bundle (Ironwood or Orchard), plus stages 7 and 9.
fn run_orchard_family(pczt: &Pczt, pool: Pool, ctx: &mut Ctx<'_>) {
    let verifier = Verifier::new(pczt.clone());
    let result = if pool == Pool::Ironwood {
        verifier.with_ironwood::<std::convert::Infallible, _>(|bundle| {
            orchard_checks(bundle, pool, ctx);
            Ok(())
        })
    } else {
        verifier.with_orchard::<std::convert::Infallible, _>(|bundle| {
            orchard_checks(bundle, pool, ctx);
            Ok(())
        })
    };
    if let Err(e) = result {
        ctx.findings.push(checks::orchard_parse_error(pool, e));
    }
}

fn orchard_checks(bundle: &orchard::pczt::Bundle, pool: Pool, ctx: &mut Ctx<'_>) {
    ctx.findings.extend(checks::orchard_family(bundle, pool));
    ctx.findings.extend(checks::orchard_anchor(bundle, pool));
    ctx.findings.extend(checks::orchard_proof(bundle, pool));

    let ownership: Vec<Ownership> = bundle
        .actions()
        .iter()
        .map(|action| ctx.keys.classify(bundle, action))
        .collect();

    let (spends, mut outputs) = orchard_values(bundle);
    // A value that trial decryption recovered is the note's real value, so it fills in a
    // redacted one and lets the fee be computed exactly.
    for (declared, owned) in outputs.iter_mut().zip(&ownership) {
        if declared.is_none() {
            if let Ownership::Ours { value } = owned {
                *declared = Some(*value);
            }
        }
    }

    for value in &spends {
        ctx.tally.spend(*value);
    }
    for value in &outputs {
        ctx.tally.output(*value);
    }

    let actions = bundle.actions().len();
    ctx.tally.count_actions(actions as u64);
    if pool == Pool::Ironwood {
        ctx.privacy.ironwood_actions += actions;
    } else {
        ctx.privacy.orchard_actions += actions;
    }

    if let Some(finding) = value::balance_check(
        pool,
        value::orchard_declared(bundle.value_sum()),
        &spends,
        &outputs,
    ) {
        ctx.findings.push(finding);
    }
    if *bundle.anchor_deferred() {
        ctx.findings.push(value::deferred_anchor(pool));
    }

    let (findings, payments) = binding::bind(
        pool,
        ctx.allow_unlabeled_change,
        ctx.network_type,
        orchard_outputs(bundle, ctx.network_type, &ownership),
    );
    ctx.findings.extend(findings);
    ctx.payments.extend(payments);
}

/// Stage 5: the Sapling bundle, plus stages 7 and 9.
fn run_sapling(pczt: &Pczt, ctx: &mut Ctx<'_>) {
    let result =
        Verifier::new(pczt.clone()).with_sapling::<std::convert::Infallible, _>(|bundle| {
            ctx.findings.extend(checks::sapling(bundle));

            for spend in bundle.spends() {
                ctx.tally.spend(spend.value().map(|v| v.inner()));
            }
            for output in bundle.outputs() {
                ctx.tally.output(output.value().map(|v| v.inner()));
            }
            let items = bundle.spends().len() + bundle.outputs().len();
            ctx.tally.count_actions(items as u64);
            ctx.privacy.sapling_actions += items;

            // Stage 9 for Sapling: does the bundle agree with its own actions? The value
            // balance is committed by the transaction digest, so a contradiction here makes
            // the transaction unmineable rather than stealable — but it is still a
            // contradiction, and leaving it unchecked meant one pool was judged more
            // leniently than the other.
            let spends: Vec<Option<u64>> = bundle
                .spends()
                .iter()
                .map(|spend| spend.value().map(|v| v.inner()))
                .collect();
            let outputs_value: Vec<Option<u64>> = bundle
                .outputs()
                .iter()
                .map(|output| output.value().map(|v| v.inner()))
                .collect();
            if let Some(finding) = value::balance_check(
                Pool::Sapling,
                bundle.value_sum().to_raw(),
                &spends,
                &outputs_value,
            ) {
                ctx.findings.push(finding);
            }

            let outputs = bundle
                .outputs()
                .iter()
                .map(|output| LabeledOutput {
                    value: output.value().map(|v| v.inner()),
                    receiver: output.recipient().map(|r| Receiver::Sapling(r.to_bytes())),
                    committed_display: output
                        .recipient()
                        .map(|r| encode_sapling_receiver(r.to_bytes(), ctx.network_type)),
                    user_address: output.user_address().as_deref(),
                    // Sapling trial decryption is not implemented: the pool is deprecated
                    // after NU6.3, and its notes cannot cross into Ironwood.
                    ownership: Ownership::Unknown,
                })
                .collect();
            let (findings, payments) = binding::bind(
                Pool::Sapling,
                ctx.allow_unlabeled_change,
                ctx.network_type,
                outputs,
            );
            ctx.findings.extend(findings);
            ctx.payments.extend(payments);
            Ok(())
        });
    if let Err(e) = result {
        ctx.findings.push(checks::sapling_parse_error(e));
    }
}

/// Stage 6: the transparent bundle, plus stages 7 and 9.
fn run_transparent(pczt: &Pczt, ctx: &mut Ctx<'_>) {
    let result =
        Verifier::new(pczt.clone()).with_transparent::<std::convert::Infallible, _>(|bundle| {
            for (index, input) in bundle.inputs().iter().enumerate() {
                if let Err(e) = input.verify() {
                    ctx.findings
                        .push(checks::transparent_item_error(e, "input", index));
                }
                ctx.tally.spend(Some(u64::from(*input.value())));
            }
            ctx.privacy.transparent_inputs += bundle.inputs().len();

            let mut outputs = Vec::new();
            for (index, output) in bundle.outputs().iter().enumerate() {
                if let Err(e) = output.verify() {
                    ctx.findings
                        .push(checks::transparent_item_error(e, "output", index));
                }
                let value = u64::from(*output.value());
                ctx.tally.output(Some(value));
                ctx.privacy.transparent_outputs.push(TransparentOutput {
                    value,
                    is_wallet_owned: !output.bip32_derivation().is_empty(),
                });
                outputs.push(LabeledOutput {
                    value: Some(value),
                    receiver: TransparentAddress::from_script_pubkey(output.script_pubkey()).map(
                        |address| match address {
                            TransparentAddress::PublicKeyHash(hash) => Receiver::P2pkh(hash),
                            TransparentAddress::ScriptHash(hash) => Receiver::P2sh(hash),
                        },
                    ),
                    // `zcash_address` 0.14 has no bare transparent encoder, so the
                    // committed side is compared as raw receiver bytes and not printed.
                    committed_display: None,
                    user_address: output.user_address().as_deref(),
                    // Transparent outputs carry no note ciphertext to decrypt.
                    ownership: Ownership::Unknown,
                });
            }
            let items = bundle.inputs().len() + bundle.outputs().len();
            ctx.tally.count_actions(items as u64);

            let (findings, payments) = binding::bind(
                Pool::Transparent,
                ctx.allow_unlabeled_change,
                ctx.network_type,
                outputs,
            );
            ctx.findings.extend(findings);
            ctx.payments.extend(payments);
            Ok(())
        });
    if let Err(e) = result {
        ctx.findings.push(checks::transparent_parse_error(e));
    }
}

/// The spend and output values of an Orchard-family bundle, in action order.
fn orchard_values(bundle: &orchard::pczt::Bundle) -> (Vec<Option<u64>>, Vec<Option<u64>>) {
    let mut spends = Vec::new();
    let mut outputs = Vec::new();
    for action in bundle.actions() {
        spends.push(action.spend().value().map(|v| v.inner()));
        outputs.push(action.output().value().map(|v| v.inner()));
    }
    (spends, outputs)
}

/// Every Ironwood/Orchard output, reduced to what stage 7 needs.
///
/// Zero-value outputs are padding — ZIP 326 dummies, and the fabricated outputs that pair
/// with each spend — so they carry no funds and are dropped by [`binding::bind`].
fn orchard_outputs<'a>(
    bundle: &'a orchard::pczt::Bundle,
    network_type: NetworkType,
    ownership: &[Ownership],
) -> Vec<LabeledOutput<'a>> {
    bundle
        .actions()
        .iter()
        .zip(ownership)
        .map(|(action, owned)| {
            let output = action.output();
            let value = match (output.value().map(|v| v.inner()), owned) {
                (None, Ownership::Ours { value }) => Some(*value),
                (declared, _) => declared,
            };
            LabeledOutput {
                value,
                receiver: output
                    .recipient()
                    .map(|r| Receiver::Orchard(r.to_raw_address_bytes())),
                committed_display: output
                    .recipient()
                    .map(|r| encode_orchard_receiver(r.to_raw_address_bytes(), network_type)),
                user_address: output.user_address().as_deref(),
                ownership: *owned,
            }
        })
        .collect()
}

fn encode_orchard_receiver(raw: [u8; 43], network_type: NetworkType) -> String {
    match UnifiedAddress::try_from_items(Revision::R0, vec![Uitem::Data(Receiver::Orchard(raw))]) {
        Ok(ua) => ua.encode(&network_type),
        Err(_) => format!("<unencodable orchard receiver {}>", hex(&raw)),
    }
}

fn encode_sapling_receiver(raw: [u8; 43], network_type: NetworkType) -> String {
    match UnifiedAddress::try_from_items(Revision::R0, vec![Uitem::Data(Receiver::Sapling(raw))]) {
        Ok(ua) => ua.encode(&network_type),
        Err(_) => format!("<unencodable sapling receiver {}>", hex(&raw)),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn network_type(network: Network) -> NetworkType {
    match network {
        Network::Main => NetworkType::Main,
        // Regtest shares the testnet HRP and coin type.
        Network::Test | Network::Other(_) => NetworkType::Test,
    }
}
