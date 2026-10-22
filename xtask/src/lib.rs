//! Fixture generation for PCZT Guard.
//!
//! Builds real, structurally valid PCZTs (Ironwood pool, Testnet, post-NU6.3) so that
//! PCZT Guard can be tested and demonstrated without spending Testnet funds:
//!
//! * [`Payment::honest`] — the recipient shown in `user_address` is the recipient the
//!   value is cryptographically committed to.
//! * [`Payment::address_deception`] — the value is committed to a different recipient
//!   while `user_address` still shows the original one. This is the attack described in
//!   librustzcash#3155.
//!
//! Both PCZTs are internally consistent: every commitment, nullifier, randomizer and
//! value balance verifies. The only difference is who the money actually goes to.

use std::convert::Infallible;

use orchard::{
    keys::{FullViewingKey, Scope, SpendingKey},
    note::{Note, NoteVersion, RandomSeed, Rho},
    pczt::Zip32Derivation,
    value::NoteValue,
    Address as OrchardAddress,
};
use pczt::roles::{creator::Creator, updater::Updater};
use rand_core::UnwrapErr;
use zcash_address::unified::{Address as UnifiedAddress, Encoding as _, Receiver, Revision, Uitem};
use zcash_primitives::transaction::{
    builder::{BundlePadding, DeferredPcztBuilder},
    fees::zip317::FeeRule as Zip317,
};
use zcash_protocol::{
    consensus::{BlockHeight, Network},
    memo::MemoBytes,
    value::Zatoshis,
};

/// Height used for every fixture: on Testnet this is after NU6.3 (4,134,000) and before
/// NU7 (4,465,026), so the transaction is v6 and the Ironwood pool is active.
pub const FIXTURE_HEIGHT: u32 = 4_200_000;

const OWNER_SEED: [u8; 32] = [7; 32];
const ALICE_SEED: [u8; 32] = [9; 32];
const MALLORY_SEED: [u8; 32] = [11; 32];

/// A generated PCZT plus the facts a verifier needs to judge it.
#[derive(Debug)]
pub struct Payment {
    /// The serialized PCZT, ready to be written to a `.pczt` file.
    pub bytes: Vec<u8>,
    /// The address a human is shown (`user_address` on the recipient output), if set.
    pub shown_address: Option<String>,
    /// The address the value is actually committed to.
    pub committed_address: String,
    /// The value of the recipient output, in zatoshis.
    pub value: u64,
    /// The fee, in zatoshis.
    pub fee: u64,
    /// Action index holding the spend (needed to sign).
    pub spend_action: usize,
    /// Action index holding the recipient output (needed to label it).
    pub output_action: usize,
}

fn keys(seed: [u8; 32]) -> (SpendingKey, FullViewingKey) {
    let sk = SpendingKey::from_bytes(seed).unwrap();
    let fvk = FullViewingKey::from(&sk);
    (sk, fvk)
}

/// The account that owns the note being spent.
pub fn owner() -> (SpendingKey, FullViewingKey) {
    keys(OWNER_SEED)
}

/// The intended recipient, as encoded in the honest `user_address`.
pub fn alice() -> OrchardAddress {
    keys(ALICE_SEED).1.address_at(0u32, Scope::External)
}

/// The attacker's address: what a tampered PCZT actually pays.
pub fn mallory() -> OrchardAddress {
    keys(MALLORY_SEED).1.address_at(0u32, Scope::External)
}

/// The owner's external address: where a payment back into this wallet would go.
pub fn owner_address() -> OrchardAddress {
    owner().1.address_at(0u32, Scope::External)
}

/// The recipient's full viewing key, for tests that need a key that is *not* the owner's.
pub fn alice_fvk() -> FullViewingKey {
    keys(ALICE_SEED).1
}

/// The owner's account as a Unified Full Viewing Key string — what `--ufvk` accepts.
///
/// A UFVK reveals incoming notes and cannot spend, which is exactly the amount of
/// authority PCZT Guard needs to prove an unlabelled output is the signer's own change.
pub fn owner_ufvk_encoded() -> String {
    let (_, fvk) = owner();
    encode_ufvk(fvk)
}

/// The recipient's account as a UFVK: a valid key that is not the signer's.
pub fn alice_ufvk_encoded() -> String {
    encode_ufvk(alice_fvk())
}

fn encode_ufvk(fvk: FullViewingKey) -> String {
    zcash_keys::keys::UnifiedFullViewingKey::from_orchard_fvk(fvk)
        .expect("an Orchard-only unified key is valid")
        .encode(&Network::TestNetwork)
        .expect("an Orchard-only unified key encodes")
}

/// Encodes a raw Orchard receiver as a Unified Address, which is the form wallets put in
/// `user_address`. Ironwood shares the Orchard receiver (verified in `zcash_keys`).
pub fn encode_address(addr: OrchardAddress) -> String {
    let ua = UnifiedAddress::try_from_items(
        Revision::R0,
        vec![zcash_address::unified::Uitem::Data(
            zcash_address::unified::Receiver::Orchard(addr.to_raw_address_bytes()),
        )],
    )
    .expect("a single Orchard receiver is a valid Unified Address");
    ua.encode(&zcash_protocol::consensus::NetworkType::Test)
}

/// A note owned by `fvk`, in the Ironwood note plaintext format.
fn owned_note(fvk: &FullViewingKey, value: u64) -> Note {
    let rho = Rho::from_bytes(&[3; 32]).unwrap();
    let rseed = RandomSeed::from_bytes([5; 32], &rho).unwrap();
    Note::from_parts(
        fvk.address_at(0u32, Scope::External),
        NoteValue::from_raw(value),
        rho,
        rseed,
        NoteVersion::V3,
    )
    .unwrap()
}

fn deferred_builder() -> DeferredPcztBuilder<Network> {
    DeferredPcztBuilder::new::<Infallible>(
        Network::TestNetwork,
        BlockHeight::from_u32(FIXTURE_HEIGHT),
        BundlePadding::DEFAULT,
        BundlePadding::DEFAULT,
    )
    .expect("NU6.3 testnet height supports deferred-anchor PCZTs")
}

/// The fee ZIP 317 charges for this transaction's shape. The fee depends only on the
/// action counts, so it can be measured with a throwaway output of the same shape.
fn fee_for(fvk: &FullViewingKey, note: &Note, recipient: OrchardAddress) -> u64 {
    let mut builder = deferred_builder();
    builder
        .add_ironwood_spend::<Infallible>(fvk.clone(), *note)
        .expect("note is owned by the fvk");
    builder
        .add_ironwood_output::<Infallible>(
            None,
            recipient,
            Zatoshis::const_from_u64(0),
            MemoBytes::empty(),
        )
        .expect("output is well formed");
    u64::from(
        builder
            .get_fee(&Zip317::standard())
            .expect("ZIP 317 fee is computable"),
    )
}

/// Builds a PCZT that sends `value` to `paid_to` while telling the user it pays `shown`.
///
/// Passing the same address for both arguments yields an honest PCZT. Passing different
/// ones yields the address-deception attack: internally consistent, and paying somebody
/// other than the address on the label.
pub fn payment(paid_to: OrchardAddress, shown: OrchardAddress, value: u64) -> Payment {
    payment_with_label(paid_to, Some(encode_address(shown)), value)
}

/// A PCZT whose `user_address` carries ANSI escape sequences.
///
/// Twenty-odd bytes are enough to clear the lines above and repaint the verdict, so a label
/// like this is an attack on the report rather than a malformed address.
pub fn label_with_control_characters() -> Payment {
    payment_with_label(
        alice(),
        Some("prize\u{1b}[2K\u{1b}[3ASAFE\u{1b}[0m".to_string()),
        100_000_000,
    )
}

/// A PCZT whose `user_address` uses a bidirectional override.
///
/// `U+202E` (right-to-left override) makes the following characters render in reverse order,
/// so the address a reader sees is not the address in the bytes. It is a Unicode *format*
/// character, not a control character, so `char::is_control` does not catch it.
pub fn label_with_bidi_override() -> Payment {
    payment_with_label(
        alice(),
        Some("utest1\u{202E}00ff\u{202C}deadbeef".to_string()),
        100_000_000,
    )
}

/// A PCZT whose `user_address` hides characters with zero-width joiners.
pub fn label_with_zero_width() -> Payment {
    payment_with_label(
        alice(),
        Some("utest1\u{200B}abc\u{200D}def".to_string()),
        100_000_000,
    )
}

/// A PCZT whose `user_address` is long and multi-byte, so displaying it must truncate on a
/// character boundary rather than at a byte offset.
pub fn label_long_multibyte() -> Payment {
    payment_with_label(
        alice(),
        Some(format!("utest1{}", "ü".repeat(40))),
        100_000_000,
    )
}

/// As [`payment`], but the label is arbitrary text — including something that is not an
/// address, an address that cannot receive in the Ironwood pool, or nothing at all.
pub fn payment_with_label(paid_to: OrchardAddress, label: Option<String>, value: u64) -> Payment {
    let (_, fvk) = owner();
    let placeholder = owned_note(&fvk, value + 10_000);
    let fee = fee_for(&fvk, &placeholder, paid_to);
    assemble(paid_to, label, value + fee, value, fee, &Zip317::standard())
}

/// A 2-action payment that pays 0.99 ZEC in fees to nobody: a fee drain.
///
/// The builder only accepts a transaction whose inputs exceed its outputs by exactly the
/// fee its rule demands, so a fee this size needs a rule that asks for it.
pub fn inflated_fee() -> Payment {
    const INPUT: u64 = 100_000_000;
    const OUTPUT: u64 = 1_000_000;
    const FEE: u64 = INPUT - OUTPUT;
    assemble(
        alice(),
        Some(encode_address(alice())),
        INPUT,
        OUTPUT,
        FEE,
        &FixedFee(FEE),
    )
}

/// A payment **with change**: the shape every real wallet produces.
///
/// `zcash_client_backend` sets `user_address` only on outputs paying somebody else, so the
/// change output here carries value and no label — exactly what a wallet hands a signer.
pub fn payment_with_change() -> Payment {
    const INPUT: u64 = 100_000_000;
    const PAYMENT: u64 = 40_000_000;

    let (_, fvk) = owner();
    let change_to = fvk.address_at(0u32, Scope::External);
    let fee = fee_for_outputs(&fvk, INPUT, &[alice(), change_to]);

    let mut builder = deferred_builder();
    builder
        .add_ironwood_spend::<Infallible>(fvk.clone(), owned_note(&fvk, INPUT))
        .expect("note is owned by the fvk");
    builder
        .add_ironwood_output::<Infallible>(
            None,
            alice(),
            Zatoshis::const_from_u64(PAYMENT),
            MemoBytes::empty(),
        )
        .expect("output is well formed");
    builder
        .add_ironwood_output::<Infallible>(
            None,
            change_to,
            Zatoshis::const_from_u64(INPUT - PAYMENT - fee),
            MemoBytes::empty(),
        )
        .expect("output is well formed");

    let result = builder
        .build_for_pczt(UnwrapErr(rand::rngs::SysRng), &Zip317::standard())
        .expect("spend and outputs balance against the fee");

    let meta = result.ironwood_meta;
    let spend_action = meta.spend_action_index(0).expect("one spend was added");
    let output_action = meta
        .output_action_index(0)
        .expect("the payment output was added");

    let pczt = Creator::build_from_parts(result.pczt_parts)
        .expect("a v6 transaction is representable as a PCZT");
    let label = encode_address(alice());
    let pczt = Updater::new(pczt)
        .update_ironwood_with(|mut u| {
            u.update_action_with(output_action, |mut action| {
                action.set_output_user_address(label.clone());
                Ok(())
            })
        })
        .expect("the output action exists")
        .finish();

    finish(
        pczt,
        Some(label),
        alice(),
        PAYMENT,
        fee,
        spend_action,
        output_action,
    )
}

/// The fee for a spend with the given outputs, measured on a throwaway build of the same
/// shape (the fee depends only on the counts).
fn fee_for_outputs(fvk: &FullViewingKey, input: u64, recipients: &[OrchardAddress]) -> u64 {
    let mut builder = deferred_builder();
    builder
        .add_ironwood_spend::<Infallible>(fvk.clone(), owned_note(fvk, input))
        .expect("note is owned by the fvk");
    for recipient in recipients {
        builder
            .add_ironwood_output::<Infallible>(
                None,
                *recipient,
                Zatoshis::const_from_u64(0),
                MemoBytes::empty(),
            )
            .expect("output is well formed");
    }
    u64::from(
        builder
            .get_fee(&Zip317::standard())
            .expect("ZIP 317 fee is computable"),
    )
}

/// A payment with change, carrying the extra fields `zcash_client_backend` attaches:
/// ZIP 32 derivations on the spend and the labelled output, and a proprietary blob.
///
/// This is the shape a wallet hands a signer, which our own builder never produces.
pub fn wallet_shaped() -> Payment {
    let (spend_index, output_index) = {
        let payment = payment_with_change();
        (payment.spend_action, payment.output_action)
    };
    let source = payment_with_change();
    let pczt = pczt::Pczt::parse(&source.bytes).expect("just built");

    let updated = Updater::new(pczt)
        .update_ironwood_with(|mut u| {
            u.update_action_with(spend_index, |mut action| {
                action.set_spend_zip32_derivation(zip32_derivation());
                Ok(())
            })?;
            u.update_action_with(output_index, |mut action| {
                action.set_output_zip32_derivation(zip32_derivation());
                action.set_output_proprietary(
                    PROPRIETARY_OUTPUT_INFO.to_string(),
                    PROPRIETARY_VALUE.to_vec(),
                );
                Ok(())
            })
        })
        .expect("the actions exist")
        .finish();

    Payment {
        bytes: updated.serialize().expect("the PCZT is encodable"),
        ..source
    }
}

/// [`wallet_shaped`] with its derivable fields compacted, which is what a wallet does to
/// shrink a PCZT for a QR code: `cv_net` and `cmx` are dropped and must be re-derived when
/// the PCZT is parsed again.
pub fn wallet_shaped_compacted() -> Payment {
    let source = wallet_shaped();
    let pczt = pczt::Pczt::parse(&source.bytes).expect("just built");
    let compacted = pczt::roles::redactor::Redactor::new(pczt)
        .redact_ironwood_with(|mut bundle| bundle.compact_resolvable_fields())
        .finish();
    Payment {
        bytes: compacted
            .serialize_with_version()
            .expect("the PCZT is encodable")
            .1,
        ..source
    }
}

/// A standard ZIP 32 path: purpose 32', coin type 1' (testnet), account 0'.
fn zip32_derivation() -> Zip32Derivation {
    Zip32Derivation::parse([0xAB; 32], vec![0x8000_0020, 0x8000_0001, 0x8000_0000])
        .expect("a standard ZIP 32 path")
}

/// The key `zcash_client_backend` uses for its per-output metadata.
const PROPRIETARY_OUTPUT_INFO: &str = "zcash_client_backend:output_info";
/// Stand-in for the postcard-encoded `PcztRecipient` a wallet stores there.
const PROPRIETARY_VALUE: &[u8] = &[0x01, 0xA4, 0x7F, 0x00, 0x2B, 0x9C];

/// A fee rule that always demands the same amount. Used to build transactions whose fee no
/// sane wallet would choose.
struct FixedFee(u64);
impl zcash_primitives::transaction::fees::FeeRule for FixedFee {
    type Error = Infallible;

    fn fee_required<P: zcash_protocol::consensus::Parameters>(
        &self,
        _params: &P,
        _target_height: BlockHeight,
        _transparent_input_sizes: impl IntoIterator<
            Item = zcash_primitives::transaction::fees::transparent::InputSize,
        >,
        _transparent_output_sizes: impl IntoIterator<Item = usize>,
        _sapling_input_count: usize,
        _sapling_output_count: usize,
        _orchard_action_count: usize,
        _ironwood_action_count: usize,
    ) -> Result<Zatoshis, Infallible> {
        Ok(Zatoshis::const_from_u64(self.0))
    }
}

/// A structurally valid PCZT that spends nothing and pays nobody.
///
/// A constructor can produce this, and an attacker who controls one can hand it to a signer
/// instead of the payment the user expects. It is indistinguishable from "nothing happened",
/// which is why Guard must refuse to call it safe rather than reporting a vacuous pass.
pub fn empty() -> Payment {
    let builder = deferred_builder();
    let result = builder
        .build_for_pczt(UnwrapErr(rand::rngs::SysRng), &FixedFee(0))
        .expect("an empty transaction balances at a zero fee");
    let pczt = Creator::build_from_parts(result.pczt_parts)
        .expect("a v6 transaction is representable as a PCZT");
    Payment {
        bytes: pczt.serialize().expect("the PCZT encodes"),
        shown_address: None,
        committed_address: String::new(),
        value: 0,
        fee: 0,
        spend_action: 0,
        output_action: 0,
    }
}

/// Assembles a PCZT paying `output_value` with `input_value` of notes, under `fee_rule`.
fn assemble<FR>(
    paid_to: OrchardAddress,
    label: Option<String>,
    input_value: u64,
    output_value: u64,
    fee: u64,
    fee_rule: &FR,
) -> Payment
where
    FR: zcash_primitives::transaction::fees::FeeRule,
    FR::Error: std::fmt::Debug,
{
    let (_, fvk) = owner();
    let note = owned_note(&fvk, input_value);

    let mut builder = deferred_builder();
    builder
        .add_ironwood_spend::<Infallible>(fvk, note)
        .expect("note is owned by the fvk");
    builder
        .add_ironwood_output::<Infallible>(
            None,
            paid_to,
            Zatoshis::const_from_u64(output_value),
            MemoBytes::empty(),
        )
        .expect("output is well formed");

    let result = builder
        .build_for_pczt(UnwrapErr(rand::rngs::SysRng), fee_rule)
        .expect("spend and output balance against the fee");

    let meta = result.ironwood_meta;
    let spend_action = meta.spend_action_index(0).expect("one spend was added");
    let output_action = meta
        .output_action_index(0)
        .expect("one non-change output was added");

    let pczt = Creator::build_from_parts(result.pczt_parts)
        .expect("a v6 transaction is representable as a PCZT");

    let pczt = match &label {
        Some(label) => Updater::new(pczt)
            .update_ironwood_with(|mut u| {
                u.update_action_with(output_action, |mut action| {
                    action.set_output_user_address(label.clone());
                    Ok(())
                })
            })
            .expect("the output action exists")
            .finish(),
        None => pczt,
    };

    finish(
        pczt,
        label,
        paid_to,
        output_value,
        fee,
        spend_action,
        output_action,
    )
}

#[allow(clippy::too_many_arguments)]
fn finish(
    pczt: pczt::Pczt,
    shown_address: Option<String>,
    paid_to: OrchardAddress,
    value: u64,
    fee: u64,
    spend_action: usize,
    output_action: usize,
) -> Payment {
    Payment {
        bytes: pczt.serialize().expect("the PCZT is encodable"),
        shown_address,
        committed_address: encode_address(paid_to),
        value,
        fee,
        spend_action,
        output_action,
    }
}

/// An honest 1 ZEC payment: what the user is shown is what gets paid.
pub fn honest() -> Payment {
    payment(alice(), alice(), 100_000_000)
}

/// The address-deception attack (librustzcash#3155): the label says Alice, the money goes
/// to Mallory. Every cryptographic field is self-consistent.
pub fn address_deception() -> Payment {
    payment(mallory(), alice(), 100_000_000)
}

/// Same attack, but the attacker relabels the output with something that is not an address
/// at all.
pub fn label_not_an_address() -> Payment {
    payment_with_label(mallory(), Some("notanaddress".to_string()), 100_000_000)
}

/// The label is a valid Unified Address that cannot receive in the Ironwood pool, while the
/// value is committed to Mallory.
pub fn label_wrong_pool() -> Payment {
    payment_with_label(
        mallory(),
        Some(unified_with_unknown_receiver()),
        100_000_000,
    )
}

/// The output carries value but no label at all: the signer has nothing to show the user.
pub fn unlabeled() -> Payment {
    payment_with_label(alice(), None, 100_000_000)
}

/// The honest payment with its recipient field stripped, so no check can bind the label.
pub fn redacted_recipient() -> Payment {
    redacted(|mut action| action.clear_output_recipient())
}

/// The honest payment with the recipient output's value stripped, so the fee is unknowable.
pub fn redacted_value() -> Payment {
    redacted(|mut action| action.clear_output_value())
}

fn redacted(
    clear: impl FnOnce(pczt::roles::redactor::orchard::ActionRedactor<'_>) + 'static,
) -> Payment {
    let payment = payment(alice(), alice(), 100_000_000);
    let index = payment.output_action;
    let pczt = pczt::Pczt::parse(&payment.bytes).expect("just built");
    let redacted = pczt::roles::redactor::Redactor::new(pczt)
        .redact_ironwood_with(|mut bundle| {
            bundle.redact_action(index, clear);
        })
        .finish();
    Payment {
        bytes: redacted.serialize().expect("the PCZT is encodable"),
        ..payment
    }
}

/// A Unified Address whose only receiver has a typecode nothing here recognises, so no
/// known pool can receive to it.
fn unified_with_unknown_receiver() -> String {
    let ua = UnifiedAddress::try_from_items(
        Revision::R0,
        vec![Uitem::Data(Receiver::Unknown {
            typecode: 0x99,
            data: vec![7u8; 43],
        })],
    )
    .expect("an unrecognised receiver typecode is encodable");
    ua.encode(&zcash_protocol::consensus::NetworkType::Test)
}
