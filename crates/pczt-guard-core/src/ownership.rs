//! Stage 8: is this output the signer's own change, or somebody else's?
//!
//! Without a viewing key an unlabelled output is unknowable: it could be this wallet's
//! change or a payment an attacker inserted while removing its label. With a viewing key
//! it becomes a proof. Trial-decrypting the output's note ciphertext succeeds only for a
//! note actually addressed to that key, and the decryption binds the result to the action's
//! `cmx`, so "it decrypted" means "this value is mine".
//!
//! That turns the weakest verdict into the strongest one:
//!
//! * it decrypted → proven change, so the payment line can be shown to the signer;
//! * it did not decrypt, and the PCZT gives no address for it → proven *not* the signer's,
//!   which is the hidden-output attack (threat T3), now `UNSAFE`;
//! * no key was supplied, or the bundle version defines no note-encryption domain →
//!   [`Ownership::Unknown`], and the verdict stays [`crate::Verdict::CannotVerify`] rather
//!   than being mistaken for either answer.
//!
//! Decryption is sound because [`orchard::pczt::Action::decrypt_output_with_ivk`] re-derives
//! the note commitment: a ciphertext that decrypts cannot have been swapped for another
//! note after the fact.

use orchard::{
    keys::{FullViewingKey, PreparedIncomingViewingKey, Scope},
    pczt::{Action, Bundle},
};

/// What trial decryption proved about one output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Ownership {
    /// Nothing was proven: no key was supplied, or this bundle version has no
    /// note-encryption domain, so no trial decryption was attempted.
    Unknown,
    /// The note decrypted under one of the supplied keys, and carries this value.
    Ours { value: u64 },
    /// Every supplied key was tried and none decrypted the note.
    NotOurs,
}

/// The prepared incoming viewing keys of every wallet the signer speaks for.
///
/// Both scopes are prepared for each key: wallets send to their internal scope for change
/// and to their external scope for self-payments, and a change output is far more often the
/// former.
pub(crate) struct ViewingKeys {
    keys: Vec<PreparedIncomingViewingKey>,
}

impl ViewingKeys {
    /// Prepares a key set once, so the expensive part is not repeated per action.
    pub fn new(fvks: &[FullViewingKey]) -> Self {
        let mut keys = Vec::with_capacity(fvks.len() * 2);
        for fvk in fvks {
            for scope in [Scope::External, Scope::Internal] {
                keys.push(PreparedIncomingViewingKey::new(&fvk.to_ivk(scope)));
            }
        }
        ViewingKeys { keys }
    }

    /// Trial-decrypts one action's output against every key.
    pub fn classify(&self, bundle: &Bundle, action: &Action) -> Ownership {
        if self.keys.is_empty() {
            return Ownership::Unknown;
        }

        let version = *bundle.bundle_version();
        for key in &self.keys {
            match action.decrypt_output_with_ivk(key, version) {
                Ok(Some((note, _, _))) => {
                    return Ownership::Ours {
                        value: note.value().inner(),
                    }
                }
                Ok(None) => continue,
                // `orchard` defines no note-encryption domain for this bundle version, so
                // nothing was learned. Reporting `NotOurs` here would libel an honest
                // output, so the answer has to stay unknown.
                Err(_) => return Ownership::Unknown,
            }
        }
        Ownership::NotOurs
    }
}
