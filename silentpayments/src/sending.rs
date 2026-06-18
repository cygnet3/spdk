//! The sending component of silent payments.
//!
//! The [`generate_recipient_pubkeys`] function creates taproot output keys for silent payment recipients.
//!
//! Callers must supply a [`TransactionSharedSecret`] per unique recipient scan key.
//! On the sender side, build secrets from a [`GlobalSenderEcdhShare`](crate::utils::sending::GlobalSenderEcdhShare)
//! or from combined [`PartialSenderEcdhShare`](crate::utils::sending::PartialSenderEcdhShare)s.
//! See [the test vectors](https://github.com/cygnet3/spdk/blob/master/silentpayments/tests/vector_tests.rs)
//! for a full example.

use secp256k1::{PublicKey, Secp256k1, XOnlyPublicKey};
use std::collections::HashMap;

use crate::utils::common::calculate_t_n;
use crate::utils::common::SilentPaymentAddressRaw;
use crate::utils::common::TransactionSharedSecret;
use crate::{Error, Result};

/// Create taproot output keys for a set of silent payment recipients.
///
/// Recipients are grouped by scan key. Within each group the BIP352 output-index counter `n`
/// increments in the order the addresses appear in `recipients`, so callers must pass addresses
/// in their intended output order. Calling this function more than once for the same transaction
/// with the same `shared_secrets` will restart every `n` counter at 0, producing duplicate output
/// keys and breaking recipient privacy — call it exactly once per transaction.
///
/// # Arguments
///
/// * `recipients` - Silent payment addresses to pay, in output order. Multiple entries may share
///   the same scan key; `n` is assigned within that scan-key group in the order given.
/// * `shared_secrets` - One [`TransactionSharedSecret`] per unique scan key, keyed by that scan
///   `PublicKey`. Each entry's internally stored scan key must equal its map key.
///
/// # Returns
///
/// A [`HashMap`] whose keys are the original addresses from `recipients` and whose values are the
/// corresponding taproot [`XOnlyPublicKey`] outputs.
pub fn generate_recipient_pubkeys<C: secp256k1::Signing>(
    secp: &Secp256k1<C>,
    recipients: &[SilentPaymentAddressRaw],
    shared_secrets: &HashMap<PublicKey, TransactionSharedSecret>,
) -> Result<HashMap<SilentPaymentAddressRaw, Vec<XOnlyPublicKey>>> {
    let mut silent_payment_groups: HashMap<
        PublicKey,
        (TransactionSharedSecret, Vec<SilentPaymentAddressRaw>),
    > = HashMap::new();

    for address in recipients {
        let recipient_scan_key = address.get_scan_pubkey();

        if let Some((_, payments)) = silent_payment_groups.get_mut(&recipient_scan_key) {
            payments.push(*address);
        } else {
            let shared_secret = shared_secrets.get(&recipient_scan_key).ok_or_else(|| {
                Error::GenericError(format!(
                    "Missing shared secret for scan key {recipient_scan_key}"
                ))
            })?;
            if shared_secret.as_recipient_scan_key() != &recipient_scan_key {
                return Err(Error::GenericError(format!(
                    "Shared secret stored under scan key {recipient_scan_key} has mismatched \
                     internal scan key {}",
                    shared_secret.as_recipient_scan_key()
                )));
            }
            silent_payment_groups.insert(recipient_scan_key, (*shared_secret, vec![*address]));
        }
    }

    let mut result: HashMap<SilentPaymentAddressRaw, Vec<XOnlyPublicKey>> = HashMap::new();
    for (ecdh_shared_secret, addresses) in silent_payment_groups.into_values() {
        for (n, addr) in addresses.into_iter().enumerate() {
            let t_n = calculate_t_n(&ecdh_shared_secret, n as u32)?;

            let res = t_n.public_key(secp);
            let reskey = res.combine(&addr.get_m_pubkey())?;
            let (reskey_xonly, _) = reskey.x_only_public_key();

            result.entry(addr).or_default().push(reskey_xonly);
        }
    }
    Ok(result)
}
