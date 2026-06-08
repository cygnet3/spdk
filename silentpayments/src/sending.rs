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

use crate::utils::common::TransactionSharedSecret;
use crate::utils::common::calculate_t_n;
use crate::{Error, Result};
use crate::SilentPaymentAddress;

/// Create outputs for a given set of silent payment recipients and their corresponding shared secrets.
///
/// When creating the outputs for a transaction, this function should be used to generate the output keys.
///
/// This function should only be used once per transaction! If used multiple times, address reuse may occur.
///
/// # Arguments
///
/// * `recipients` - Silent payment addresses to pay, in output order. Multiple entries may share the
///   same scan key; output index `n` is assigned per scan-key group in this order.
/// * `shared_secrets` - One [`TransactionSharedSecret`] per unique scan key (`B_scan`), keyed by that
///   public key.
///
/// # Returns
///
/// If successful, the function returns a [Result] wrapping a [HashMap] of silent payment addresses to a [Vec].
/// The [Vec] contains all the outputs that are associated with the silent payment address.
///
/// # Errors
///
/// This function will return an error if:
///
/// * A recipient's scan key is missing from `shared_secrets`.
/// * Edge cases are hit during elliptic curve computation (extremely unlikely).
pub fn generate_recipient_pubkeys(
    recipients: &[SilentPaymentAddress],
    shared_secrets: &HashMap<PublicKey, TransactionSharedSecret>,
) -> Result<HashMap<SilentPaymentAddress, Vec<XOnlyPublicKey>>> {
    let secp = Secp256k1::new();

    let mut silent_payment_groups: HashMap<PublicKey, (TransactionSharedSecret, Vec<SilentPaymentAddress>)> =
        HashMap::new();
    for address in recipients {
        let b_scan = address.get_scan_key();

        if let Some((_, payments)) = silent_payment_groups.get_mut(&b_scan) {
            payments.push(*address);
        } else {
            let shared_secret = shared_secrets.get(&b_scan).ok_or_else(|| {
                Error::GenericError(format!("Missing shared secret for scan key {b_scan}"))
            })?;
            silent_payment_groups.insert(b_scan, (*shared_secret, vec![*address]));
        }
    }

    let mut result: HashMap<SilentPaymentAddress, Vec<XOnlyPublicKey>> = HashMap::new();
    for (ecdh_shared_secret, addresses) in silent_payment_groups.into_values() {
        for (n, addr) in addresses.into_iter().enumerate() {
            let t_n = calculate_t_n(&ecdh_shared_secret, n as u32)?;

            let res = t_n.public_key(&secp);
            let reskey = res.combine(&addr.get_spend_key())?;
            let (reskey_xonly, _) = reskey.x_only_public_key();

            let entry = result.entry(addr).or_default();
            entry.push(reskey_xonly);
        }
    }
    Ok(result)
}
