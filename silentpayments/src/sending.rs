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
use crate::utils::common::TransactionSharedSecret;
use crate::SILENT_PAYMENT_ADDRESS_BYTE_LEN;
use crate::{Error, Result};

/// Create taproot output keys for a set of silent payment recipients.
///
/// Recipients are grouped by scan key. Within each group the BIP352 output-index counter `n`
/// increments in the order the addresses appear in `recipients`, so callers must pass addresses
/// in their intended output order.  Calling this function more than once for the same transaction
/// with the same `shared_secrets` will restart every `n` counter at 0, producing duplicate output
/// keys and breaking recipient privacy — call it exactly once per transaction.
///
/// # Arguments
///
/// * `recipients` - Silent payment address byte arrays to pay, in output order.  Each entry is
///   `[version (1) | scan_pubkey (33) | spend_pubkey (33)]` (67 bytes total).  Multiple entries
///   may share the same scan key; `n` is assigned within that scan-key group in the order given.
/// * `shared_secrets` - One [`TransactionSharedSecret`] per unique scan key, keyed by that scan
///   `PublicKey`.  Each entry's internally stored scan key must equal its map key (this is
///   asserted at runtime as a caller-contract check).
///
/// # Returns
///
/// A [`HashMap`] whose keys are the original address byte arrays from `recipients` and whose
/// values are the corresponding taproot [`XOnlyPublicKey`] outputs.  A single address that
/// appears *k* times in `recipients` maps to a `Vec` of *k* distinct output keys.
///
/// # Errors
///
/// * A recipient's scan key is missing from `shared_secrets`.
/// * The stored scan key inside a [`TransactionSharedSecret`] does not match its map key.
/// * An elliptic-curve operation fails (e.g. point-at-infinity; negligible probability).
pub fn generate_recipient_pubkeys<C: secp256k1::Signing>(
    secp: &Secp256k1<C>,
    recipients: &[[u8; SILENT_PAYMENT_ADDRESS_BYTE_LEN]],
    shared_secrets: &HashMap<PublicKey, TransactionSharedSecret>,
) -> Result<HashMap<[u8; SILENT_PAYMENT_ADDRESS_BYTE_LEN], Vec<XOnlyPublicKey>>> {
    // Group spend keys by scan key so that n is incremented once per scan-key group, not per
    // address.  We also carry the version byte so the output map keys round-trip correctly.
    let mut silent_payment_groups: HashMap<
        PublicKey,
        (
            TransactionSharedSecret,
            Vec<&[u8; SILENT_PAYMENT_ADDRESS_BYTE_LEN]>,
        ),
    > = HashMap::new();
    for address in recipients {
        let recipient_scan_key = PublicKey::from_slice(&address[1..34])?;

        if let Some((_, payments)) = silent_payment_groups.get_mut(&recipient_scan_key) {
            payments.push(address);
        } else {
            let shared_secret = shared_secrets.get(&recipient_scan_key).ok_or_else(|| {
                Error::GenericError(format!(
                    "Missing shared secret for scan key {recipient_scan_key}"
                ))
            })?;
            // Caller-contract assertion: the TransactionSharedSecret stored under this map key
            // must have the same scan key internally.  This can only fail if the caller built
            // the shared_secrets map incorrectly (e.g. inserted a secret under the wrong key).
            if shared_secret.as_recipient_scan_key() != &recipient_scan_key {
                return Err(Error::GenericError(format!(
                    "Shared secret stored under scan key {recipient_scan_key} has mismatched \
                     internal scan key {}",
                    shared_secret.as_recipient_scan_key()
                )));
            }
            silent_payment_groups.insert(recipient_scan_key, (*shared_secret, vec![address]));
        }
    }

    let mut result: HashMap<[u8; SILENT_PAYMENT_ADDRESS_BYTE_LEN], Vec<XOnlyPublicKey>> =
        HashMap::new();
    for (ecdh_shared_secret, addresses) in silent_payment_groups.into_values() {
        for (n, addr) in addresses.into_iter().enumerate() {
            let t_n = calculate_t_n(&ecdh_shared_secret, n as u32)?;

            let res = t_n.public_key(secp);
            let reskey = res.combine(&PublicKey::from_slice(&addr[34..])?)?;
            let (reskey_xonly, _) = reskey.x_only_public_key();

            let entry = result.entry(*addr).or_default();
            entry.push(reskey_xonly);
        }
    }
    Ok(result)
}
