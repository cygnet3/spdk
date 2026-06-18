//! The sending component of silent payments.
//!
//! The [`generate_recipient_pubkeys`] function can be used to create outputs for a list of silent payment recipients.
//!
//! Using [`generate_recipient_pubkeys`] will require calculating a
//! `partial_secret` beforehand.
//! To do this, you can use [`calculate_partial_secret`](crate::utils::sending::calculate_partial_secret) from the `utils` module.
//! See the [tests on github](https://github.com/cygnet3/rust-silentpayments/blob/master/tests/vector_tests.rs)
//! for a concrete example.

use secp256k1::{PublicKey, Secp256k1, XOnlyPublicKey};
use std::collections::HashMap;

use crate::utils::common::calculate_t_n;
use crate::utils::common::SilentPaymentAddressRaw;
use crate::utils::common::TransactionSharedSecret;
use crate::utils::sending::calculate_ecdh_shared_secret;
use crate::utils::sending::PartialSecret;
use crate::Result;

/// Create outputs for a given set of silent payment recipients and their corresponding shared secrets.
///
/// When creating the outputs for a transaction, this function should be used to generate the output keys.
///
/// This function should only be used once per transaction! If used multiple times, address reuse may occur.
///
/// # Arguments
///
/// * `recipients` - A [Vec] of silent payment addresses to be paid.
/// * `partial_secret` - [PartialSecret] that represents the sum of the private keys of eligible inputs of the transaction multiplied by the input hash.
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
/// * Edge cases are hit during elliptic curve computation (extremely unlikely).
pub fn generate_recipient_pubkeys(
    recipients: Vec<SilentPaymentAddressRaw>,
    partial_secret: PartialSecret,
) -> Result<HashMap<SilentPaymentAddressRaw, Vec<XOnlyPublicKey>>> {
    let secp = Secp256k1::new();

    let mut silent_payment_groups: HashMap<
        PublicKey,
        (TransactionSharedSecret, Vec<SilentPaymentAddressRaw>),
    > = HashMap::new();
    for address in recipients {
        let recipient_scan_key = address.get_scan_pubkey();

        if let Some((_, payments)) = silent_payment_groups.get_mut(&recipient_scan_key) {
            payments.push(address);
        } else {
            let ecdh_shared_secret =
                calculate_ecdh_shared_secret(&recipient_scan_key, &partial_secret);

            silent_payment_groups.insert(recipient_scan_key, (ecdh_shared_secret, vec![address]));
        }
    }

    let mut result: HashMap<SilentPaymentAddressRaw, Vec<XOnlyPublicKey>> = HashMap::new();
    for group in silent_payment_groups.into_values() {
        let (ecdh_shared_secret, recipients) = group;

        for (n, addr) in recipients.into_iter().enumerate() {
            let t_n = calculate_t_n(&ecdh_shared_secret, n as u32)?;

            let res = t_n.public_key(&secp);
            let reskey = res.combine(&addr.get_m_pubkey())?;
            let (reskey_xonly, _) = reskey.x_only_public_key();

            let entry = result.entry(addr).or_default();
            entry.push(reskey_xonly);
        }
    }
    Ok(result)
}
