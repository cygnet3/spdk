//! Silent Payment ECDH Share Aggregation
//!
//! Provides functions for aggregating ECDH shares across PSBT inputs according to BIP-375.
//!
//! # Global vs Per-Input Shares
//!
//! BIP-375 supports two modes of ECDH share distribution:
//!
//! - **Global Shares**: All inputs have the same ECDH share point for a given scan key.
//!   These are stored in PSBT_GLOBAL_SP_ECDH_SHARE (0x07) and should NOT be summed.
//!   Used when one party knows all input private keys.
//!
//! - **Per-Input Shares**: Each input has a unique ECDH share computed from its private key.
//!   These are stored in PSBT_IN_SP_ECDH_SHARE (0x1d) and MUST be summed.
//!   Used in multi-party signing scenarios.
//!
//! This module automatically detects which mode is being used and aggregates accordingly.

use super::{Bip375PsbtExt, Error, Result, SilentPaymentPsbt};
use secp256k1::PublicKey;
use std::collections::HashMap;

/// Result of ECDH share aggregation for a single scan key
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggregatedShare {
    /// The scan key this aggregation is for
    pub scan_key: PublicKey,
    /// The aggregated ECDH share (single point)
    pub aggregated_share: PublicKey,
    /// Whether this was a global share (true) or per-input shares (false)
    pub is_global: bool,
    /// Number of inputs that contributed shares
    pub num_inputs: usize,
}

/// Collection of aggregated ECDH shares for all scan keys in a PSBT
#[derive(Debug, Clone)]
pub struct AggregatedShares {
    /// Map of scan_key -> aggregated result
    shares: HashMap<PublicKey, AggregatedShare>,
}

impl AggregatedShares {
    /// Get the aggregated share for a specific scan key
    pub fn get(&self, scan_key: &PublicKey) -> Option<&AggregatedShare> {
        self.shares.get(scan_key)
    }

    /// Get the aggregated share point for a specific scan key
    pub fn get_share_point(&self, scan_key: &PublicKey) -> Option<PublicKey> {
        self.shares.get(scan_key).map(|s| s.aggregated_share)
    }

    /// Get all scan keys that have aggregated shares
    pub fn scan_keys(&self) -> Vec<PublicKey> {
        self.shares.keys().copied().collect()
    }

    /// Check if shares exist for a given scan key
    pub fn has_scan_key(&self, scan_key: &PublicKey) -> bool {
        self.shares.contains_key(scan_key)
    }

    /// Get the number of scan keys with aggregated shares
    pub fn len(&self) -> usize {
        self.shares.len()
    }

    /// Check if there are no aggregated shares
    pub fn is_empty(&self) -> bool {
        self.shares.is_empty()
    }

    /// Iterate over all aggregated shares
    pub fn iter(&self) -> impl Iterator<Item = (&PublicKey, &AggregatedShare)> {
        self.shares.iter()
    }
}

/// Aggregate ECDH shares from all inputs in a PSBT
///
/// This function:
/// 1. Collects all ECDH shares from all inputs, grouped by scan key
/// 2. Detects whether shares are global (all identical) or per-input (unique)
/// 3. For global shares: returns the share without summing
/// 4. For per-input shares: sums all shares using elliptic curve addition
///
/// # Arguments
/// * `psbt` - The PSBT containing ECDH shares
///
/// # Returns
/// * `AggregatedShares` - Collection of aggregated shares for all scan keys
///
/// # Errors
/// * If no inputs exist in the PSBT
/// * If elliptic curve operations fail during aggregation
///
/// # Example
/// ```rust,ignore
/// let aggregated = aggregate_ecdh_shares(&psbt)?;
/// let share = aggregated.get_share_point(&scan_key)
///     .ok_or_else(|| Error::Other("Missing share".to_string()))?;
/// ```
pub fn aggregate_ecdh_shares(psbt: &SilentPaymentPsbt) -> Result<AggregatedShares> {
    let num_inputs = psbt.num_inputs();
    if num_inputs == 0 {
        return Err(Error::Other(
            "Cannot aggregate ECDH shares: no inputs".to_string(),
        ));
    }

    let mut result_shares = HashMap::new();

    // Step 0: Collect explicit Global Shares
    // These are stored in PSBT_GLOBAL_SP_ECDH_SHARE (0x07) and take precedence
    let global_shares = psbt.get_global_ecdh_shares();
    for share in global_shares {
        result_shares.insert(
            share.scan_key,
            AggregatedShare {
                scan_key: share.scan_key,
                aggregated_share: share.share,
                is_global: true,
                num_inputs, // Global share implicitly covers all inputs
            },
        );
    }

    // Step 1: Collect input shares grouped by scan key
    let mut shares_by_scan_key: HashMap<PublicKey, Vec<PublicKey>> = HashMap::new();

    for input_idx in 0..num_inputs {
        let shares = psbt.get_input_ecdh_shares(input_idx);
        for share in shares {
            shares_by_scan_key
                .entry(share.scan_key)
                .or_default()
                .push(share.share);
        }
    }

    // Step 2: Detect implicit global vs per-input shares and aggregate
    for (scan_key, shares) in shares_by_scan_key {
        // If we already have an explicit global share for this key, skip input aggregation
        if result_shares.contains_key(&scan_key) {
            continue;
        }

        if shares.is_empty() {
            continue; // Should never happen
        }

        // Detect implicit global shares: all inputs have the exact same share point
        // AND there are shares from all inputs
        let first_share = shares[0];
        let is_global = shares.len() == num_inputs && shares.iter().all(|s| *s == first_share);

        let aggregated_share = if is_global {
            // Global share: use it directly without summing
            first_share
        } else {
            // Per-input shares: sum them using elliptic curve addition
            aggregate_public_keys(&shares)?
        };

        result_shares.insert(
            scan_key,
            AggregatedShare {
                scan_key,
                aggregated_share,
                is_global,
                num_inputs: shares.len(),
            },
        );
    }

    Ok(AggregatedShares {
        shares: result_shares,
    })
}

/// Sum multiple public keys using elliptic curve addition
///
/// This is used to aggregate per-input ECDH shares. Each share is a point on the curve,
/// and we sum them to get the total ECDH secret.
///
/// # Arguments
/// * `pubkeys` - Slice of public keys to sum
///
/// # Returns
/// * The sum of all public keys (P1 + P2 + ... + Pn)
///
/// # Errors
/// * If the input slice is empty
/// * If elliptic curve addition fails (e.g., adding a point to its negation)
fn aggregate_public_keys(pubkeys: &[PublicKey]) -> Result<PublicKey> {
    if pubkeys.is_empty() {
        return Err(Error::Other(
            "Cannot aggregate zero public keys".to_string(),
        ));
    }

    let mut result = pubkeys[0];
    for pubkey in &pubkeys[1..] {
        result = result
            .combine(pubkey)
            .map_err(|e| Error::Other(format!("Failed to aggregate ECDH shares: {}", e)))?;
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    // use super::*;
    // Tests will be added during implementation
}
