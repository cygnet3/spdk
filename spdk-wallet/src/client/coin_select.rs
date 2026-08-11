use anyhow::Result;
use bdk_coin_select::metrics::{Changeless, LowestFee};
use bdk_coin_select::{
    Candidate, ChangePolicy, CoinSelector, DrainWeights, FeeRate, TR_DUST_RELAY_MIN_VALUE,
    TR_KEYSPEND_TXIN_WEIGHT, TR_SPK_WEIGHT, TXOUT_BASE_WEIGHT,
    Target, TargetFee, TargetOutputs,
};
use bitcoin::script::PushBytesBuf;
use bitcoin::{Amount, OutPoint, ScriptBuf, TxOut};
use spdk_core::constants::DATA_CARRIER_SIZE;

use crate::client::{Recipient, RecipientAddress};

/// Upper bound on branch-and-bound iterations (see `bdk_coin_select` README).
const BNB_MAX_ROUNDS: usize = 10_000;

/// Maximum satisfaction weight for a native P2WPKH input (segwit, counted at 1 WU/byte).
///
/// Derived from `InputWeightPrediction::P2WPKH_MAX.weight().to_wu() - 4`:
/// `InputWeightPrediction` includes the 1-byte scriptSig length varint in its `script_size`
/// (4 WU), but `bdk_coin_select`'s `TXIN_BASE_WEIGHT` already covers that byte, so it must
/// be subtracted. Witness: varint(2 items=1) + varint(sig_len=1) + sig(72) + varint(pubkey_len=1)
/// + pubkey(33) = 108 WU.
pub const P2WPKH_SATISFACTION_WEIGHT: u64 = 1 + 1 + 72 + 1 + 33; // 108 WU

/// Maximum satisfaction weight for a compressed-key P2PKH input (non-segwit, at 4 WU/byte).
///
/// Derived from `InputWeightPrediction::P2PKH_COMPRESSED_MAX.weight().to_wu() - 4`.
/// scriptSig content: OP_DATA(1) + sig(72) + OP_DATA(1) + pubkey(33) = 107 bytes × 4 WU = 428 WU.
pub const P2PKH_SATISFACTION_WEIGHT: u64 = (1 + 72 + 1 + 33) * 4; // 428 WU

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strategy {
    Changeless,
    LowestFee,
    Greedy, // Fallback
    Drain,  // for the drain transaction case
}

#[derive(Debug, Clone)]
pub struct UtxoCandidate {
    pub outpoint: OutPoint,
    pub txout: TxOut,
    pub satisfaction_weight: u64,
    pub is_segwit: bool,
    pub is_ours: bool,
}

fn candidate_from_utxo(candidate: &UtxoCandidate) -> Candidate {
    Candidate::new(
        candidate.txout.value.to_sat(),
        candidate.satisfaction_weight,
        candidate.is_segwit,
    )
}

/// Builds a [`UtxoCandidate`] for an externally-provided mandatory input.
///
/// Only standard script types with a statically-known worst-case satisfaction weight are
/// accepted; everything else is rejected to prevent a malicious peer from understating the
/// weight of their input and corrupting fee estimation:
///
/// | Script type | Assumption            | Weight  |
/// |-------------|---------------------- |---------|
/// | P2TR        | key-path spend        | 66 WU   |
/// | P2WPKH      | single ECDSA sig      | 109 WU  |
/// | P2PKH       | single ECDSA sig      | 432 WU  |
pub fn candidate_from_external_utxo(outpoint: OutPoint, txout: TxOut) -> Result<UtxoCandidate> {
    let spk = &txout.script_pubkey;
    let (satisfaction_weight, is_segwit) = if spk.is_p2tr() {
        (TR_KEYSPEND_SATISFACTION_WEIGHT, true)
    } else if spk.is_p2wpkh() {
        (P2WPKH_SATISFACTION_WEIGHT, true)
    } else if spk.is_p2pkh() {
        (P2PKH_SATISFACTION_WEIGHT, false)
    } else {
        return Err(anyhow::Error::msg(format!(
            "external input {outpoint}: unsupported script type — \
             only P2TR (key-path), P2WPKH, and P2PKH are accepted"
        )));
    };
    Ok(UtxoCandidate {
        outpoint,
        txout,
        satisfaction_weight: Some(satisfaction_weight),
        is_segwit,
        is_ours: false,
    })
}

/// Returns the output weight in weight units for the given recipient.
///
/// For silent-payment recipients the actual script pubkey is not known yet (the key is derived in
/// [`finalize_transaction`]), but the output is always P2TR (OP_PUSHNUM_1 + 32-byte key = 34
/// bytes). We build a zero-byte placeholder script of that exact shape and call
/// [`TxOut::weight`] so the bitcoin library owns the arithmetic.
fn recipient_output_weight(recipient: &Recipient) -> u64 {
    let spk: ScriptBuf = match &recipient.address {
        // SP outputs are always P2TR; placeholder key is all-zeros.
        RecipientAddress::SpAddress(_) => ScriptBuf::from_bytes(
            [0x51u8, 0x20] // OP_PUSHNUM_1, OP_PUSHBYTES_32
                .into_iter()
                .chain([0u8; 32])
                .collect(),
        ),
        RecipientAddress::LegacyAddress(addr) => addr.assume_checked_ref().script_pubkey(),
        RecipientAddress::Data(data) => {
            let data_len = data.len().min(DATA_CARRIER_SIZE);
            let mut buf = PushBytesBuf::with_capacity(data_len);
            // DATA_CARRIER_SIZE (205) is well within the PushBytes limit (520).
            buf.extend_from_slice(&data[..data_len])
                .expect("DATA_CARRIER_SIZE is within PushBytes limits");
            ScriptBuf::new_op_return(buf)
        }
    };
    TxOut {
        value: Amount::ZERO,
        script_pubkey: spk,
    }
    .weight()
    .to_wu()
}

#[derive(Debug)]
pub struct InputSelection {
    pub selected_utxos: Vec<OutPoint>,
    pub sent: Amount,
    pub n_sent_outputs: usize,
    pub change: Amount,
    pub n_change_outputs: usize,
    pub fee: Amount,
    pub actual_fee_rate: FeeRate,
    pub strategy: Strategy,
}

pub fn select_all_utxos_for_fee_rate(
    available_utxos: Vec<UtxoCandidate>,
    recipients: &[Recipient],
    fee_rate: FeeRate,
) -> Result<InputSelection> {
    // as a silent payment wallet, we only spend taproot outputs
    let candidates: Vec<Candidate> = available_utxos.iter().map(candidate_from_utxo).collect();

    let mut coin_selector = CoinSelector::new(&candidates);

    let n_outputs = recipients.len();
    let output_weight: u64 = recipients.iter().map(recipient_output_weight).sum();

    let drain_output = DrainWeights {
        output_weight,
        spend_weight: 0,
        n_outputs,
    };

    let change_policy =
        ChangePolicy::min_value(drain_output, TR_DUST_RELAY_MIN_VALUE);

    let target = Target {
        fee: TargetFee::from_feerate(fee_rate),
        outputs: TargetOutputs {
            value_sum: 0,
            weight_sum: 0,
            n_outputs: 0,
        },
    };

    coin_selector.select_all();

    let change = coin_selector.drain(target, change_policy);

    if change.is_none() {
        return Err(anyhow::Error::msg("No funds available"));
    }

    let fee_value = coin_selector.fee(target.outputs.value_sum, change.value);
    if fee_value < 0 {
        return Err(anyhow::Error::msg("Not enough funds available")); // Maybe if we have very little funds and environment is high fees?
    }

    let actual_fee_rate = coin_selector
        .implied_feerate(target.outputs, change)
        .ok_or_else(|| anyhow::Error::msg("cannot compute effective feerate for selection"))?;

    Ok(InputSelection {
        selected_utxos: available_utxos
            .iter()
            .map(|candidate| candidate.outpoint)
            .collect(),
        sent: Amount::from_sat(change.value),
        n_sent_outputs: n_outputs,
        change: Amount::ZERO,
        n_change_outputs: 0,
        fee: Amount::from_sat(fee_value as u64),
        actual_fee_rate,
        strategy: Strategy::Drain,
    })
}

struct SelectionContext<'a> {
    available_utxos: &'a [UtxoCandidate],
    candidates: &'a [Candidate],
    target: Target,
    change_policy: ChangePolicy,
    fee_rate: FeeRate,
    n_change_outputs: usize,
}

fn finalize_selection(
    ctx: &SelectionContext<'_>,
    coin_selector: &CoinSelector<'_>,
    strategy: Strategy,
) -> Result<InputSelection> {
    let selected_utxos = coin_selector
        .selected_indices()
        .iter()
        .map(|i| ctx.available_utxos[*i].outpoint)
        .collect();

    let change = coin_selector.drain(ctx.target, ctx.change_policy);
    let change_value = if change.is_some() { change.value } else { 0 };
    let n_change_outputs = if change_value == 0 {
        0
    } else {
        ctx.n_change_outputs
    };

    let outputs_value = ctx.target.outputs.value_sum;

    let fee_value = coin_selector.fee(outputs_value, change_value);
    if fee_value < 0 {
        return Err(anyhow::Error::msg("Not enough funds available"));
    }

    let actual_fee_rate = coin_selector
        .implied_feerate(ctx.target.outputs, change)
        .ok_or_else(|| anyhow::Error::msg("cannot compute effective feerate for selection"))?;

    Ok(InputSelection {
        selected_utxos,
        sent: Amount::from_sat(outputs_value),
        n_sent_outputs: ctx.target.outputs.n_outputs,
        change: Amount::from_sat(change_value),
        n_change_outputs,
        fee: Amount::from_sat(fee_value as u64),
        actual_fee_rate,
        strategy,
    })
}

fn selector_with_mandatory_inputs<'a>(ctx: &SelectionContext<'a>) -> CoinSelector<'a> {
    let mut coin_selector = CoinSelector::new(ctx.candidates);
    for (index, candidate) in ctx.available_utxos.iter().enumerate() {
        if !candidate.is_ours {
            coin_selector.select(index);
        }
    }
    coin_selector
}

fn try_changeless_selection(ctx: &SelectionContext<'_>) -> Result<InputSelection> {
    let mut coin_selector = selector_with_mandatory_inputs(ctx);
    coin_selector.run_bnb(
        Changeless {
            target: ctx.target,
            change_policy: ctx.change_policy,
        },
        BNB_MAX_ROUNDS,
    )?;
    finalize_selection(ctx, &coin_selector, Strategy::Changeless)
}

fn try_lowest_fee_selection(ctx: &SelectionContext<'_>) -> Result<InputSelection> {
    let mut coin_selector = selector_with_mandatory_inputs(ctx);
    coin_selector.run_bnb(
        LowestFee {
            target: ctx.target,
            long_term_feerate: ctx.fee_rate,
            change_policy: ctx.change_policy,
        },
        BNB_MAX_ROUNDS,
    )?;
    finalize_selection(ctx, &coin_selector, Strategy::LowestFee)
}

fn try_greedy_selection(ctx: &SelectionContext<'_>) -> Result<InputSelection> {
    let mut coin_selector = selector_with_mandatory_inputs(ctx);
    coin_selector
        .select_until_target_met(ctx.target)
        .map_err(|e| anyhow::Error::msg(e.to_string()))?;
    finalize_selection(ctx, &coin_selector, Strategy::Greedy)
}

fn run_all_strategies(ctx: &SelectionContext<'_>) -> Vec<InputSelection> {
    let runners = [
        try_changeless_selection as fn(&SelectionContext<'_>) -> Result<InputSelection>,
        try_lowest_fee_selection,
        try_greedy_selection,
    ];

    runners.iter().filter_map(|run| run(ctx).ok()).collect()
}

/// Run each coin-selection strategy independently on a fresh [`CoinSelector`] clone.
///
/// Returns every strategy that found a valid selection (up to 3). Errors only when all
/// strategies fail.
pub fn pick_utxos_for_fee_rate(
    available_utxos: Vec<UtxoCandidate>,
    recipients: &[Recipient],
    n_change_outputs: usize,
    fee_rate: FeeRate,
) -> Result<Vec<InputSelection>> {
    // as a silent payment wallet, we only spend taproot outputs
    let candidates: Vec<Candidate> = available_utxos.iter().map(candidate_from_utxo).collect();

    // The dust floor scales with n_change_outputs: the change amount will be split across
    // that many outputs, so each part must stay above the dust threshold.
    let change_policy = ChangePolicy::min_value(
        DrainWeights {
            output_weight: (TXOUT_BASE_WEIGHT + TR_SPK_WEIGHT) * n_change_outputs as u64,
            spend_weight: TR_KEYSPEND_TXIN_WEIGHT * n_change_outputs as u64,
            n_outputs: n_change_outputs,
        },
        TR_DUST_RELAY_MIN_VALUE * 2 * n_change_outputs as u64,
    );

    let target = Target {
        fee: TargetFee::from_feerate(fee_rate),
        outputs: TargetOutputs::fund_outputs(
            recipients
                .iter()
                .map(|r| (recipient_output_weight(r), r.amount.to_sat())),
        ),
    };

    let ctx = SelectionContext {
        available_utxos: &available_utxos,
        candidates: &candidates,
        target,
        change_policy,
        fee_rate,
        n_change_outputs,
    };

    let selections = run_all_strategies(&ctx);
    if selections.is_empty() {
        return Err(anyhow::Error::msg("Not enough funds available"));
    }

    Ok(selections)
}

/// Splits `total` into `n` randomly-sized parts, each at least `min_part`,
/// summing exactly to `total`.
///
/// The split is uniform over all valid compositions (random cut points over
/// the amount exceeding the minimums), avoiding the equal-amount fingerprint
/// of a naive split.
///
/// The RNG is provided by the caller (same philosophy as `aux_rand` in
/// [`SpClient::sign_transaction`](crate::client::SpClient::sign_transaction)):
/// pass `&mut rand::rngs::ThreadRng` for production, a seeded RNG for tests.
///
/// Returns an error if `n == 0` or `total < n * min_part`.
pub fn random_split(
    total: Amount,
    n: usize,
    min_part: Amount,
    rng: &mut impl rand::Rng,
) -> Result<Vec<Amount>> {
    if n == 0 {
        return Err(anyhow::Error::msg("cannot split an amount into 0 outputs"));
    }
    let total_sat = total.to_sat();
    let min_sat = min_part.to_sat();
    let reserved = min_sat.saturating_mul(n as u64);
    if total_sat < reserved {
        return Err(anyhow::Error::msg(format!(
            "cannot split {} into {} outputs of at least {}",
            total, n, min_part
        )));
    }

    // n-1 uniform cut points over the freely distributable remainder.
    let remainder = total_sat - reserved;
    let mut cuts: Vec<u64> = (0..n - 1).map(|_| rng.gen_range(0..=remainder)).collect();
    cuts.sort_unstable();

    let mut parts = Vec::with_capacity(n);
    let mut prev = 0;
    for cut in cuts {
        parts.push(Amount::from_sat(min_sat + cut - prev));
        prev = cut;
    }
    parts.push(Amount::from_sat(min_sat + remainder - prev));
    Ok(parts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bdk_coin_select::{TR_DUST_RELAY_MIN_VALUE, TR_KEYSPEND_SATISFACTION_WEIGHT};
    use bitcoin::hashes::Hash;
    use bitcoin::key::{Keypair, TapTweak};
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use bitcoin::{Address, Network, ScriptBuf, Txid};

    fn test_fee_rate() -> FeeRate {
        fee_rate_sat_per_vb(1.0)
    }

    fn test_change_outputs() -> usize {
        1
    }

    fn fee_rate_sat_per_vb(sat_per_vb: f32) -> FeeRate {
        FeeRate::from_sat_per_vb(sat_per_vb)
    }

    fn p2tr_txout(value_sat: u64) -> TxOut {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x42; 32]).expect("valid test key");
        let keypair = Keypair::from_secret_key(&secp, &sk);
        let (xonly, _) = keypair.x_only_public_key();
        let tweaked = xonly.tap_tweak(&secp, None).0;
        TxOut {
            value: Amount::from_sat(value_sat),
            script_pubkey: ScriptBuf::new_p2tr_tweaked(tweaked),
        }
    }

    fn utxo(value_sat: u64, vout: u32) -> UtxoCandidate {
        UtxoCandidate {
            outpoint: OutPoint::new(Txid::all_zeros(), vout),
            txout: p2tr_txout(value_sat),
            satisfaction_weight: TR_KEYSPEND_SATISFACTION_WEIGHT,
            is_segwit: true,
            is_ours: true,
        }
    }

    fn external_utxo(value_sat: u64, vout: u32) -> UtxoCandidate {
        UtxoCandidate {
            is_ours: false,
            ..utxo(value_sat, vout)
        }
    }

    fn payment_recipient(value_sat: u64) -> Recipient {
        // Use a distinct key ([0x43; 32]) so payment outputs are never confused with UTXOs.
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x43; 32]).expect("valid test key");
        let keypair = Keypair::from_secret_key(&secp, &sk);
        let (xonly, _) = keypair.x_only_public_key();
        let tweaked = xonly.tap_tweak(&secp, None).0;
        let address = Address::p2tr_tweaked(tweaked, Network::Regtest);
        Recipient {
            address: RecipientAddress::LegacyAddress(address.as_unchecked().clone()),
            amount: Amount::from_sat(value_sat),
        }
    }

    fn many_utxos(count: usize, value_sat: u64) -> Vec<UtxoCandidate> {
        (0..count as u32)
            .map(|vout| utxo(value_sat, vout))
            .collect()
    }

    fn selected_input_sum(utxos: &[UtxoCandidate], selection: &InputSelection) -> u64 {
        selection
            .selected_utxos
            .iter()
            .map(|op| {
                utxos
                    .iter()
                    .find(|candidate| candidate.outpoint == *op)
                    .map(|candidate| candidate.txout.value.to_sat())
                    .expect("selected outpoint must exist in pool")
            })
            .sum()
    }

    fn assert_selection_balances(
        utxos: &[UtxoCandidate],
        selection: &InputSelection,
        payment_sat: u64,
    ) {
        let input_sum = selected_input_sum(utxos, selection);
        assert_eq!(selection.sent.to_sat(), payment_sat);
        assert_eq!(
            selection.change.to_sat() + selection.fee.to_sat() + selection.sent.to_sat(),
            input_sum,
        );
    }

    fn selection_by_strategy<'a>(
        selections: &'a [InputSelection],
        strategy: Strategy,
    ) -> &'a InputSelection {
        selections
            .iter()
            .find(|selection| selection.strategy == strategy)
            .unwrap_or_else(|| panic!("missing {:?} selection", strategy))
    }

    #[test]
    fn select_all_utxos_uses_every_input() {
        let utxos = vec![utxo(100_000, 0), utxo(200_000, 1)];
        let outpoints: Vec<_> = utxos.iter().map(|candidate| candidate.outpoint).collect();

        let selection =
            select_all_utxos_for_fee_rate(utxos, &[], test_fee_rate()).expect("selection");

        assert_eq!(selection.selected_utxos.len(), 2);
        for op in outpoints {
            assert!(selection.selected_utxos.contains(&op));
        }
        assert!(selection.fee > Amount::ZERO);
        // Drain: everything left after fees is sendable, there is no change.
        assert!(selection.sent > Amount::ZERO);
        assert_eq!(selection.change, Amount::ZERO);
        assert_eq!(selection.n_sent_outputs, 0);
        assert_eq!(selection.n_change_outputs, 0);
        assert_eq!(selection.sent + selection.fee, Amount::from_sat(300_000));
    }

    #[test]
    fn select_all_utxos_accounts_for_output_weight() {
        let utxos = vec![utxo(500_000, 0)];
        let recipient = payment_recipient(0);

        let without_outputs =
            select_all_utxos_for_fee_rate(utxos.clone(), &[], test_fee_rate()).expect("selection");
        let with_outputs =
            select_all_utxos_for_fee_rate(utxos, &[recipient], test_fee_rate()).expect("selection");

        assert_eq!(without_outputs.n_sent_outputs, 0);
        assert_eq!(with_outputs.n_sent_outputs, 1);
        assert!(with_outputs.fee >= without_outputs.fee);
        assert!(with_outputs.sent <= without_outputs.sent);
        assert_eq!(
            with_outputs.sent + with_outputs.fee,
            without_outputs.sent + without_outputs.fee,
        );
    }

    #[test]
    fn select_all_utxos_empty_inputs_fails() {
        let err = select_all_utxos_for_fee_rate(vec![], &[], test_fee_rate())
            .expect_err("expected error");
        assert_eq!(err.to_string(), "No funds available");
    }

    #[test]
    fn pick_utxos_prefers_single_input_when_sufficient() {
        let large = utxo(500_000, 0);
        let small = utxo(100_000, 1);
        let payment = payment_recipient(50_000);

        let selections = pick_utxos_for_fee_rate(
            vec![large.clone(), small],
            &[payment],
            test_change_outputs(),
            test_fee_rate(),
        )
        .expect("selection");
        let selection = selection_by_strategy(&selections, Strategy::LowestFee);

        assert_eq!(selection.selected_utxos, vec![large.outpoint]);
        assert!(selection.fee > Amount::ZERO);
    }

    #[test]
    fn pick_utxos_combines_inputs_when_one_is_not_enough() {
        let a = utxo(30_000, 0);
        let b = utxo(30_000, 1);
        let payment = payment_recipient(50_000);

        let selections = pick_utxos_for_fee_rate(
            vec![a.clone(), b.clone()],
            &[payment],
            test_change_outputs(),
            test_fee_rate(),
        )
        .expect("selection");
        let selection = selection_by_strategy(&selections, Strategy::LowestFee);

        assert_eq!(selection.selected_utxos.len(), 2);
        assert!(selection.selected_utxos.contains(&a.outpoint));
        assert!(selection.selected_utxos.contains(&b.outpoint));
        assert_eq!(
            selection.change + selection.fee + Amount::from_sat(50_000),
            Amount::from_sat(60_000),
        );
    }

    #[test]
    fn pick_utxos_always_includes_external_inputs() {
        let external = external_utxo(10_000, 0);
        let external_outpoint = external.outpoint;
        let owned = utxo(100_000, 1);
        let payment = payment_recipient(50_000);

        let selections = pick_utxos_for_fee_rate(
            vec![external, owned],
            &[payment],
            test_change_outputs(),
            test_fee_rate(),
        )
        .expect("selection");

        for selection in selections {
            assert!(selection.selected_utxos.contains(&external_outpoint));
        }
    }

    #[test]
    fn pick_utxos_emits_change_above_dust_threshold() {
        let utxos = vec![utxo(500_000, 0)];
        let payment = payment_recipient(50_000);

        let selections =
            pick_utxos_for_fee_rate(utxos, &[payment], test_change_outputs(), test_fee_rate())
                .expect("selection");
        let selection = selection_by_strategy(&selections, Strategy::LowestFee);

        let min_change = TR_DUST_RELAY_MIN_VALUE * 2;
        assert!(
            selection.change == Amount::ZERO || selection.change >= Amount::from_sat(min_change),
            "change {} below dust policy minimum {}",
            selection.change,
            min_change,
        );
        assert_eq!(
            selection.change + selection.fee + Amount::from_sat(50_000),
            Amount::from_sat(500_000),
        );
    }

    /// At 1 sat/vB a single input can fund the payment with no change; at 5 sat/vB the same
    /// input is insufficient, a second input is required, and the excess must become change.
    #[test]
    fn pick_utxos_fee_rate_affects_changeless_vs_change() {
        let low = fee_rate_sat_per_vb(1.0);
        let high = fee_rate_sat_per_vb(5.0);
        let min_change = TR_DUST_RELAY_MIN_VALUE * 2;
        // Sized so 25_250 sats covers payment + fee at 1 sat/vB with no change; at 5 sat/vB
        // that input alone is insufficient and the 2_500 sat top-up is required, which leaves
        // excess above the dust policy (unavoidable change).
        let payment_sat = 25_000;
        let primary_sat = 25_250;
        let second_sat = 2_500;

        let payment = payment_recipient(payment_sat);
        let pool = vec![utxo(primary_sat, 0), utxo(second_sat, 1)];

        let low_sels =
            pick_utxos_for_fee_rate(pool.clone(), &[payment.clone()], test_change_outputs(), low)
                .expect("low fee");
        let low_sel = selection_by_strategy(&low_sels, Strategy::Changeless);
        assert_eq!(low_sel.change, Amount::ZERO);
        assert_eq!(low_sel.selected_utxos, vec![utxo(primary_sat, 0).outpoint]);
        assert_selection_balances(&pool, &low_sel, payment_sat);

        assert!(
            pick_utxos_for_fee_rate(
                vec![utxo(primary_sat, 0)],
                &[payment.clone()],
                test_change_outputs(),
                high,
            )
            .is_err(),
            "primary input alone must not fund the payment at 5 sat/vB",
        );

        let high_sels =
            pick_utxos_for_fee_rate(pool.clone(), &[payment], test_change_outputs(), high)
                .expect("high fee");
        let high_sel = selection_by_strategy(&high_sels, Strategy::LowestFee);
        assert_eq!(high_sel.selected_utxos.len(), 2);
        assert!(
            high_sel
                .selected_utxos
                .contains(&utxo(primary_sat, 0).outpoint)
        );
        assert!(
            high_sel
                .selected_utxos
                .contains(&utxo(second_sat, 1).outpoint)
        );
        assert!(high_sel.change >= Amount::from_sat(min_change));
        assert_selection_balances(&pool, &high_sel, payment_sat);
    }

    #[test]
    fn pick_utxos_uses_changeless_when_exact_input_exists() {
        let payment_sat = 50_000;
        let fee_rate = test_fee_rate();
        let exact_sat = (payment_sat..payment_sat + 5_000)
            .find(|&value_sat| {
                pick_utxos_for_fee_rate(
                    vec![utxo(value_sat, 0), utxo(1_000_000, 1)],
                    &[payment_recipient(payment_sat)],
                    test_change_outputs(),
                    fee_rate,
                )
                .ok()
                .is_some_and(|selections| {
                    selections.iter().any(|selection| {
                        selection.strategy == Strategy::Changeless
                            && selection.change == Amount::ZERO
                            && selection.selected_utxos == vec![utxo(value_sat, 0).outpoint]
                    })
                })
            })
            .expect("a changeless single-input fixture must exist");

        let selections = pick_utxos_for_fee_rate(
            vec![utxo(exact_sat, 0), utxo(1_000_000, 1)],
            &[payment_recipient(payment_sat)],
            test_change_outputs(),
            fee_rate,
        )
        .expect("selection");
        let selection = selection_by_strategy(&selections, Strategy::Changeless);

        assert_eq!(selection.change, Amount::ZERO);
        assert_eq!(selection.selected_utxos, vec![utxo(exact_sat, 0).outpoint]);
    }

    #[test]
    fn pick_utxos_insufficient_funds() {
        let utxos = vec![utxo(1_000, 0)];
        let payment = payment_recipient(1_000_000);

        assert!(
            pick_utxos_for_fee_rate(utxos, &[payment], test_change_outputs(), test_fee_rate())
                .is_err()
        );
    }

    #[test]
    fn pick_utxos_many_utxos_one_large_covers_payment() {
        let mut utxos = many_utxos(250, 10_000);
        let whale = utxo(10_000_000, 250);
        utxos.push(whale.clone());
        let payment = payment_recipient(100_000);

        let selections = pick_utxos_for_fee_rate(
            utxos.clone(),
            &[payment],
            test_change_outputs(),
            test_fee_rate(),
        )
        .expect("selection");
        let selection = selection_by_strategy(&selections, Strategy::LowestFee);

        assert_eq!(selection.selected_utxos, vec![whale.outpoint]);
        assert!(selection.selected_utxos.len() < utxos.len());
        assert_selection_balances(&utxos, &selection, 100_000);
    }

    #[test]
    fn pick_utxos_many_utxos_combines_small_inputs() {
        let utxos = many_utxos(200, 10_000);
        let payment = payment_recipient(150_000);

        let selections = pick_utxos_for_fee_rate(
            utxos.clone(),
            &[payment],
            test_change_outputs(),
            test_fee_rate(),
        )
        .expect("selection");
        let selection = selection_by_strategy(&selections, Strategy::LowestFee);

        assert!(!selection.selected_utxos.is_empty());
        assert!(selection.selected_utxos.len() <= utxos.len());
        assert_selection_balances(&utxos, &selection, 150_000);
        let min_change = TR_DUST_RELAY_MIN_VALUE * 2;
        assert!(
            selection.change == Amount::ZERO || selection.change >= Amount::from_sat(min_change),
        );
    }

    #[test]
    fn pick_utxos_many_utxos_does_not_use_entire_pool() {
        let utxos = many_utxos(300, 50_000);
        let payment = payment_recipient(25_000);

        let selections = pick_utxos_for_fee_rate(
            utxos.clone(),
            &[payment],
            test_change_outputs(),
            test_fee_rate(),
        )
        .expect("selection");
        let selection = selection_by_strategy(&selections, Strategy::LowestFee);

        assert!(selection.selected_utxos.len() < utxos.len());
        assert_selection_balances(&utxos, &selection, 25_000);
    }

    #[test]
    fn pick_utxos_many_utxos_insufficient_funds() {
        let utxos = many_utxos(200, 1_000);
        let payment = payment_recipient(500_000);

        assert!(
            pick_utxos_for_fee_rate(utxos, &[payment], test_change_outputs(), test_fee_rate())
                .is_err()
        );
    }

    #[test]
    fn pick_utxos_more_change_outputs_never_reduces_fee() {
        let payment_sat = 50_000;
        let utxos = vec![utxo(500_000, 0)];
        let payment = payment_recipient(payment_sat);

        let one_change_sels =
            pick_utxos_for_fee_rate(utxos.clone(), &[payment.clone()], 1, test_fee_rate())
                .expect("selection with one change output");
        let two_change_sels =
            pick_utxos_for_fee_rate(utxos.clone(), &[payment], 2, test_fee_rate())
                .expect("selection with two change outputs");
        let one_change = selection_by_strategy(&one_change_sels, Strategy::LowestFee);
        let two_change = selection_by_strategy(&two_change_sels, Strategy::LowestFee);

        assert_eq!(one_change.selected_utxos, two_change.selected_utxos);
        assert!(two_change.fee >= one_change.fee);
        assert!(two_change.change <= one_change.change);
        assert_selection_balances(&utxos, &one_change, payment_sat);
        assert_selection_balances(&utxos, &two_change, payment_sat);
    }

    #[test]
    fn pick_utxos_two_change_outputs_needs_at_least_as_much_input_value() {
        let payment_sat = 50_000;
        let fee_rate = test_fee_rate();
        let payment = payment_recipient(payment_sat);
        let min_for_one_change = (payment_sat..payment_sat + 50_000)
            .find(|&value_sat| {
                pick_utxos_for_fee_rate(vec![utxo(value_sat, 0)], &[payment.clone()], 1, fee_rate)
                    .is_ok()
            })
            .expect("fixture where one change output is affordable");
        let min_for_two_change = (payment_sat..payment_sat + 50_000)
            .find(|&value_sat| {
                pick_utxos_for_fee_rate(vec![utxo(value_sat, 0)], &[payment.clone()], 2, fee_rate)
                    .is_ok()
            })
            .expect("fixture where two change outputs are affordable");

        let one_change_sels = pick_utxos_for_fee_rate(
            vec![utxo(min_for_one_change, 0)],
            &[payment.clone()],
            1,
            fee_rate,
        )
        .expect("one change output should succeed");
        let one_change = selection_by_strategy(&one_change_sels, Strategy::LowestFee);
        assert_selection_balances(&vec![utxo(min_for_one_change, 0)], one_change, payment_sat);

        let two_change_sels =
            pick_utxos_for_fee_rate(vec![utxo(min_for_two_change, 0)], &[payment], 2, fee_rate)
                .expect("two change outputs should succeed");
        let two_change = selection_by_strategy(&two_change_sels, Strategy::LowestFee);
        assert_selection_balances(&vec![utxo(min_for_two_change, 0)], two_change, payment_sat);
        assert!(min_for_two_change >= min_for_one_change);
    }

    #[test]
    fn pick_utxos_returns_one_selection_per_successful_strategy() {
        let utxos = vec![utxo(500_000, 0), utxo(100_000, 1)];
        let payment = payment_recipient(50_000);

        let selections = pick_utxos_for_fee_rate(
            utxos.clone(),
            &[payment],
            test_change_outputs(),
            test_fee_rate(),
        )
        .expect("selection");

        assert!(selections.len() >= 2);
        assert!(
            selections
                .iter()
                .any(|selection| selection.strategy == Strategy::LowestFee)
        );
        assert!(
            selections
                .iter()
                .any(|selection| selection.strategy == Strategy::Greedy)
        );

        for selection in &selections {
            assert_selection_balances(&utxos, selection, 50_000);
        }
    }

    #[test]
    fn random_split_parts_sum_to_total_and_respect_minimum() {
        use rand::SeedableRng;
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        let total = Amount::from_sat(100_000);
        let min = Amount::from_sat(TR_DUST_RELAY_MIN_VALUE * 2);

        for n in 1..=5 {
            let parts = random_split(total, n, min, &mut rng).expect("split");
            assert_eq!(parts.len(), n);
            assert_eq!(parts.iter().copied().sum::<Amount>(), total);
            assert!(parts.iter().all(|&part| part >= min));
        }
    }

    #[test]
    fn random_split_rejects_impossible_splits() {
        use rand::SeedableRng;
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        let min = Amount::from_sat(TR_DUST_RELAY_MIN_VALUE * 2);

        assert!(random_split(Amount::from_sat(1_000), 0, min, &mut rng).is_err());
        // 5 * min > total
        assert!(random_split(Amount::from_sat(1_000), 5, min, &mut rng).is_err());
    }

    #[test]
    fn random_split_with_exact_minimum_returns_all_minimums() {
        use rand::SeedableRng;
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        let min = Amount::from_sat(TR_DUST_RELAY_MIN_VALUE * 2);

        let parts =
            random_split(Amount::from_sat(min.to_sat() * 4), 4, min, &mut rng).expect("split");
        assert!(parts.iter().all(|&part| part == min));
    }

    #[test]
    fn random_split_produces_uneven_parts() {
        use rand::SeedableRng;
        // Fixed seed: deterministic, but must not be the naive equal split.
        let mut rng = rand::rngs::StdRng::seed_from_u64(7);

        let parts = random_split(Amount::from_sat(100_000), 4, Amount::from_sat(1), &mut rng)
            .expect("split");
        assert!(parts.iter().any(|&part| part != parts[0]));
    }

    #[test]
    fn select_all_utxos_many_inputs() {
        let utxos: Vec<_> = (0..400).map(|vout| utxo(25_000, vout)).collect();
        let outpoints: Vec<_> = utxos.iter().map(|candidate| candidate.outpoint).collect();

        let selection =
            select_all_utxos_for_fee_rate(utxos, &[], test_fee_rate()).expect("selection");

        assert_eq!(selection.selected_utxos.len(), 400);
        for op in outpoints {
            assert!(selection.selected_utxos.contains(&op));
        }
        assert_eq!(selection.change, Amount::ZERO);
        assert_eq!(
            selection.sent + selection.fee,
            Amount::from_sat(400 * 25_000),
        );
    }
}
