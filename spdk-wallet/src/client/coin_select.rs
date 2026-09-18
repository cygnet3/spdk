use std::collections::HashSet;

use anyhow::{Error, Result};
use bdk_coin_select::float::Ordf32;
use bdk_coin_select::metrics::{Changeless, LowestFee};
use bdk_coin_select::{
    BnbMetric, Candidate, ChangePolicy, CoinSelector, Drain, DrainWeights, FeeRate,
    TR_DUST_RELAY_MIN_VALUE, Target, TargetFee, TargetOutputs,
};
use bitcoin::script::PushBytesBuf;
use bitcoin::{Amount, OutPoint, ScriptBuf, TxOut};
use spdk_core::constants::DATA_CARRIER_SIZE;

use crate::client::{Recipient, RecipientAddress};

/// Upper bound on branch-and-bound iterations (see `bdk_coin_select` README).
const BNB_MAX_ROUNDS: usize = 100_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strategy {
    Changeless,
    LowestFee,
    FeeRateCap, // Only accepts selections whose implied fee rate stays within the bound, then minimize fees
    Greedy,     // Fallback
}

fn candidate_from_txout(txout: &TxOut) -> Result<Candidate> {
    if !txout.script_pubkey.is_p2tr() {
        return Err(anyhow::Error::msg(
            "unsupported input script for coin selection",
        ));
    }
    // Keyspend only. Script-path satisfaction is not visible on the TxOut.
    Ok(Candidate::new_tr_keyspend(txout.value.to_sat()))
}

fn pool_from_utxos(utxos: &[(OutPoint, TxOut)]) -> Result<(Vec<OutPoint>, Vec<Candidate>)> {
    let mut seen: HashSet<OutPoint> = HashSet::with_capacity(utxos.len());
    let mut outpoints = Vec::with_capacity(utxos.len());
    let mut candidates = Vec::with_capacity(utxos.len());
    for (outpoint, txout) in utxos {
        if !seen.insert(*outpoint) {
            return Err(Error::msg(format!("duplicate outpoint: {outpoint}")));
        }
        outpoints.push(*outpoint);
        candidates
            .push(candidate_from_txout(txout).map_err(|e| Error::msg(format!("{e}: {outpoint}")))?);
    }
    Ok((outpoints, candidates))
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
        RecipientAddress::SpCode(_) => ScriptBuf::from_bytes(
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
    selected_utxos: Vec<OutPoint>,
    sent: Amount,
    n_sent_outputs: usize,
    change: Amount,
    fee: Amount,
    actual_fee_rate: FeeRate,
    strategy: Strategy,
}

impl InputSelection {
    pub fn selected_utxos(&self) -> &[OutPoint] {
        &self.selected_utxos
    }

    pub fn sent(&self) -> Amount {
        self.sent
    }

    pub fn n_sent_outputs(&self) -> usize {
        self.n_sent_outputs
    }

    pub fn change(&self) -> Amount {
        self.change
    }

    pub fn fee(&self) -> Amount {
        self.fee
    }

    pub fn actual_fee_rate(&self) -> FeeRate {
        self.actual_fee_rate
    }

    pub fn strategy(&self) -> Strategy {
        self.strategy
    }
}

/// Coin selection for a drain (spend-all) transaction.
///
/// `sent` is the amount remaining after fees, paid to the drain address. There is no change.
#[derive(Debug)]
pub struct DrainSelection {
    selected_utxos: Vec<OutPoint>,
    sent: Amount,
    n_sent_outputs: usize,
    fee: Amount,
    actual_fee_rate: FeeRate,
}

impl DrainSelection {
    pub fn selected_utxos(&self) -> &[OutPoint] {
        &self.selected_utxos
    }

    pub fn sent(&self) -> Amount {
        self.sent
    }

    pub fn n_sent_outputs(&self) -> usize {
        self.n_sent_outputs
    }

    pub fn fee(&self) -> Amount {
        self.fee
    }

    pub fn actual_fee_rate(&self) -> FeeRate {
        self.actual_fee_rate
    }
}

pub fn select_all_utxos_for_fee_rate(
    available_utxos: &[(OutPoint, TxOut)],
    recipients: &[Recipient],
    fee_rate: FeeRate,
) -> Result<DrainSelection> {
    let (outpoints, candidates) = pool_from_utxos(available_utxos)?;

    let mut coin_selector = CoinSelector::new(&candidates);

    let n_outputs = recipients.len();
    let output_weight: u64 = recipients.iter().map(recipient_output_weight).sum();

    let drain_output = DrainWeights {
        output_weight,
        spend_weight: 0,
        n_outputs,
    };

    let change_policy = ChangePolicy::min_value(drain_output, TR_DUST_RELAY_MIN_VALUE);

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

    Ok(DrainSelection {
        selected_utxos: outpoints,
        sent: Amount::from_sat(change.value),
        n_sent_outputs: n_outputs,
        fee: Amount::from_sat(fee_value as u64),
        actual_fee_rate,
    })
}

struct SelectionContext<'a> {
    outpoints: &'a [OutPoint],
    candidates: &'a [Candidate],
    target: Target,
    change_policy: ChangePolicy,
    fee_rate: FeeRate,
    bnb_max_rounds: usize,
}

fn finalize_selection(
    ctx: &SelectionContext<'_>,
    coin_selector: &CoinSelector<'_>,
    strategy: Strategy,
) -> Result<InputSelection> {
    let selected_utxos = coin_selector
        .selected_indices()
        .iter()
        .map(|i| ctx.outpoints[*i])
        .collect();

    let change = coin_selector.drain(ctx.target, ctx.change_policy);
    let change_value = if change.is_some() { change.value } else { 0 };

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
        fee: Amount::from_sat(fee_value as u64),
        actual_fee_rate,
        strategy,
    })
}

fn try_changeless_selection(
    ctx: &SelectionContext<'_>,
    mut coin_selector: CoinSelector<'_>,
) -> Result<InputSelection> {
    coin_selector.run_bnb(
        Changeless {
            target: ctx.target,
            change_policy: ctx.change_policy,
        },
        ctx.bnb_max_rounds,
    )?;
    finalize_selection(ctx, &coin_selector, Strategy::Changeless)
}

fn try_lowest_fee_selection(
    ctx: &SelectionContext<'_>,
    mut coin_selector: CoinSelector<'_>,
) -> Result<InputSelection> {
    coin_selector.run_bnb(
        LowestFee {
            target: ctx.target,
            long_term_feerate: ctx.fee_rate,
            change_policy: ctx.change_policy,
        },
        ctx.bnb_max_rounds,
    )?;
    finalize_selection(ctx, &coin_selector, Strategy::LowestFee)
}

/// 1.0 = implied feerate must match the request (modulo vbyte rounding).
const FEE_RATE_CAP_MAX_OVERSHOOT: f32 = 1.0;

/// Only accepts selections whose implied fee rate stays within the bound;
/// among those, minimizes fee (fewest/cheapest inputs).
struct FeeRateCapMetric {
    target: Target,
    change_policy: ChangePolicy,
    max_overshoot: f32,
}

impl FeeRateCapMetric {
    fn drain_for(cs: &CoinSelector<'_>, target: Target, change_policy: ChangePolicy) -> Drain {
        match cs.drain_value(target, change_policy) {
            Some(value) => Drain {
                weights: change_policy.drain_weights,
                value,
            },
            None => Drain::NONE,
        }
    }

    fn fee_within_cap(&self, cs: &CoinSelector<'_>) -> Option<i64> {
        if !cs.is_target_met(self.target) {
            return None;
        }
        let drain = Self::drain_for(cs, self.target, self.change_policy);
        let fee = cs.fee(self.target.outputs.value_sum, drain.value);
        if fee < 0 {
            return None;
        }
        // Change (or zero leftover) makes fee equal implied_fee. Leftover dumped
        // to miners raises fee above that; max_overshoot 1.0 rejects it.
        // Compare fees, not float feerates: vbyte rounding already lives in
        // implied_fee, so 1.0 stays exact modulo that ceil.
        let max_fee =
            (cs.implied_fee(self.target, drain.weights) as f32 * self.max_overshoot).ceil() as i64;
        if fee > max_fee {
            return None;
        }
        Some(fee)
    }
}

impl BnbMetric for FeeRateCapMetric {
    fn score(&mut self, cs: &CoinSelector<'_>) -> Option<Ordf32> {
        self.fee_within_cap(cs).map(|fee| Ordf32(fee as f32))
    }

    fn bound(&mut self, cs: &CoinSelector<'_>) -> Option<Ordf32> {
        if !cs.is_selection_possible(self.target) {
            return None;
        }
        match self.score(cs) {
            // Already in cap; adding inputs only raises fee.
            Some(score) => Some(score),
            None => Some(Ordf32(0.0)),
        }
    }

    fn requires_ordering_by_descending_value_pwu(&self) -> bool {
        true
    }
}

fn try_fee_rate_cap_selection(
    ctx: &SelectionContext<'_>,
    mut coin_selector: CoinSelector<'_>,
) -> Result<InputSelection> {
    for (index, candidate) in ctx.candidates.iter().enumerate() {
        if candidate.effective_value(ctx.fee_rate) <= 0.0 {
            coin_selector.ban(index);
        }
    }
    coin_selector.run_bnb(
        FeeRateCapMetric {
            target: ctx.target,
            change_policy: ctx.change_policy,
            max_overshoot: FEE_RATE_CAP_MAX_OVERSHOOT,
        },
        ctx.bnb_max_rounds,
    )?;
    finalize_selection(ctx, &coin_selector, Strategy::FeeRateCap)
}

fn try_greedy_selection(
    ctx: &SelectionContext<'_>,
    mut coin_selector: CoinSelector<'_>,
) -> Result<InputSelection> {
    coin_selector
        .select_until_target_met(ctx.target)
        .map_err(|e| anyhow::Error::msg(e.to_string()))?;
    finalize_selection(ctx, &coin_selector, Strategy::Greedy)
}

fn run_all_strategies(ctx: &SelectionContext<'_>) -> Vec<InputSelection> {
    let base_selector = CoinSelector::new(ctx.candidates);

    let mut selections = Vec::new();
    if let Ok(selection) = try_changeless_selection(ctx, base_selector.clone()) {
        selections.push(selection);
    }
    if let Ok(selection) = try_lowest_fee_selection(ctx, base_selector.clone()) {
        selections.push(selection);
    }
    if let Ok(selection) = try_fee_rate_cap_selection(ctx, base_selector.clone()) {
        selections.push(selection);
    }

    if selections.is_empty() {
        if let Ok(selection) = try_greedy_selection(ctx, base_selector) {
            selections.push(selection);
        }
    }

    selections
}

/// Run Changeless, LowestFee, and FeeRateCap independently on a fresh [`CoinSelector`] clone.
///
/// Returns every BnB strategy that found a valid selection. If none of them succeed,
/// falls back to Greedy. Errors only when that fallback also fails.
pub fn pick_utxos_for_fee_rate(
    available_utxos: &[(OutPoint, TxOut)],
    recipients: &[Recipient],
    fee_rate: FeeRate,
) -> Result<Vec<InputSelection>> {
    pick_utxos(available_utxos, recipients, fee_rate, BNB_MAX_ROUNDS)
}

fn pick_utxos(
    available_utxos: &[(OutPoint, TxOut)],
    recipients: &[Recipient],
    fee_rate: FeeRate,
    bnb_max_rounds: usize,
) -> Result<Vec<InputSelection>> {
    let (outpoints, candidates) = pool_from_utxos(available_utxos)?;

    let change_policy =
        ChangePolicy::min_value(DrainWeights::TR_KEYSPEND, TR_DUST_RELAY_MIN_VALUE * 2);

    let target = Target {
        fee: TargetFee::from_feerate(fee_rate),
        outputs: TargetOutputs::fund_outputs(
            recipients
                .iter()
                .map(|r| (recipient_output_weight(r), r.amount.to_sat())),
        ),
    };

    let ctx = SelectionContext {
        outpoints: &outpoints,
        candidates: &candidates,
        target,
        change_policy,
        fee_rate,
        bnb_max_rounds,
    };

    let selections = run_all_strategies(&ctx);
    if selections.is_empty() {
        return Err(anyhow::Error::msg("Not enough funds available"));
    }

    Ok(selections)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bdk_coin_select::TR_DUST_RELAY_MIN_VALUE;
    use bitcoin::hashes::Hash;
    use bitcoin::key::{Keypair, TapTweak};
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use bitcoin::{Address, Network, ScriptBuf, Txid};

    fn test_fee_rate() -> FeeRate {
        fee_rate_sat_per_vb(1.0)
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

    fn utxo(value_sat: u64, vout: u32) -> (OutPoint, TxOut) {
        (
            OutPoint::new(Txid::all_zeros(), vout),
            p2tr_txout(value_sat),
        )
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

    fn many_utxos(count: usize, value_sat: u64) -> Vec<(OutPoint, TxOut)> {
        (0..count as u32)
            .map(|vout| utxo(value_sat, vout))
            .collect()
    }

    fn selected_input_sum(utxos: &[(OutPoint, TxOut)], selection: &InputSelection) -> u64 {
        selection
            .selected_utxos()
            .iter()
            .map(|op| {
                utxos
                    .iter()
                    .find(|(outpoint, _)| outpoint == op)
                    .map(|(_, txout)| txout.value.to_sat())
                    .expect("selected outpoint must exist in pool")
            })
            .sum()
    }

    fn assert_selection_balances(
        utxos: &[(OutPoint, TxOut)],
        selection: &InputSelection,
        payment_sat: u64,
    ) {
        let input_sum = selected_input_sum(utxos, selection);
        assert_eq!(selection.sent().to_sat(), payment_sat);
        assert_eq!(
            selection.change().to_sat() + selection.fee().to_sat() + selection.sent().to_sat(),
            input_sum,
        );
    }

    fn selection_by_strategy<'a>(
        selections: &'a [InputSelection],
        strategy: Strategy,
    ) -> &'a InputSelection {
        selections
            .iter()
            .find(|selection| selection.strategy() == strategy)
            .unwrap_or_else(|| panic!("missing {:?} selection", strategy))
    }

    fn dumps_leftover_to_fee(selection: &InputSelection, requested: FeeRate) -> bool {
        selection.change() == Amount::ZERO && selection.actual_fee_rate() > requested
    }

    #[test]
    fn select_all_utxos_uses_every_input() {
        let utxos = vec![utxo(100_000, 0), utxo(200_000, 1)];
        let outpoints: Vec<_> = utxos.iter().map(|output| output.0).collect();

        let selection =
            select_all_utxos_for_fee_rate(&utxos, &[], test_fee_rate()).expect("selection");

        assert_eq!(selection.selected_utxos().len(), 2);
        for op in outpoints {
            assert!(selection.selected_utxos().contains(&op));
        }
        assert!(selection.fee() > Amount::ZERO);
        // Drain: everything left after fees is sendable, there is no change.
        assert!(selection.sent() > Amount::ZERO);
        assert_eq!(selection.n_sent_outputs(), 0);
        assert_eq!(
            selection.sent() + selection.fee(),
            Amount::from_sat(300_000)
        );
    }

    #[test]
    fn select_all_utxos_accounts_for_output_weight() {
        let utxos = vec![utxo(500_000, 0)];
        let recipient = payment_recipient(0);

        let without_outputs =
            select_all_utxos_for_fee_rate(&utxos, &[], test_fee_rate()).expect("selection");
        let with_outputs = select_all_utxos_for_fee_rate(&utxos, &[recipient], test_fee_rate())
            .expect("selection");

        assert_eq!(without_outputs.n_sent_outputs(), 0);
        assert_eq!(with_outputs.n_sent_outputs(), 1);
        assert!(with_outputs.fee() >= without_outputs.fee());
        assert!(with_outputs.sent() <= without_outputs.sent());
        assert_eq!(
            with_outputs.sent() + with_outputs.fee(),
            without_outputs.sent() + without_outputs.fee(),
        );
    }

    #[test]
    fn select_all_utxos_empty_inputs_fails() {
        let err =
            select_all_utxos_for_fee_rate(&[], &[], test_fee_rate()).expect_err("expected error");
        assert_eq!(err.to_string(), "No funds available");
    }

    #[test]
    fn pick_utxos_prefers_single_input_when_sufficient() {
        let large = utxo(500_000, 0);
        let small = utxo(100_000, 1);
        let payment = payment_recipient(50_000);

        let selections =
            pick_utxos_for_fee_rate(&[large.clone(), small], &[payment], test_fee_rate())
                .expect("selection");
        let selection = selection_by_strategy(&selections, Strategy::LowestFee);

        assert_eq!(selection.selected_utxos(), &[large.0]);
        assert!(selection.fee() > Amount::ZERO);
    }

    #[test]
    fn pick_utxos_combines_inputs_when_one_is_not_enough() {
        let a = utxo(30_000, 0);
        let b = utxo(30_000, 1);
        let payment = payment_recipient(50_000);

        let selections =
            pick_utxos_for_fee_rate(&[a.clone(), b.clone()], &[payment], test_fee_rate())
                .expect("selection");
        let selection = selection_by_strategy(&selections, Strategy::LowestFee);

        assert_eq!(selection.selected_utxos().len(), 2);
        assert!(selection.selected_utxos().contains(&a.0));
        assert!(selection.selected_utxos().contains(&b.0));
        assert_eq!(
            selection.change() + selection.fee() + Amount::from_sat(50_000),
            Amount::from_sat(60_000),
        );
    }

    #[test]
    fn pick_utxos_emits_change_above_dust_threshold() {
        let utxos = vec![utxo(500_000, 0)];
        let payment = payment_recipient(50_000);

        let selections =
            pick_utxos_for_fee_rate(&utxos, &[payment], test_fee_rate()).expect("selection");
        let selection = selection_by_strategy(&selections, Strategy::LowestFee);

        let min_change = TR_DUST_RELAY_MIN_VALUE * 2;
        assert!(
            selection.change() == Amount::ZERO
                || selection.change() >= Amount::from_sat(min_change),
            "change {} below dust policy minimum {}",
            selection.change(),
            min_change,
        );
        assert_eq!(
            selection.change() + selection.fee() + Amount::from_sat(50_000),
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

        let low_sels = pick_utxos_for_fee_rate(&pool, &[payment.clone()], low).expect("low fee");
        let low_sel = selection_by_strategy(&low_sels, Strategy::Changeless);
        assert_eq!(low_sel.change(), Amount::ZERO);
        assert_eq!(low_sel.selected_utxos(), &[utxo(primary_sat, 0).0]);
        assert_selection_balances(&pool, &low_sel, payment_sat);

        assert!(
            pick_utxos_for_fee_rate(&[utxo(primary_sat, 0)], &[payment.clone()], high,).is_err(),
            "primary input alone must not fund the payment at 5 sat/vB",
        );

        let high_sels = pick_utxos_for_fee_rate(&pool, &[payment], high).expect("high fee");
        let high_sel = selection_by_strategy(&high_sels, Strategy::LowestFee);
        assert_eq!(high_sel.selected_utxos().len(), 2);
        assert!(high_sel.selected_utxos().contains(&utxo(primary_sat, 0).0));
        assert!(high_sel.selected_utxos().contains(&utxo(second_sat, 1).0));
        assert!(high_sel.change() >= Amount::from_sat(min_change));
        assert_selection_balances(&pool, &high_sel, payment_sat);
    }

    #[test]
    fn pick_utxos_uses_changeless_when_exact_input_exists() {
        let payment_sat = 50_000;
        let fee_rate = test_fee_rate();
        let exact_sat = (payment_sat..payment_sat + 5_000)
            .find(|&value_sat| {
                pick_utxos_for_fee_rate(
                    &[utxo(value_sat, 0), utxo(1_000_000, 1)],
                    &[payment_recipient(payment_sat)],
                    fee_rate,
                )
                .ok()
                .is_some_and(|selections| {
                    selections.iter().any(|selection| {
                        selection.strategy() == Strategy::Changeless
                            && selection.change() == Amount::ZERO
                            && selection.selected_utxos() == [utxo(value_sat, 0).0]
                            && !dumps_leftover_to_fee(selection, fee_rate)
                    })
                })
            })
            .expect("a changeless single-input fixture must exist");

        let selections = pick_utxos_for_fee_rate(
            &[utxo(exact_sat, 0), utxo(1_000_000, 1)],
            &[payment_recipient(payment_sat)],
            fee_rate,
        )
        .expect("selection");
        let selection = selection_by_strategy(&selections, Strategy::Changeless);

        assert_eq!(selection.change(), Amount::ZERO);
        assert_eq!(selection.selected_utxos(), &[utxo(exact_sat, 0).0]);

        let cap = selection_by_strategy(&selections, Strategy::FeeRateCap);
        assert_eq!(cap.change(), Amount::ZERO);
        assert_eq!(cap.selected_utxos(), &[utxo(exact_sat, 0).0]);
        assert!(!dumps_leftover_to_fee(cap, fee_rate));
    }

    #[test]
    fn pick_utxos_insufficient_funds() {
        let utxos = vec![utxo(1_000, 0)];
        let payment = payment_recipient(1_000_000);

        assert!(pick_utxos_for_fee_rate(&utxos, &[payment], test_fee_rate(),).is_err());
    }

    #[test]
    fn pick_utxos_many_utxos_one_large_covers_payment() {
        let mut utxos = many_utxos(250, 10_000);
        let whale = utxo(10_000_000, 250);
        utxos.push(whale.clone());
        let payment = payment_recipient(100_000);

        let selections =
            pick_utxos_for_fee_rate(&utxos, &[payment], test_fee_rate()).expect("selection");
        let selection = selection_by_strategy(&selections, Strategy::LowestFee);

        assert_eq!(selection.selected_utxos(), &[whale.0]);
        assert!(selection.selected_utxos().len() < utxos.len());
        assert_selection_balances(&utxos, &selection, 100_000);
    }

    #[test]
    fn pick_utxos_many_utxos_combines_small_inputs() {
        let utxos = many_utxos(200, 10_000);
        let payment = payment_recipient(150_000);

        let selections =
            pick_utxos_for_fee_rate(&utxos, &[payment], test_fee_rate()).expect("selection");
        let selection = selection_by_strategy(&selections, Strategy::LowestFee);

        assert!(!selection.selected_utxos().is_empty());
        assert!(selection.selected_utxos().len() <= utxos.len());
        assert_selection_balances(&utxos, &selection, 150_000);
        let min_change = TR_DUST_RELAY_MIN_VALUE * 2;
        assert!(
            selection.change() == Amount::ZERO
                || selection.change() >= Amount::from_sat(min_change),
        );
    }

    #[test]
    fn pick_utxos_many_utxos_does_not_use_entire_pool() {
        let utxos = many_utxos(300, 50_000);
        let payment = payment_recipient(25_000);

        let selections =
            pick_utxos_for_fee_rate(&utxos, &[payment], test_fee_rate()).expect("selection");
        let selection = selection_by_strategy(&selections, Strategy::LowestFee);

        assert!(selection.selected_utxos().len() < utxos.len());
        assert_selection_balances(&utxos, &selection, 25_000);
    }

    #[test]
    fn pick_utxos_many_utxos_insufficient_funds() {
        let utxos = many_utxos(200, 1_000);
        let payment = payment_recipient(500_000);

        assert!(pick_utxos_for_fee_rate(&utxos, &[payment], test_fee_rate(),).is_err());
    }

    #[test]
    fn pick_utxos_returns_one_selection_per_successful_strategy() {
        let utxos = vec![utxo(500_000, 0), utxo(100_000, 1)];
        let payment = payment_recipient(50_000);

        let selections =
            pick_utxos_for_fee_rate(&utxos, &[payment], test_fee_rate()).expect("selection");

        assert!(selections.len() >= 2);
        assert!(
            selections
                .iter()
                .any(|selection| selection.strategy() == Strategy::LowestFee)
        );
        assert!(
            selections
                .iter()
                .any(|selection| selection.strategy() == Strategy::FeeRateCap)
        );
        assert!(
            selections
                .iter()
                .all(|selection| selection.strategy() != Strategy::Greedy)
        );

        for selection in &selections {
            assert_selection_balances(&utxos, selection, 50_000);
        }
    }

    #[test]
    fn greedy_fallback_when_bnb_is_not_allowed_any_rounds() {
        let utxos = vec![utxo(500_000, 0), utxo(100_000, 1)];
        let payment = payment_recipient(50_000);

        let with_bnb =
            pick_utxos(&utxos, &[payment.clone()], test_fee_rate(), BNB_MAX_ROUNDS).expect("bnb");
        assert!(
            with_bnb
                .iter()
                .all(|selection| selection.strategy() != Strategy::Greedy)
        );

        let selections =
            pick_utxos(&utxos, &[payment], test_fee_rate(), 0).expect("greedy fallback");
        assert_eq!(selections.len(), 1);
        assert_eq!(selections[0].strategy(), Strategy::Greedy);
        assert_selection_balances(&utxos, &selections[0], 50_000);
    }

    fn single_input_overpay_sat(payment: &Recipient, fee_rate: FeeRate) -> u64 {
        let payment_sat = payment.amount.to_sat();
        (payment_sat..payment_sat + 5_000)
            .find(|&value_sat| {
                pick_utxos_for_fee_rate(&[utxo(value_sat, 0)], &[payment.clone()], fee_rate)
                    .ok()
                    .is_some_and(|selections| {
                        selections.iter().any(|selection| {
                            matches!(
                                selection.strategy(),
                                Strategy::Changeless | Strategy::LowestFee
                            ) && dumps_leftover_to_fee(selection, fee_rate)
                        })
                    })
            })
            .expect("a single-input overpay fixture must exist")
    }

    /// A single input that funds the payment with leftover below the change
    /// floor. Changeless dumps that leftover into the fee; FeeRateCap should
    /// pull in another input so leftover becomes change.
    #[test]
    fn fee_rate_cap_creates_change_instead_of_overpaying() {
        let fee_rate = test_fee_rate();
        let payment = payment_recipient(50_000);
        let overpay_sat = single_input_overpay_sat(&payment, fee_rate);

        let extra = utxo(10_000, 1);
        let pool = vec![utxo(overpay_sat, 0), extra.clone()];
        let selections = pick_utxos_for_fee_rate(&pool, &[payment], fee_rate).expect("selection");
        let cap = selection_by_strategy(&selections, Strategy::FeeRateCap);

        // LowestFee/Changeless keep the cheaper single-input dump; only
        // FeeRateCap should spend the extra input to stay at the requested rate.
        for strategy in [Strategy::Changeless, Strategy::LowestFee] {
            let overpay = selection_by_strategy(&selections, strategy);
            assert!(
                dumps_leftover_to_fee(overpay, fee_rate),
                "{strategy:?} must still dump leftover on this pool"
            );
            assert!(!overpay.selected_utxos().contains(&extra.0));
        }

        assert!(cap.selected_utxos().contains(&extra.0));
        assert!(!dumps_leftover_to_fee(cap, fee_rate));
        // Extra is 10_000 sats; at 1 sat/vB the added input+change output is
        // ~100 sats. If that extra were dumped to fee, change would sit at the
        // dust floor and actual_fee_rate would jump by tens of sat/vB.
        assert!(
            cap.change() >= extra.1.value - Amount::from_sat(1_000),
            "extra input was selected but mostly overpaid as fee; change was {}",
            cap.change(),
        );
        assert!(cap.actual_fee_rate() >= fee_rate);
        assert!(
            cap.actual_fee_rate().as_sat_vb()
                <= fee_rate.as_sat_vb() * FEE_RATE_CAP_MAX_OVERSHOOT + 0.05,
            "FeeRateCap implied {} sat/vB, cap is {} sat/vB",
            cap.actual_fee_rate().as_sat_vb(),
            fee_rate.as_sat_vb() * FEE_RATE_CAP_MAX_OVERSHOOT,
        );
        assert_selection_balances(&pool, cap, 50_000);
    }

    #[test]
    fn fee_rate_cap_absent_when_change_is_impossible() {
        let fee_rate = test_fee_rate();
        let payment = payment_recipient(50_000);
        let overpay_sat = single_input_overpay_sat(&payment, fee_rate);

        let pool = vec![utxo(overpay_sat, 0)];
        let selections = pick_utxos_for_fee_rate(&pool, &[payment], fee_rate).expect("selection");

        assert!(
            selections
                .iter()
                .all(|selection| selection.strategy() != Strategy::FeeRateCap)
        );
        assert!(!selections.is_empty());
    }

    #[test]
    fn select_all_utxos_many_inputs() {
        let utxos: Vec<_> = (0..400).map(|vout| utxo(25_000, vout)).collect();
        let outpoints: Vec<_> = utxos.iter().map(|output| output.0).collect();

        let selection =
            select_all_utxos_for_fee_rate(&utxos, &[], test_fee_rate()).expect("selection");

        assert_eq!(selection.selected_utxos().len(), 400);
        for op in outpoints {
            assert!(selection.selected_utxos().contains(&op));
        }
        assert_eq!(
            selection.sent() + selection.fee(),
            Amount::from_sat(400 * 25_000),
        );
    }
}
