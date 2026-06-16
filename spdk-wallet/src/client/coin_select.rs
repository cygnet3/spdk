use anyhow::Result;
use bdk_coin_select::metrics::{Changeless, LowestFee};
use bdk_coin_select::{Candidate, ChangePolicy, CoinSelector, DrainWeights, FeeRate, TR_DUST_RELAY_MIN_VALUE, TR_KEYSPEND_TXIN_WEIGHT, TR_SPK_WEIGHT, TXOUT_BASE_WEIGHT, Target, TargetFee, TargetOutputs};
use bitcoin::{Amount, OutPoint, TxOut};

/// Upper bound on branch-and-bound iterations (see `bdk_coin_select` README).
const BNB_MAX_ROUNDS: usize = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strategy {
    Changeless,
    LowestFee,
    Greedy, // Fallback
    Drain, // for the drain transaction case
}

#[derive(Debug)]
pub struct InputSelection {
    pub selected_utxos: Vec<OutPoint>,
    pub change: Amount,
    pub n_change_outputs: usize,
    pub fee: Amount,
    pub actual_fee_rate: FeeRate,
    pub strategy: Strategy,
}

pub fn select_all_utxos_for_fee_rate(
    available_utxos: Vec<(OutPoint, TxOut)>,
    tx_outs: Vec<TxOut>,
    fee_rate: FeeRate,
) -> Result<InputSelection> {
    // If we don't have any change outputs, we return an error
    if tx_outs.is_empty() {
        return Err(anyhow::Error::msg("No change outputs provided"));
    }

    // as a silent payment wallet, we only spend taproot outputs
    let candidates: Vec<Candidate> = available_utxos
        .iter()
        .map(|(_, o)| {
            if o.script_pubkey.is_p2tr() {
                Candidate::new_tr_keyspend(o.value.to_sat())
            } else {
                unimplemented!()
            }
        })
        .collect();

    let mut coin_selector = CoinSelector::new(&candidates);

    let mut n_outputs = 0;
    let mut output_weight = 0;
    for tx_out in tx_outs {
        n_outputs += 1;
        output_weight += tx_out.weight().to_wu();
    }

    let drain_output = DrainWeights {
            output_weight,
            spend_weight: 0,
            n_outputs,
        };

    let change_policy =
        ChangePolicy::min_value(drain_output, 0);

    let target = Target {
        fee: TargetFee::from_feerate(fee_rate),
        outputs: TargetOutputs {
            value_sum: 0,
            weight_sum: 0,
            n_outputs: 0
        }
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
        selected_utxos: coin_selector.selected_indices().iter().map(|i| available_utxos[*i].0).collect(),
        change: Amount::from_sat(change.value),
        n_change_outputs: n_outputs,
        fee: Amount::from_sat(fee_value as u64),
        actual_fee_rate,
        strategy: Strategy::Drain,
    })
}

struct SelectionContext<'a> {
    available_utxos: &'a [(OutPoint, TxOut)],
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
        .map(|i| ctx.available_utxos[*i].0)
        .collect();

    let change = coin_selector.drain(ctx.target, ctx.change_policy);
    let change_value = if change.is_some() { change.value } else { 0 };
    let n_change_outputs = if change_value == 0 {
        0
    } else {
        ctx.n_change_outputs
    };

    let fee_value = coin_selector.fee(ctx.target.outputs.value_sum, change_value);
    if fee_value < 0 {
        return Err(anyhow::Error::msg("Not enough funds available"));
    }

    let actual_fee_rate = coin_selector
        .implied_feerate(ctx.target.outputs, change)
        .ok_or_else(|| anyhow::Error::msg("cannot compute effective feerate for selection"))?;

    Ok(InputSelection {
        selected_utxos,
        change: Amount::from_sat(change_value),
        n_change_outputs,
        fee: Amount::from_sat(fee_value as u64),
        actual_fee_rate,
        strategy,
    })
}

fn try_changeless_selection(ctx: &SelectionContext<'_>) -> Result<InputSelection> {
    let mut coin_selector = CoinSelector::new(ctx.candidates);
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
    let mut coin_selector = CoinSelector::new(ctx.candidates);
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
    let mut coin_selector = CoinSelector::new(ctx.candidates);
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

    runners
        .iter()
        .filter_map(|run| run(ctx).ok())
        .collect()
}

/// Run each coin-selection strategy independently on a fresh [`CoinSelector`] clone.
///
/// Returns every strategy that found a valid selection (up to 3). Errors only when all
/// strategies fail.
pub fn pick_utxos_for_fee_rate(
    available_utxos: Vec<(OutPoint, TxOut)>,
    tx_outs: Vec<TxOut>,
    n_change_outputs: usize,
    fee_rate: FeeRate,
) -> Result<Vec<InputSelection>> {
    // as a silent payment wallet, we only spend taproot outputs
    let candidates: Vec<Candidate> = available_utxos
        .iter()
        .map(|(_, o)| {
            if o.script_pubkey.is_p2tr() {
                Candidate::new_tr_keyspend(o.value.to_sat())
            } else {
                unimplemented!()
            }
        })
        .collect();

    let change_policy = ChangePolicy::min_value(
        DrainWeights {
            output_weight: (TXOUT_BASE_WEIGHT + TR_SPK_WEIGHT) * n_change_outputs as u64,
            spend_weight: TR_KEYSPEND_TXIN_WEIGHT * n_change_outputs as u64,
            n_outputs: n_change_outputs,
        },
        TR_DUST_RELAY_MIN_VALUE * 2,
    );

    let target = Target {
        fee: TargetFee::from_feerate(fee_rate),
        outputs: TargetOutputs::fund_outputs(
            tx_outs
                .iter()
                .map(|o| (o.weight().to_wu(), o.value.to_sat())),
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

#[cfg(test)]
mod tests {
    use super::*;
    use bdk_coin_select::TR_DUST_RELAY_MIN_VALUE;
    use bitcoin::key::{Keypair, TapTweak};
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use bitcoin::hashes::Hash;
    use bitcoin::{ScriptBuf, Txid};

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

    fn utxo(value_sat: u64, vout: u32) -> (OutPoint, TxOut) {
        (
            OutPoint::new(Txid::all_zeros(), vout),
            p2tr_txout(value_sat),
        )
    }

    fn payment_output(value_sat: u64) -> TxOut {
        p2tr_txout(value_sat)
    }

    fn many_utxos(count: usize, value_sat: u64) -> Vec<(OutPoint, TxOut)> {
        (0..count as u32).map(|vout| utxo(value_sat, vout)).collect()
    }

    fn selected_input_sum(
        utxos: &[(OutPoint, TxOut)],
        selection: &InputSelection,
    ) -> u64 {
        selection
            .selected_utxos
            .iter()
            .map(|op| {
                utxos
                    .iter()
                    .find(|(o, _)| o == op)
                    .map(|(_, txo)| txo.value.to_sat())
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
        assert_eq!(
            selection.change.to_sat() + selection.fee.to_sat() + payment_sat,
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
        let outpoints: Vec<_> = utxos.iter().map(|(op, _)| *op).collect();

        let selection = select_all_utxos_for_fee_rate(utxos, vec![payment_output(0)], test_fee_rate())
            .expect("selection");

        assert_eq!(selection.selected_utxos.len(), 2);
        for op in outpoints {
            assert!(selection.selected_utxos.contains(&op));
        }
        assert!(selection.fee > Amount::ZERO);
        assert!(selection.change > Amount::ZERO);
        assert_eq!(selection.change + selection.fee, Amount::from_sat(300_000));
    }

    #[test]
    fn select_all_utxos_accounts_for_output_weight() {
        let utxos = vec![utxo(500_000, 0)];
        let base_outputs = vec![payment_output(0)];
        let outputs = vec![payment_output(0)];

        let without_outputs = select_all_utxos_for_fee_rate(utxos.clone(), base_outputs, test_fee_rate())
            .expect("selection");
        let with_outputs =
            select_all_utxos_for_fee_rate(utxos, outputs, test_fee_rate()).expect("selection");

        assert!(with_outputs.fee >= without_outputs.fee);
        assert!(with_outputs.change <= without_outputs.change);
        assert_eq!(
            with_outputs.change + with_outputs.fee,
            without_outputs.change + without_outputs.fee,
        );
    }

    #[test]
    fn select_all_utxos_empty_inputs_fails() {
        let err = select_all_utxos_for_fee_rate(vec![], vec![payment_output(0)], test_fee_rate())
            .expect_err("expected error");
        assert_eq!(err.to_string(), "No funds available");
    }

    #[test]
    fn pick_utxos_prefers_single_input_when_sufficient() {
        let large = utxo(500_000, 0);
        let small = utxo(100_000, 1);
        let payment = payment_output(50_000);

        let selections = pick_utxos_for_fee_rate(
            vec![large.clone(), small],
            vec![payment],
            test_change_outputs(),
            test_fee_rate(),
        )
        .expect("selection");
        let selection = selection_by_strategy(&selections, Strategy::LowestFee);

        assert_eq!(selection.selected_utxos, vec![large.0]);
        assert!(selection.fee > Amount::ZERO);
    }

    #[test]
    fn pick_utxos_combines_inputs_when_one_is_not_enough() {
        let a = utxo(30_000, 0);
        let b = utxo(30_000, 1);
        let payment = payment_output(50_000);

        let selections = pick_utxos_for_fee_rate(
            vec![a.clone(), b.clone()],
            vec![payment],
            test_change_outputs(),
            test_fee_rate(),
        )
        .expect("selection");
        let selection = selection_by_strategy(&selections, Strategy::LowestFee);

        assert_eq!(selection.selected_utxos.len(), 2);
        assert!(selection.selected_utxos.contains(&a.0));
        assert!(selection.selected_utxos.contains(&b.0));
        assert_eq!(
            selection.change + selection.fee + Amount::from_sat(50_000),
            Amount::from_sat(60_000),
        );
    }

    #[test]
    fn pick_utxos_emits_change_above_dust_threshold() {
        let utxos = vec![utxo(500_000, 0)];
        let payment = payment_output(50_000);

        let selections =
            pick_utxos_for_fee_rate(utxos, vec![payment], test_change_outputs(), test_fee_rate())
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

        let payment = payment_output(payment_sat);
        let pool = vec![utxo(primary_sat, 0), utxo(second_sat, 1)];

        let low_sels =
            pick_utxos_for_fee_rate(pool.clone(), vec![payment.clone()], test_change_outputs(), low)
                .expect("low fee");
        let low_sel = selection_by_strategy(&low_sels, Strategy::Changeless);
        assert_eq!(low_sel.change, Amount::ZERO);
        assert_eq!(low_sel.selected_utxos, vec![utxo(primary_sat, 0).0]);
        assert_selection_balances(&pool, &low_sel, payment_sat);

        assert!(
            pick_utxos_for_fee_rate(
                vec![utxo(primary_sat, 0)],
                vec![payment.clone()],
                test_change_outputs(),
                high,
            )
            .is_err(),
            "primary input alone must not fund the payment at 5 sat/vB",
        );

        let high_sels =
            pick_utxos_for_fee_rate(pool.clone(), vec![payment], test_change_outputs(), high)
                .expect("high fee");
        let high_sel = selection_by_strategy(&high_sels, Strategy::LowestFee);
        assert_eq!(high_sel.selected_utxos.len(), 2);
        assert!(high_sel.selected_utxos.contains(&utxo(primary_sat, 0).0));
        assert!(high_sel.selected_utxos.contains(&utxo(second_sat, 1).0));
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
                    vec![payment_output(payment_sat)],
                    test_change_outputs(),
                    fee_rate,
                )
                .ok()
                .is_some_and(|selections| {
                    selections.iter().any(|selection| {
                        selection.strategy == Strategy::Changeless
                            && selection.change == Amount::ZERO
                            && selection.selected_utxos == vec![utxo(value_sat, 0).0]
                    })
                })
            })
            .expect("a changeless single-input fixture must exist");

        let selections = pick_utxos_for_fee_rate(
            vec![utxo(exact_sat, 0), utxo(1_000_000, 1)],
            vec![payment_output(payment_sat)],
            test_change_outputs(),
            fee_rate,
        )
        .expect("selection");
        let selection = selection_by_strategy(&selections, Strategy::Changeless);

        assert_eq!(selection.change, Amount::ZERO);
        assert_eq!(selection.selected_utxos, vec![utxo(exact_sat, 0).0]);
    }

    #[test]
    fn pick_utxos_insufficient_funds() {
        let utxos = vec![utxo(1_000, 0)];
        let payment = payment_output(1_000_000);

        assert!(
            pick_utxos_for_fee_rate(utxos, vec![payment], test_change_outputs(), test_fee_rate())
                .is_err()
        );
    }

    #[test]
    fn pick_utxos_many_utxos_one_large_covers_payment() {
        let mut utxos = many_utxos(250, 10_000);
        let whale = utxo(10_000_000, 250);
        utxos.push(whale.clone());
        let payment = payment_output(100_000);

        let selections = pick_utxos_for_fee_rate(
            utxos.clone(),
            vec![payment],
            test_change_outputs(),
            test_fee_rate(),
        )
        .expect("selection");
        let selection = selection_by_strategy(&selections, Strategy::LowestFee);

        assert_eq!(selection.selected_utxos, vec![whale.0]);
        assert!(selection.selected_utxos.len() < utxos.len());
        assert_selection_balances(&utxos, &selection, 100_000);
    }

    #[test]
    fn pick_utxos_many_utxos_combines_small_inputs() {
        let utxos = many_utxos(200, 10_000);
        let payment = payment_output(150_000);

        let selections = pick_utxos_for_fee_rate(
            utxos.clone(),
            vec![payment],
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
        let payment = payment_output(25_000);

        let selections = pick_utxos_for_fee_rate(
            utxos.clone(),
            vec![payment],
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
        let payment = payment_output(500_000);

        assert!(
            pick_utxos_for_fee_rate(utxos, vec![payment], test_change_outputs(), test_fee_rate())
                .is_err()
        );
    }

    #[test]
    fn pick_utxos_more_change_outputs_never_reduces_fee() {
        let payment_sat = 50_000;
        let utxos = vec![utxo(500_000, 0)];
        let payment = payment_output(payment_sat);

        let one_change_sels = pick_utxos_for_fee_rate(
            utxos.clone(),
            vec![payment.clone()],
            1,
            test_fee_rate(),
        )
        .expect("selection with one change output");
        let two_change_sels = pick_utxos_for_fee_rate(utxos.clone(), vec![payment], 2, test_fee_rate())
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
        let payment = payment_output(payment_sat);
        let min_for_one_change = (payment_sat..payment_sat + 50_000)
            .find(|&value_sat| {
                pick_utxos_for_fee_rate(vec![utxo(value_sat, 0)], vec![payment.clone()], 1, fee_rate)
                    .is_ok()
            })
            .expect("fixture where one change output is affordable");
        let min_for_two_change = (payment_sat..payment_sat + 50_000)
            .find(|&value_sat| {
                pick_utxos_for_fee_rate(vec![utxo(value_sat, 0)], vec![payment.clone()], 2, fee_rate)
                    .is_ok()
            })
            .expect("fixture where two change outputs are affordable");

        let one_change_sels = pick_utxos_for_fee_rate(
            vec![utxo(min_for_one_change, 0)],
            vec![payment.clone()],
            1,
            fee_rate,
        )
        .expect("one change output should succeed");
        let one_change = selection_by_strategy(&one_change_sels, Strategy::LowestFee);
        assert_selection_balances(&vec![utxo(min_for_one_change, 0)], one_change, payment_sat);

        let two_change_sels = pick_utxos_for_fee_rate(
            vec![utxo(min_for_two_change, 0)],
            vec![payment],
            2,
            fee_rate,
        )
        .expect("two change outputs should succeed");
        let two_change = selection_by_strategy(&two_change_sels, Strategy::LowestFee);
        assert_selection_balances(&vec![utxo(min_for_two_change, 0)], two_change, payment_sat);
        assert!(min_for_two_change >= min_for_one_change);
    }

    #[test]
    fn pick_utxos_returns_one_selection_per_successful_strategy() {
        let utxos = vec![utxo(500_000, 0), utxo(100_000, 1)];
        let payment = payment_output(50_000);

        let selections = pick_utxos_for_fee_rate(
            utxos.clone(),
            vec![payment],
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
    fn select_all_utxos_many_inputs() {
        let utxos = many_utxos(400, 25_000);
        let outpoints: Vec<_> = utxos.iter().map(|(op, _)| *op).collect();

        let selection = select_all_utxos_for_fee_rate(utxos, vec![payment_output(0)], test_fee_rate())
            .expect("selection");

        assert_eq!(selection.selected_utxos.len(), 400);
        for op in outpoints {
            assert!(selection.selected_utxos.contains(&op));
        }
        assert_eq!(
            selection.change + selection.fee,
            Amount::from_sat(400 * 25_000),
        );
    }
}