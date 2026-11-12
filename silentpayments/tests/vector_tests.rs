#![allow(non_snake_case)]
mod common;
#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};

    use bitcoin::hashes::Hash as _;
    use secp256k1::{Scalar, Secp256k1};
    use silentpayments::receiving::{Label, Receiver};
    use silentpayments::sending::generate_recipient_pubkeys;
    use silentpayments::utils::OutPoint;
    use silentpayments::utils::receiving::{PublicTweakData, get_pubkey_from_input, is_p2tr};
    use silentpayments::utils::sending::{GlobalSenderEcdhShare, NormalizedSecretKey};
    use silentpayments::{
        Network, NonEmptyArray, SilentPaymentCode, TransactionInputs, TransactionSharedSecret,
    };

    use crate::common::structs::TestData;
    use crate::common::utils::{self, verify_and_calculate_signatures};

    const NETWORK: Network = Network::Mainnet;

    #[test]
    fn test_with_test_vectors() {
        let testdata = utils::read_file();

        for test in testdata {
            process_test_case(test);
        }
    }

    #[expect(clippy::too_many_lines)]
    fn process_test_case(test_case: TestData) {
        println!("test: {}", test_case.comment);
        let secp = Secp256k1::new();

        let mut sending_outputs: HashSet<String> = HashSet::new();

        for sendingtest in test_case.sending {
            let given = sendingtest.given;
            let expected = sendingtest.expected;

            // Keep every vin. The input hash uses the smallest outpoint of the whole
            // transaction, including inputs that are not silent-payment eligible.
            // Private keys are summed only for inputs that yield a pubkey, matching
            // `TransactionInputs::eligible_pubkeys`.
            let mut inputs = TransactionInputs::with_capacity(given.vin.len());
            let mut normalized_keys = Vec::new();
            for input in given.vin {
                let outpoint =
                    OutPoint::from_txid_bytes_and_vout(input.txid.to_byte_array(), input.vout);
                let script_pub_key = input.prevout.scriptPubKey.hex.as_bytes().to_vec();
                let pubkey = match get_pubkey_from_input(
                    input.scriptSig.as_bytes(),
                    &input.txinwitness.to_vec(),
                    &script_pub_key,
                ) {
                    Ok(pubkey) => pubkey,
                    Err(e) => panic!("Problem parsing the input: {e:?}"),
                };
                if pubkey.is_some() {
                    normalized_keys.push(NormalizedSecretKey::new(
                        &secp,
                        input.private_key,
                        is_p2tr(&script_pub_key),
                    ));
                }
                inputs.push(outpoint, script_pub_key, pubkey);
            }
            if normalized_keys.is_empty() {
                continue;
            }

            // we drop the amounts from the test here, since we don't work with amounts
            // the wallet should make sure the amount sent are correct
            let silent_payment_codes = given.recipients;

            let aux_rand = [0u8; 32];

            let mut shared_secrets = HashMap::new();
            for payment_code in &silent_payment_codes {
                let recipient_scan_key = payment_code.scan_key();
                if shared_secrets.contains_key(&recipient_scan_key) {
                    continue;
                }
                let global_share = GlobalSenderEcdhShare::new_from_summed_keys(
                    &secp,
                    recipient_scan_key,
                    NonEmptyArray::new(&normalized_keys).unwrap(),
                    &aux_rand,
                )
                .unwrap();
                shared_secrets.insert(
                    recipient_scan_key,
                    TransactionSharedSecret::new_from_global_share(&secp, &global_share, &inputs)
                        .unwrap(),
                );
            }

            let outputs =
                generate_recipient_pubkeys(&secp, &silent_payment_codes, &shared_secrets).unwrap();

            for output_pubkeys in &outputs {
                for pubkey in output_pubkeys.1 {
                    sending_outputs.insert(hex::encode(pubkey.serialize()));
                }
            }
            assert!(expected.outputs.iter().any(|candidate_set| {
                sending_outputs
                    .iter()
                    .all(|output| candidate_set.contains(output))
            }));
        }

        for receivingtest in test_case.receiving {
            let given = receivingtest.given;
            let expected = receivingtest.expected;

            let b_scan = given.key_material.scan_priv_key;
            let b_spend = given.key_material.spend_priv_key;
            let B_spend = b_spend.public_key(&secp);
            let B_scan = b_scan.public_key(&secp);

            let change_label = Label::new(b_scan, 0);
            let mut sp_receiver = Receiver::new(
                silentpayments::SpVersion::ZERO,
                B_scan,
                B_spend,
                change_label,
                NETWORK,
            )
            .unwrap();

            let outputs_to_check = given.outputs;

            // Keep every vin. The input hash uses the smallest outpoint of the whole
            // transaction, including inputs that are not silent-payment eligible.
            let mut inputs = TransactionInputs::with_capacity(given.vin.len());
            for input in given.vin {
                let outpoint =
                    OutPoint::from_txid_bytes_and_vout(input.txid.to_byte_array(), input.vout);
                let script_pub_key = input.prevout.scriptPubKey.hex.as_bytes().to_vec();
                let pubkey = match get_pubkey_from_input(
                    input.scriptSig.as_bytes(),
                    &input.txinwitness.to_vec(),
                    &script_pub_key,
                ) {
                    Ok(pubkey) => pubkey,
                    Err(e) => panic!("Problem parsing the input: {e:?}"),
                };
                inputs.push(outpoint, script_pub_key, pubkey);
            }
            if inputs.input_pubkeys().iter().all(Option::is_none) {
                continue;
            }

            for label_int in &given.labels {
                let label = Label::new(b_scan, *label_int);
                sp_receiver.add_label(label).unwrap();
            }

            let mut receiving_codes: HashSet<SilentPaymentCode> = HashSet::new();
            // get receiving code for no label
            receiving_codes.insert(sp_receiver.receiving_code());

            // get receiving codes for every label
            let labels = sp_receiver.list_labels();
            for label in &labels {
                receiving_codes.insert(sp_receiver.receiving_code_for_label(label).unwrap());
            }

            if !&given.labels.contains(&0) {
                receiving_codes.remove(&sp_receiver.change_code());
            }

            let expected_codes: HashSet<SilentPaymentCode> = expected.codes.into_iter().collect();

            // check that the receiving codes generated are equal
            // to the expected codes
            assert_eq!(receiving_codes, expected_codes);

            let tweak_data = PublicTweakData::new(&secp, &inputs).unwrap();
            let ecdh_shared_secret =
                TransactionSharedSecret::new_from_public_tweak_data(&secp, &tweak_data, &b_scan)
                    .unwrap();

            let scanned_outputs_received = sp_receiver
                .scan_transaction(&ecdh_shared_secret, &outputs_to_check)
                .unwrap();

            let key_tweaks: Vec<Scalar> = scanned_outputs_received
                .into_iter()
                .flat_map(|(_, map)| {
                    let mut ret: Vec<Scalar> = vec![];
                    for l in map.into_values() {
                        ret.push(l);
                    }
                    ret
                })
                .collect();

            let res = verify_and_calculate_signatures(key_tweaks, b_spend).unwrap();
            assert_eq!(expected.outputs.len(), res.len());
            assert!(res.iter().all(|output| expected.outputs.contains(output)));
        }
    }
}
