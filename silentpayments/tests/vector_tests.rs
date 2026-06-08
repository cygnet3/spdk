#![allow(non_snake_case)]
mod common;
#[cfg(test)]
mod tests {
    use secp256k1::{Scalar, Secp256k1, SecretKey};
    use silentpayments::{
        InputsHash, Network, NonEmptyArray, TransactionSharedSecret, SilentPaymentAddress, receiving::Label, utils::{
            OutPoint, receiving::{
                PublicTweakData, get_pubkey_from_input, is_p2tr
            }, sending::{GlobalSenderEcdhShare, NormalizedSecretKey}
        }
    };
    use std::{collections::{HashMap, HashSet}, io::Cursor, str::FromStr};

    use silentpayments::receiving::Receiver;

    use silentpayments::sending::generate_recipient_pubkeys;

    use crate::common::{
        structs::TestData,
        utils::{
            self, decode_outputs_to_check, decode_recipients, deser_string_vector,
            verify_and_calculate_signatures,
        },
    };

    const NETWORK: Network = Network::Mainnet;

    #[test]
    fn test_with_test_vectors() {
        let testdata = utils::read_file();

        for test in testdata {
            process_test_case(test);
        }
    }

    fn process_test_case(test_case: TestData) {
        println!("test: {}", test_case.comment);
        let secp = Secp256k1::new();

        let mut sending_outputs: HashSet<String> = HashSet::new();

        for sendingtest in test_case.sending {
            let given = sendingtest.given;
            let expected = sendingtest.expected;
            let outpoints: Vec<OutPoint> = given
                .vin
                .iter()
                .map(|vin| OutPoint::from_txid_and_vout(vin.txid.clone(), vin.vout).unwrap())
                .collect();
            let mut input_priv_keys = Vec::new();
            let mut script_pubkeys = Vec::new();
            for input in &given.vin {
                let script_sig = hex::decode(&input.scriptSig).unwrap();
                let txinwitness_bytes = hex::decode(&input.txinwitness).unwrap();
                let mut cursor = Cursor::new(&txinwitness_bytes);
                let txinwitness = deser_string_vector(&mut cursor).unwrap();
                let script_pub_key = hex::decode(&input.prevout.scriptPubKey.hex).unwrap();

                // We don't really test the sending case here since we have access to the script sig and witness
                // which will not be the case most of the time.
                match get_pubkey_from_input(&script_sig, &txinwitness, &script_pub_key) {
                    Ok(Some(pubkey)) => {
                        input_priv_keys.push((
                            SecretKey::from_str(&input.private_key).unwrap(),
                            is_p2tr(&script_pub_key),
                        ));
                        script_pubkeys.push((script_pub_key, Some(pubkey)));
                        }
                    Ok(None) => {
                        script_pubkeys.push((script_pub_key, None));
                    },
                    Err(e) => panic!("Problem parsing the input: {:?}", e),
                }
            }
            if input_priv_keys.is_empty() {
                continue;
            }

            // we drop the amounts from the test here, since they're of no concern to us
            let silent_addresses = decode_recipients(&given.recipients);

            let input_priv_keys_normalized_data: Vec<NormalizedSecretKey> = input_priv_keys
                .into_iter()
                .map(|(key, is_taproot)| NormalizedSecretKey::new(&secp, key, is_taproot))
                .collect();

            let mut shared_secrets = HashMap::new();
            for address in &silent_addresses {
                let recipient_scan_key = address.get_scan_key();
                if shared_secrets.contains_key(&recipient_scan_key) {
                    continue;
                }
                let mut global_share = GlobalSenderEcdhShare::new_from_summed_keys(
                    recipient_scan_key,
                    NonEmptyArray::new(&input_priv_keys_normalized_data).unwrap(),
                )
                .unwrap();
                let input_hash = InputsHash::new(
                    NonEmptyArray::new(&outpoints).unwrap(),
                    NonEmptyArray::new(&script_pubkeys).unwrap(),
                )
                .unwrap();
                global_share
                    .apply_input_hash(&secp, input_hash)
                    .unwrap();
                shared_secrets.insert(
                    recipient_scan_key,
                    TransactionSharedSecret::new_from_global_share(&global_share).unwrap(),
                );
            }
            let outputs = generate_recipient_pubkeys(&silent_addresses, &shared_secrets).unwrap();

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

            let b_scan = SecretKey::from_str(&given.key_material.scan_priv_key).unwrap();
            let b_spend = SecretKey::from_str(&given.key_material.spend_priv_key).unwrap();
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

            let outputs_to_check = decode_outputs_to_check(&given.outputs);

            let outpoints: Vec<OutPoint> = given
                .vin
                .iter()
                .map(|vin| OutPoint::from_txid_and_vout(vin.txid.clone(), vin.vout).unwrap())
                .collect();
            let mut script_pubkeys = Vec::new();
            for input in given.vin {
                let script_sig = hex::decode(&input.scriptSig).unwrap();
                let txinwitness_bytes = hex::decode(&input.txinwitness).unwrap();
                let mut cursor = Cursor::new(&txinwitness_bytes);
                let txinwitness = deser_string_vector(&mut cursor).unwrap();
                let script_pub_key = hex::decode(&input.prevout.scriptPubKey.hex).unwrap();

                match get_pubkey_from_input(&script_sig, &txinwitness, &script_pub_key) {
                    Ok(Some(pubkey)) => script_pubkeys.push((script_pub_key, Some(pubkey))),
                    Ok(None) => script_pubkeys.push((script_pub_key, None)),
                    Err(e) => panic!("Problem parsing the input: {:?}", e),
                }
            }
            if script_pubkeys.iter().all(|(_, pk)| pk.is_none()) {
                continue;
            }

            for label_int in &given.labels {
                let label = Label::new(b_scan, *label_int);
                sp_receiver.add_label(label).unwrap();
            }

            let mut receiving_addresses: HashSet<SilentPaymentAddress> = HashSet::new();
            // get receiving address for no label
            receiving_addresses.insert(sp_receiver.get_receiving_address());

            // get receiving addresses for every label
            let labels = sp_receiver.list_labels();
            for label in &labels {
                receiving_addresses
                    .insert(sp_receiver.get_receiving_address_for_label(label).unwrap());
            }

            if !&given.labels.contains(&0) {
                receiving_addresses.remove(&sp_receiver.get_change_address());
            }

            let set1: HashSet<_> = receiving_addresses.iter().collect();
            let set2: HashSet<_> = expected.addresses.iter().collect();

            // check that the receiving addresses generated are equal
            // to the expected addresses
            assert_eq!(set1, set2);

            let tweak_data = PublicTweakData::new(
                &secp,
                NonEmptyArray::new(&outpoints).unwrap(),
                NonEmptyArray::new(&script_pubkeys).unwrap(),
            )
            .unwrap();
            let ecdh_shared_secret =
                TransactionSharedSecret::new_from_public_tweak_data(&tweak_data, &b_scan).unwrap();

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
            assert!(expected.outputs.len() == res.len());
            assert!(res.iter().all(|output| expected.outputs.contains(output)));
        }
    }
}
