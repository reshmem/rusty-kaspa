use crate::harness::MockKaspaNode;
use igra_core::infrastructure::rpc::NodeRpc;
use kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
use kaspa_consensus_core::tx::{ScriptPublicKey, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput, TransactionId, UtxoEntry};
use kaspa_txscript::pay_to_address_script;
use kaspa_wallet_core::prelude::Address;

#[tokio::test]
async fn mock_node_tracks_utxos_and_submissions() {
    let node = MockKaspaNode::new();
    let address = Address::try_from("kaspadev:qzjwhmuwx4fmmxleyykgcekr2m2tamseskqvl859mss2jvz7tk46j2qyvpukx")
        .expect("address");
    let outpoint = TransactionOutpoint::new(TransactionId::from_slice(&[1u8; 32]), 0);
    let entry = UtxoEntry::new(10_000, pay_to_address_script(&address), 0, false);

    node.add_utxo(igra_core::infrastructure::rpc::UtxoWithOutpoint {
        address: Some(address.clone()),
        outpoint,
        entry,
    });

    let utxos = node.get_utxos_by_addresses(&[address.clone()]).await.expect("utxos");
    assert_eq!(utxos.len(), 1);

    let input = TransactionInput {
        previous_outpoint: outpoint,
        signature_script: Vec::new(),
        sequence: 0,
        sig_op_count: 0,
    };
    let output = TransactionOutput {
        value: 9_000,
        script_public_key: ScriptPublicKey::from_vec(0, vec![1, 2, 3]),
    };
    let tx = Transaction::new_non_finalized(0, vec![input], vec![output], 0, SUBNETWORK_ID_NATIVE, 0, Vec::new());

    let tx_id = node.submit_transaction(tx).await.expect("submit");
    assert_eq!(node.submitted_transactions().len(), 1);
    node.assert_transaction_submitted(&tx_id);
}
