use backend_blindbit_v2::BlindbitClient;
use bitcoin::{Amount, absolute::Height};
use futures::StreamExt;

// static ORACLE_URL: &str = "https://oracle.setor.dev";
static ORACLE_URL: &str = "http://127.0.0.1:7001";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("Connecting to oracle service at {ORACLE_URL}...");
    let client = BlindbitClient::new(ORACLE_URL.to_string());

    let start = Height::from_consensus(300000).unwrap();
    let end = Height::from_consensus(300002).unwrap();

    let dust_limit = Amount::from_sat(600);
    let with_cutthrough = false;

    let mut block_data_stream = client
        .get_block_data_for_range(start..=end, false, dust_limit, with_cutthrough)
        .await;

    while let Some(block_data) = block_data_stream.next().await {
        let block_data = block_data.unwrap();
        let block_identifier = block_data.block_identifier;
        let comp_index = block_data.comp_index;
        let spent = block_data.spent_outputs;
        println!("got block data for {:?}", block_identifier);
        println!("nuber of new txs: {}", comp_index.len());
        println!("nuber of spent outputs: {}", spent.len());
    }

    Ok(())
}
