use std::{fs, str::FromStr};

use crate::{
    actions::{accept_challenge::AcceptorData, create_challenge::PublicChallengerData},
    context::{Context, setup_progress_bar},
};
use clap::Args;
use color_eyre::eyre;
use color_eyre::eyre::ensure;
use op_rand_prover::{BarretenbergProver, OpRandProof, OpRandProver};
use op_rand_types::ThirdRankCommitment;

#[derive(Args, Debug)]
pub struct CompleteChallengeArgs {
    /// Path to the challenge JSON file
    #[clap(long, default_value = "challenger.json")]
    pub challenger_file: String,
    /// Path to the acceptor JSON file
    #[clap(long, default_value = "acceptor.json")]
    pub acceptor_file: String,
}

pub async fn run(
    CompleteChallengeArgs {
        challenger_file,
        acceptor_file,
    }: CompleteChallengeArgs,
    mut ctx: Context,
) -> eyre::Result<()> {
    let challenger_json = fs::read_to_string(&challenger_file)?;
    let challenger_data: PublicChallengerData = serde_json::from_str(&challenger_json)?;

    let acceptor_json = fs::read_to_string(&acceptor_file)?;
    let acceptor_data: AcceptorData = serde_json::from_str(&acceptor_json)?;

    ensure!(
        challenger_data.id == acceptor_data.id,
        "Challenger and acceptor IDs do not match"
    );

    let prover = BarretenbergProver::default();
    let acceptor_pubkey_hash = hex::decode(&acceptor_data.acceptor_pubkey_hash)?;

    let challenger_commitments = challenger_data
        .third_rank_commitments
        .iter()
        .map(|s| ThirdRankCommitment::from_str(s).expect("Failed to parse commitment"))
        .collect::<Vec<_>>();

    let acceptor_commitments = acceptor_data
        .third_rank_commitments
        .iter()
        .map(|s| ThirdRankCommitment::from_str(s).expect("Failed to parse commitment"))
        .collect::<Vec<_>>();

    ensure!(
        challenger_commitments
            .iter()
            .zip(acceptor_commitments.iter())
            .all(|(a, b)| a.inner() == b.inner()),
        "Third rank commitments do not match between challenger and acceptor"
    );

    let proof = hex::decode(&acceptor_data.proof)?;
    let vk = hex::decode(&acceptor_data.vk)?;
    let proof_data = OpRandProof::new(proof, vk);

    let pb = setup_progress_bar("Setting up acceptor circuit...".into());
    let prover_clone = prover.clone();
    tokio::task::spawn_blocking(move || {
        prover_clone
            .setup_acceptor_circuit()
            .expect("Failed to setup acceptor circuit")
    })
    .await
    .expect("Failed to spawn blocking task");
    pb.finish_with_message("Acceptor circuit is set up");

    prover
        .verify_acceptor_proof(
            acceptor_pubkey_hash
                .try_into()
                .expect("Failed to convert pubkey hash to array"),
            challenger_commitments
                .try_into()
                .expect("Failed to convert commitments to array"),
            &proof_data,
        )
        .expect("Failed to verify acceptor proof");

    // TODO: cosign the PSBT and broadcast the transaction
    let _esplora_client = ctx.esplora_client()?;

    let txid = "1471f9ac8f290e090cf4d5ea85ef582efc775f8837bce0426abc59b9b45630d0";

    println!("Challenge completed! Transaction ID: {}", txid);

    Ok(())
}
