use bitcoin::{
    Address, CompressedPublicKey, OutPoint,
    hashes::{Hash, ripemd160, sha256},
};
use clap::Args;
use color_eyre::eyre;
use eyre::ensure;
use op_rand_prover::{BarretenbergProver, Commitments, OpRandProver};
use secp256k1::Secp256k1;
use tokio;

use crate::{
    context::{Context, setup_progress_bar},
    util::select_utxos,
};

#[derive(Args, Debug)]
pub struct CreateChallengeArgs {
    /// Challenge amount in satoshis.
    #[clap(long, short)]
    pub amount: u64,

    /// Number of commitments to create.s
    #[clap(long, short, default_value = "2")]
    pub commitments_count: u32,
}

pub async fn run(
    CreateChallengeArgs {
        amount,
        commitments_count,
    }: CreateChallengeArgs,
    mut ctx: Context,
) -> eyre::Result<()> {
    ensure!(
        commitments_count == 2,
        "OP_RAND currently only supports 2 commitments"
    );

    let cfg = ctx.config()?;
    let private_key = cfg.private_key;
    let secp = ctx.secp_ctx();
    let address = Address::p2wpkh(
        &CompressedPublicKey::from_private_key(secp, &private_key).unwrap(),
        cfg.network,
    );

    let esplora_client = ctx.esplora_client()?;
    let utxos = esplora_client.get_utxos(&address.to_string()).await?;
    let selected_utxos = select_utxos(utxos, amount)?;

    let prover = BarretenbergProver::default();

    let pb = setup_progress_bar("Setting up challenger circuit...".into());
    let prover_clone = prover.clone();
    tokio::task::spawn_blocking(move || {
        prover_clone
            .setup_challenger_circuit()
            .expect("Failed to setup challenger circuit")
    })
    .await
    .expect("Failed to spawn blocking task");
    pb.finish_with_message("Challenger circuit is set up");

    let ctx = Secp256k1::new();
    let (sk, pk) = ctx.generate_keypair(&mut rand::rng());

    let commitments =
        Commitments::generate(&ctx, &mut rand::rng()).expect("Failed to generate commitments");

    let first_rank_commitments = commitments.first_rank_commitments();

    let (_, A1) = first_rank_commitments[0].inner();
    let PK_ = pk.combine(&A1).expect("Failed to combine keys");

    let third_rank_commitment = commitments.third_rank_commitments();

    let sha256_hash = sha256::Hash::hash(&PK_.serialize());
    let ripemd160_hash = ripemd160::Hash::hash(sha256_hash.as_byte_array());

    println!("Generating challenger proof");

    let pb = setup_progress_bar("Generating challenger proof...".into());
    let proof = prover
        .generate_challenger_proof(
            first_rank_commitments.to_owned(),
            third_rank_commitment.to_owned(),
            &pk,
            ripemd160_hash.to_byte_array(),
        )
        .expect("Failed to generate challenger proof");
    pb.finish_with_message("Challenger proof generated");

    let pb = setup_progress_bar("Verifying challenger proof...".into());
    prover
        .verify_challenger_proof(
            third_rank_commitment.to_owned(),
            &pk,
            ripemd160_hash.to_byte_array(),
            &proof,
        )
        .expect("Failed to verify challenger proof");
    pb.finish_with_message("Challenger proof is valid");
    Ok(())
}
