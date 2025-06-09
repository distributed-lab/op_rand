use bitcoin::{
    Address, CompressedPublicKey, OutPoint, Txid,
    hashes::{Hash, ripemd160, sha256},
    secp256k1::rand::thread_rng,
};
use clap::Args;
use color_eyre::eyre;
use eyre::{OptionExt, ensure};
use op_rand_prover::{BarretenbergProver, Commitments, OpRandProver};
use serde::{Deserialize, Serialize};
use std::fs;
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

    /// Output file path for the challenge JSON
    #[clap(long, short, default_value = "challenger.json")]
    pub output: String,
}

#[derive(Serialize, Deserialize)]
pub struct ChallengeData {
    pub id: String,
    pub amount: u64,
    pub challenge_outpoint: OutPoint,
    pub third_rank_commitments: [String; 2],
    pub challenger_pubkey: String,
    pub challenger_pubkey_hash: String,
    pub proof: String,
    pub vk: String,
}

pub async fn run(
    CreateChallengeArgs {
        amount,
        commitments_count,
        output,
    }: CreateChallengeArgs,
    mut ctx: Context,
) -> eyre::Result<()> {
    ensure!(
        commitments_count == 2,
        "OP_RAND currently only supports 2 commitments"
    );

    let cfg = ctx.config()?;
    let esplora_client = ctx.esplora_client()?;
    let private_key = cfg.private_key;
    let secp = ctx.secp_ctx();
    let public_key = private_key.public_key(secp).inner;
    let address = Address::p2wpkh(
        &CompressedPublicKey::from_private_key(secp, &private_key).unwrap(),
        cfg.network,
    );

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

    let commitments =
        Commitments::generate(secp, &mut thread_rng()).expect("Failed to generate commitments");

    let first_rank_commitments = commitments.first_rank_commitments();
    let random_first_rank_commitment = commitments
        .pick_random_first_rank_commitment(&mut thread_rng())
        .ok_or_eyre("No first rank commitments available")?;

    let (_commitment_sk, commitment_pk) = random_first_rank_commitment.inner();
    let tweaked_pk = public_key
        .combine(&commitment_pk)
        .expect("Failed to combine keys");

    let third_rank_commitments = commitments.third_rank_commitments();

    let sha256_hash = sha256::Hash::hash(&tweaked_pk.serialize());
    let ripemd160_hash = ripemd160::Hash::hash(sha256_hash.as_byte_array());

    let pb = setup_progress_bar("Generating challenger proof...".into());
    let proof = prover
        .generate_challenger_proof(
            first_rank_commitments.to_owned(),
            third_rank_commitments.to_owned(),
            &public_key,
            ripemd160_hash.to_byte_array(),
        )
        .expect("Failed to generate challenger proof");
    pb.finish_with_message("Challenger proof generated");

    // TODO: This must be an actual deposit outpoint
    let challenge_outpoint = OutPoint::new(
        selected_utxos[0]
            .txid
            .parse::<Txid>()
            .expect("Failed to parse txid"),
        selected_utxos[0].vout,
    );

    let id = uuid::Uuid::new_v4().to_string();

    let challenge_output = ChallengeData {
        id,
        amount,
        challenge_outpoint,
        third_rank_commitments: [
            hex::encode(third_rank_commitments[0].inner().serialize()),
            hex::encode(third_rank_commitments[1].inner().serialize()),
        ],
        challenger_pubkey: hex::encode(public_key.serialize()),
        challenger_pubkey_hash: hex::encode(ripemd160_hash.to_byte_array()),
        proof: hex::encode(proof.proof()),
        vk: hex::encode(proof.vk()),
    };

    let json_output = serde_json::to_string_pretty(&challenge_output)?;
    fs::write(&output, json_output)?;

    println!("Challenge created successfully and saved to: {}", output);

    Ok(())
}
