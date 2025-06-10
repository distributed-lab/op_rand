use crate::{
    actions::create_challenge::PublicChallengerData,
    context::{Context, setup_progress_bar},
    util::select_utxos,
};
use bitcoin::{
    Address, CompressedPublicKey,
    hashes::{Hash, ripemd160, sha256},
    secp256k1::{Message, PublicKey, SecretKey},
};
use clap::Args;
use color_eyre::eyre;
use op_rand_prover::{BarretenbergProver, OpRandProof, OpRandProver, ThirdRankCommitment};
use serde::{Deserialize, Serialize};
use std::{fs, str::FromStr};
use tokio;

#[derive(Args, Debug)]
pub struct AcceptChallengeArgs {
    /// Path to the challenge JSON file
    #[clap(long, default_value = "challenger.json")]
    pub challenge_file: String,

    /// Output file path for the acceptor JSON
    #[clap(long, default_value = "acceptor.json")]
    pub output: String,

    /// Number of the commitment to accept
    #[clap(long)]
    pub selected_commitment: u32,
}

#[derive(Serialize, Deserialize)]
pub struct AcceptorData {
    pub id: String,
    pub acceptor_pubkey_hash: String,
    pub third_rank_commitments: [String; 2],
    pub psbt: String,
    pub proof: String,
    pub vk: String,
}

pub async fn run(
    AcceptChallengeArgs {
        challenge_file,
        output,
        selected_commitment,
    }: AcceptChallengeArgs,
    mut ctx: Context,
) -> eyre::Result<()> {
    let challenge_json = fs::read_to_string(&challenge_file)?;
    let challenge_data: PublicChallengerData = serde_json::from_str(&challenge_json)?;

    let prover = BarretenbergProver::default();
    let pb = setup_progress_bar("Setting up challenge circuit...".into());
    let prover_clone = prover.clone();
    tokio::task::spawn_blocking(move || {
        prover_clone
            .setup_challenger_circuit()
            .expect("Failed to setup challenger circuit")
    })
    .await
    .expect("Failed to spawn blocking task");
    pb.finish_with_message("Challenger circuit is set up");

    let commitments: [ThirdRankCommitment; 2] = challenge_data
        .third_rank_commitments
        .iter()
        .map(|s| ThirdRankCommitment::from_str(s).expect("Failed to parse commitment"))
        .collect::<Vec<_>>()
        .try_into()
        .expect("Failed to convert commitments to array");

    let challenger_pubkey = PublicKey::from_str(&challenge_data.challenger_pubkey)
        .expect("Failed to parse challenger public key");
    let challenger_pubkey_hash = hex::decode(&challenge_data.challenger_pubkey_hash)
        .expect("Failed to decode challenger public key hash")
        .try_into()
        .expect("Failed to convert challenger public key hash to array");
    let proof = hex::decode(&challenge_data.proof).expect("Failed to decode proof");
    let vk = hex::decode(&challenge_data.vk).expect("Failed to decode vk");
    let proof_data = OpRandProof::new(proof, vk);

    prover
        .verify_challenger_proof(
            commitments.clone(),
            &challenger_pubkey,
            challenger_pubkey_hash,
            &proof_data,
        )
        .expect("Invalid challenger proof");

    let cfg = ctx.config()?;
    let private_key = cfg.private_key;
    let esplora_client = ctx.esplora_client()?;
    let secp = ctx.secp_ctx();
    let public_key = private_key.public_key(secp);
    let address = Address::p2wpkh(
        &CompressedPublicKey::from_private_key(secp, &private_key).unwrap(),
        cfg.network,
    );

    let utxos = esplora_client.get_utxos(&address.to_string()).await?;
    // TODO: use for PSBT construction
    let _selected_utxos = select_utxos(utxos, challenge_data.amount)?;

    let selected_commitment = &commitments[selected_commitment as usize];

    let pk_combined = public_key
        .inner
        .combine(&selected_commitment.inner())
        .expect("Failed to combine keys");

    let sha256_hash = sha256::Hash::hash(&pk_combined.serialize());
    let ripemd160_hash = ripemd160::Hash::hash(sha256_hash.as_byte_array());

    let message =
        Message::from_digest(sha256::Hash::hash(ripemd160_hash.as_byte_array()).to_byte_array());
    let sk = SecretKey::from_slice(&private_key.to_bytes()).expect("Failed to parse private key");

    let sig = secp.sign_ecdsa(&message, &sk);

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
    let pb = setup_progress_bar("Generating acceptor proof...".into());
    let proof = prover
        .generate_acceptor_proof(
            &public_key.inner,
            &sig,
            ripemd160_hash.to_byte_array(),
            commitments
                .try_into()
                .expect("Failed to convert commitments to array"),
        )
        .expect("Failed to generate acceptor proof");
    pb.finish_with_message("Acceptor proof generated");

    let acceptor_output = AcceptorData {
        id: challenge_data.id,
        proof: hex::encode(proof.proof()),
        vk: hex::encode(proof.vk()),
        acceptor_pubkey_hash: hex::encode(ripemd160_hash),
        third_rank_commitments: challenge_data.third_rank_commitments,
        // TODO: Add PSBT
        psbt: "".to_string(),
    };

    let acceptor_json = serde_json::to_string(&acceptor_output)?;
    fs::write(&output, acceptor_json)?;

    Ok(())
}
