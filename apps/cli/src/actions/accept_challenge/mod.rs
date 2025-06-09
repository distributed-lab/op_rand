use bitcoin::{
    Address, CompressedPublicKey, OutPoint,
    hashes::{Hash, ripemd160, sha256},
};
use clap::Args;
use color_eyre::eyre;
use op_rand_prover::{BarretenbergProver, Commitments, OpRandProver};
use secp256k1::{Message, Secp256k1};

use crate::util::parse_outpoint;
use crate::{
    context::{Context, setup_progress_bar},
    util::select_utxos,
};
#[derive(Args, Debug)]
pub struct AcceptChallengeArgs {
    /// Challenge outpoint
    #[clap(long, short, num_args = 1.., value_parser = parse_outpoint)]
    pub outpoint: OutPoint,

    /// Challenge amount in satoshis.
    #[clap(long, short)]
    pub amount: u64,
}

pub async fn run(
    AcceptChallengeArgs { outpoint, amount }: AcceptChallengeArgs,
    mut ctx: Context,
) -> eyre::Result<()> {
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

    let ctx = Secp256k1::new();
    let (sk, pk) = ctx.generate_keypair(&mut rand::rng());

    let commitments =
        Commitments::generate(&ctx, &mut rand::rng()).expect("Failed to generate commitments");

    let third_rank_commitment = commitments.third_rank_commitments();

    let pk_combined = pk
        .combine(&third_rank_commitment[0].inner())
        .expect("Failed to combine keys");

    let sha256_hash = sha256::Hash::hash(&pk_combined.serialize());
    let ripemd160_hash = ripemd160::Hash::hash(sha256_hash.as_byte_array());

    let message =
        Message::from_digest(sha256::Hash::hash(ripemd160_hash.as_byte_array()).to_byte_array());

    let sig = ctx.sign_ecdsa(message, &sk);

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
            &pk,
            &sig,
            ripemd160_hash.to_byte_array(),
            third_rank_commitment.to_owned(),
        )
        .expect("Failed to generate acceptor proof");
    pb.finish_with_message("Acceptor proof generated");

    let pb = setup_progress_bar("Verifying acceptor proof...".into());
    prover
        .verify_acceptor_proof(
            ripemd160_hash.to_byte_array(),
            third_rank_commitment.to_owned(),
            &proof,
        )
        .expect("Failed to verify acceptor proof");
    pb.finish_with_message("Acceptor proof is valid");

    Ok(())
}
