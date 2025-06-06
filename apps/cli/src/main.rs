use std::time::Instant;

use op_rand_prover::{BarretenbergProver, Commitments, OpRandProver};
use secp256k1::{
    Message, Secp256k1,
    hashes::{Hash, ripemd160, sha256},
};

fn main() {
    check_acceptor_proof();
    // check_challenger_proof();
}

fn check_acceptor_proof() {
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

    prover
        .setup_acceptor_circuit()
        .expect("Failed to setup acceptor circuit");

    let now = Instant::now();

    let proof = prover
        .generate_acceptor_proof(
            &pk,
            &sig,
            ripemd160_hash.to_byte_array(),
            third_rank_commitment.to_owned(),
        )
        .expect("Failed to generate acceptor proof");

    println!(
        "Is valid: {}",
        prover
            .verify_acceptor_proof(
                ripemd160_hash.to_byte_array(),
                third_rank_commitment.to_owned(),
                &proof,
            )
            .expect("Failed to verify acceptor proof")
    );

    println!("Time taken: {:?}", now.elapsed());
}

fn check_challenger_proof() {
    let prover = BarretenbergProver::default();

    prover
        .setup_challenger_circuit()
        .expect("Failed to setup challenger circuit");

    println!("Challenger circuit is set up");

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

    let now = Instant::now();

    let proof = prover
        .generate_challenger_proof(
            first_rank_commitments.to_owned(),
            third_rank_commitment.to_owned(),
            &pk,
            ripemd160_hash.to_byte_array(),
        )
        .expect("Failed to generate challenger proof");

    // println!(
    //     "Is valid: {}",
    //     prover
    //         .verify_challenger_proof(&proof)
    //         .expect("Failed to verify challenger proof")
    // );

    println!("Time taken: {:?}", now.elapsed().as_secs());
}
