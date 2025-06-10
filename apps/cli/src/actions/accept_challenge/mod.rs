use crate::{
    actions::create_challenge::PublicChallengerData,
    context::{Context, setup_progress_bar},
    ui::{self, CHAIN, CHECK, GEAR, KEY, SHIELD},
    util::{FEES, MIN_CHANGE, select_utxos},
};
use base64::{Engine as _, engine::general_purpose};
use bitcoin::{
    Address, Amount, CompressedPublicKey, OutPoint, Txid,
    absolute::{Height, LockTime},
    hashes::{Hash, ripemd160, sha256},
    secp256k1::{Message, PublicKey, SecretKey},
};
use clap::Args;
use color_eyre::eyre;
use console::style;
use op_rand_prover::{BarretenbergProver, OpRandProof, OpRandProver};
use op_rand_types::ThirdRankCommitment;
use serde::{Deserialize, Serialize};
use std::{fs, str::FromStr};

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
    pub challenge_output_witness_script: String,
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
    println!(
        "{}",
        ui::header("                        🤝 ACCEPTING CHALLENGE 🤝")
    );

    let challenge_json = fs::read_to_string(&challenge_file)?;
    let challenge_data: PublicChallengerData = serde_json::from_str(&challenge_json)?;

    println!(
        "\n{} {} {}",
        CHECK,
        style("Challenge loaded:").bold().green(),
        style(&challenge_data.id).bright().white()
    );

    println!(
        "{} {} {}",
        CHECK,
        style("Challenge amount:").bold().yellow(),
        ui::format_bitcoin_amount(challenge_data.amount)
    );

    let prover = BarretenbergProver::default();
    let pb = setup_progress_bar("Setting up challenge circuit...".into());
    let prover_clone = prover.clone();
    tokio::task::spawn_blocking(move || {
        prover_clone
            .setup_challenger_circuit()
            .expect("Failed to setup challenger circuit")
    })
    .await?;
    pb.finish_with_message("Challenger circuit is set up");

    let commitments: [ThirdRankCommitment; 2] = challenge_data
        .third_rank_commitments
        .iter()
        .map(|s| ThirdRankCommitment::from_str(s))
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .map_err(|_| eyre::eyre!("Expected exactly 2 commitments"))?;

    let challenger_pubkey = PublicKey::from_str(&challenge_data.challenger_pubkey)?;
    let challenger_pubkey_hash = hex::decode(&challenge_data.challenger_pubkey_hash)?
        .try_into()
        .map_err(|_| eyre::eyre!("Failed to convert challenger public key hash to array"))?;
    let proof = hex::decode(&challenge_data.proof)?;
    let vk = hex::decode(&challenge_data.vk)?;
    let proof_data = OpRandProof::new(proof, vk);

    println!(
        "\n{} {}",
        SHIELD,
        style("Verifying challenger proof...").bold().blue()
    );

    prover.verify_challenger_proof(
        commitments.clone(),
        &challenger_pubkey,
        challenger_pubkey_hash,
        &proof_data,
    )?;

    println!(
        "{} {}",
        CHECK,
        style("Challenger proof verified successfully!")
            .bold()
            .green()
    );

    let cfg = ctx.config()?;
    let private_key = cfg.private_key;
    let esplora_client = ctx.esplora_client()?;
    let tx_builder = ctx.transaction_builder()?;
    let secp = ctx.secp_ctx();
    let public_key = private_key.public_key(secp);
    let address = Address::p2wpkh(
        &CompressedPublicKey::from_private_key(secp, &private_key).unwrap(),
        cfg.network,
    );

    println!(
        "\n{} {}",
        GEAR,
        style("Preparing transaction inputs...").bold().blue()
    );

    let utxos = esplora_client.get_utxos(&address.to_string()).await?;
    let selected_utxos = select_utxos(utxos, challenge_data.amount + FEES)?;

    let selected_commitment_index = selected_commitment as usize;
    let selected_commitment = &commitments[selected_commitment_index];

    println!(
        "{} {} {}",
        CHECK,
        style("Selected commitment:").bold().yellow(),
        style((selected_commitment_index + 1).to_string())
            .bright()
            .cyan()
    );

    let inputs_sum = selected_utxos.iter().map(|utxo| utxo.value).sum::<u64>();
    let change_amount = inputs_sum - challenge_data.amount - FEES;
    let change = if change_amount < MIN_CHANGE {
        None
    } else {
        Some(Amount::from_sat(change_amount))
    };
    let prevouts = selected_utxos
        .iter()
        .map(|utxo| {
            Ok((
                OutPoint::new(Txid::from_str(&utxo.txid)?, utxo.vout),
                Amount::from_sat(utxo.value),
            ))
        })
        .collect::<Result<Vec<_>, eyre::Error>>()?;

    println!(
        "\n{} {}",
        CHAIN,
        style("Building challenge transaction...").bold().blue()
    );

    let (challenge_script, psbt) = tx_builder.build_challenge_tx(
        &challenger_pubkey.into(),
        challenge_data.deposit_outpoint,
        selected_commitment.to_owned(),
        LockTime::Blocks(Height::from_consensus(challenge_data.locktime)?),
        Amount::from_sat(challenge_data.amount),
        prevouts,
        change,
        None,
    )?;

    let pk_combined = public_key.inner.combine(&selected_commitment.inner())?;

    let sha256_hash = sha256::Hash::hash(&pk_combined.serialize());
    let ripemd160_hash = ripemd160::Hash::hash(sha256_hash.as_byte_array());

    let message =
        Message::from_digest(sha256::Hash::hash(ripemd160_hash.as_byte_array()).to_byte_array());
    let sk = SecretKey::from_slice(&private_key.to_bytes())?;

    let sig = secp.sign_ecdsa(&message, &sk);

    let pb = setup_progress_bar("Setting up acceptor circuit...".into());
    let prover_clone = prover.clone();
    tokio::task::spawn_blocking(move || {
        prover_clone
            .setup_acceptor_circuit()
            .expect("Failed to setup acceptor circuit")
    })
    .await?;
    pb.finish_with_message("Acceptor circuit is set up");
    let pb = setup_progress_bar("Generating acceptor proof...".into());
    let proof = prover.generate_acceptor_proof(
        &public_key.inner,
        &sig,
        ripemd160_hash.to_byte_array(),
        commitments,
    )?;
    pb.finish_with_message("Acceptor proof generated");

    println!(
        "\n{} {}",
        KEY,
        style("Generating acceptor data...").bold().blue()
    );

    let acceptor_output = AcceptorData {
        id: challenge_data.id.clone(),
        proof: hex::encode(proof.proof()),
        vk: hex::encode(proof.vk()),
        acceptor_pubkey_hash: hex::encode(ripemd160_hash),
        third_rank_commitments: challenge_data.third_rank_commitments,
        psbt: general_purpose::STANDARD.encode(psbt.serialize()),
        challenge_output_witness_script: challenge_script.to_hex_string(),
    };

    let acceptor_json = serde_json::to_string(&acceptor_output)?;
    fs::write(&output, acceptor_json)?;

    println!("{}", ui::success_footer("Challenge accepted successfully!"));
    println!(
        "   {} {} {}",
        style("Acceptor data saved to:").dim(),
        style(&output).bright().white().bold(),
        style("📄").dim()
    );
    println!(
        "   {} {}",
        style("Challenge ID:").dim(),
        style(&challenge_data.id).bright().cyan()
    );

    Ok(())
}
