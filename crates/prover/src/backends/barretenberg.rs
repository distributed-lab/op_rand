use noir_rs::barretenberg::srs::setup_srs;
use noir_rs::barretenberg::{prove::prove_ultra_honk, verify::verify_ultra_honk};
use noir_rs::witness::from_vec_str_to_witness_map;

use crate::{
    bytecode::{ACCEPTOR_CIRCUIT_BYTECODE, CHALLENGER_CIRCUIT_BYTECODE},
    commitment::{FirstRankCommitment, ThirdRankCommitment},
    traits::{OpRandProof, OpRandProver},
};

#[derive(Debug, Clone, Default)]
pub struct BarretenbergProver {
    is_recursive: bool,
}

impl BarretenbergProver {
    pub fn new(is_recursive: bool) -> Self {
        Self { is_recursive }
    }
}

impl OpRandProver for BarretenbergProver {
    fn setup_challenger_circuit(&self) -> Result<u32, crate::errors::ProverError> {
        setup_srs(&CHALLENGER_CIRCUIT_BYTECODE, None, self.is_recursive)
            .map_err(|e| crate::errors::ProverError::SetupError(e.to_string()))
    }

    fn setup_acceptor_circuit(&self) -> Result<u32, crate::errors::ProverError> {
        setup_srs(&ACCEPTOR_CIRCUIT_BYTECODE, None, self.is_recursive)
            .map_err(|e| crate::errors::ProverError::SetupError(e.to_string()))
    }

    fn generate_challenger_proof(
        &self,
        first_rank_commitments: [FirstRankCommitment; 2],
        third_rank_commitments: [ThirdRankCommitment; 2],
        challenger_public_key: &secp256k1::PublicKey,
        challenger_public_key_hash: [u8; 20],
    ) -> Result<OpRandProof, crate::errors::ProverError> {
        todo!()
    }

    fn verify_challenger_proof(
        &self,
        proof: &OpRandProof,
    ) -> Result<bool, crate::errors::ProverError> {
        todo!()
    }

    fn generate_acceptor_proof(
        &self,
        acceptor_public_key: &secp256k1::PublicKey,
        acceptor_signature: &secp256k1::ecdsa::Signature,
        acceptor_public_key_hash: [u8; 20],
        third_rank_commitments: [ThirdRankCommitment; 2],
    ) -> Result<OpRandProof, crate::errors::ProverError> {
        // Extract the x and y coordinates from the acceptor's public key
        let pk_coords = acceptor_public_key.serialize_uncompressed();
        let pk_x = &pk_coords[1..33]; // Skip the first byte (0x04)
        let pk_y = &pk_coords[33..65];

        let signature = acceptor_signature.serialize_compact();

        // Extract coordinates from third rank commitments
        let h1_coords = third_rank_commitments[0].inner().serialize_uncompressed();
        let h1_x = &h1_coords[1..33];
        let h1_y = &h1_coords[33..65];

        let h2_coords = third_rank_commitments[1].inner().serialize_uncompressed();
        let h2_x = &h2_coords[1..33];
        let h2_y = &h2_coords[33..65];

        let mut witness_inputs: Vec<String> = Vec::new();

        // Private inputs first (order matters - must match circuit main function)
        witness_inputs.extend(bytes_to_string_array(pk_x)); // PK_x (32 bytes)
        witness_inputs.extend(bytes_to_string_array(pk_y)); // PK_y (32 bytes)
        witness_inputs.extend(bytes_to_string_array(&signature)); // S (64 bytes)

        // Public inputs
        witness_inputs.extend(bytes_to_string_array(h1_x)); // H1_x (32 bytes)
        witness_inputs.extend(bytes_to_string_array(h1_y)); // H1_y (32 bytes)
        witness_inputs.extend(bytes_to_string_array(h2_x)); // H2_x (32 bytes)
        witness_inputs.extend(bytes_to_string_array(h2_y)); // H2_y (32 bytes)
        witness_inputs.extend(bytes_to_string_array(&acceptor_public_key_hash)); // ADDR (20 bytes)

        let witness_input_refs = witness_inputs
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>();

        let initial_witness = from_vec_str_to_witness_map(witness_input_refs)
            .map_err(|e| crate::errors::ProverError::ProofGenerationError(e.to_string()))?;

        let (proof, vk) = prove_ultra_honk(
            &ACCEPTOR_CIRCUIT_BYTECODE,
            initial_witness,
            self.is_recursive,
        )
        .map_err(|e| crate::errors::ProverError::ProofGenerationError(e.to_string()))?;

        Ok(OpRandProof::new(proof, vk))
    }

    fn verify_acceptor_proof(
        &self,
        proof: &OpRandProof,
    ) -> Result<bool, crate::errors::ProverError> {
        verify_ultra_honk(proof.proof().to_vec(), proof.vk().to_vec())
            .map_err(|e| crate::errors::ProverError::ProofVerificationError(e.to_string()))
    }
}

/// Helper function to convert bytes to individual string values
fn bytes_to_string_array(bytes: &[u8]) -> Vec<String> {
    bytes.iter().map(|b| b.to_string()).collect()
}
