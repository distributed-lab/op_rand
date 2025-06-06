use secp256k1::{PublicKey, ecdsa};

use crate::{
    commitment::{FirstRankCommitment, ThirdRankCommitment},
    errors::ProverError,
    traits::OpRandProof,
};

/// Prover trait for the OpRand protocol
pub trait OpRandProver {
    fn setup_challenger_circuit(&self) -> Result<u32, ProverError>;
    fn setup_acceptor_circuit(&self) -> Result<u32, ProverError>;

    /// Used by the challenger to generate a proof for the acceptor
    fn generate_challenger_proof(
        &self,
        first_rank_commitments: [FirstRankCommitment; 2],
        third_rank_commitments: [ThirdRankCommitment; 2],
        challenger_public_key: &PublicKey,
        challenger_public_key_hash: [u8; 20],
    ) -> Result<OpRandProof, ProverError>;
    /// Used by the acceptor to verify the proof from the challenger
    fn verify_challenger_proof(
        &self,
        third_rank_commitments: [ThirdRankCommitment; 2],
        challenger_public_key: &secp256k1::PublicKey,
        challenger_public_key_hash: [u8; 20],
        proof: &OpRandProof,
    ) -> Result<(), ProverError>;

    /// Used by the acceptor to generate a proof for the challenger
    fn generate_acceptor_proof(
        &self,
        acceptor_public_key: &PublicKey,
        acceptor_signature: &ecdsa::Signature,
        acceptor_public_key_hash: [u8; 20],
        third_rank_commitments: [ThirdRankCommitment; 2],
    ) -> Result<OpRandProof, ProverError>;
    /// Used by the challenger to verify the proof from the acceptor
    fn verify_acceptor_proof(
        &self,
        acceptor_public_key_hash: [u8; 20],
        third_rank_commitments: [ThirdRankCommitment; 2],
        proof: &OpRandProof,
    ) -> Result<(), ProverError>;
}
