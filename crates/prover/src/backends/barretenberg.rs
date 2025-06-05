use crate::{
    commitment::{FirstRankCommitment, ThirdRankCommitment},
    traits::OpRandProver,
};

pub struct BarretenbergProver;

impl OpRandProver for BarretenbergProver {
    fn generate_challenger_proof(
        &self,
        first_rank_commitments: [FirstRankCommitment; 2],
        third_rank_commitments: [ThirdRankCommitment; 2],
        challenger_public_key: &secp256k1::PublicKey,
        challenger_public_key_hash: [u8; 20],
    ) -> Result<Vec<u8>, crate::errors::ProverError> {
        todo!()
    }

    fn verify_challenger_proof(
        &self,
        proof: &[u8],
        verification_key: &secp256k1::PublicKey,
    ) -> Result<bool, crate::errors::ProverError> {
        todo!()
    }

    fn generate_acceptor_proof(
        &self,
        acceptor_public_key: &secp256k1::PublicKey,
        acceptor_signature: &secp256k1::ecdsa::Signature,
        acceptor_public_key_hash: [u8; 20],
        third_rank_commitments: [ThirdRankCommitment; 2],
    ) -> Result<Vec<u8>, crate::errors::ProverError> {
        todo!()
    }

    fn verify_acceptor_proof(
        &self,
        proof: &[u8],
        verification_key: &secp256k1::PublicKey,
    ) -> Result<bool, crate::errors::ProverError> {
        todo!()
    }
}
