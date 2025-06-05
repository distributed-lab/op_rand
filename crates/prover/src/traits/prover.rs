use crate::errors::ProverError;

trait Prove {
    fn generate_challenge_proof(&self, challenge: &[u8]) -> Result<Vec<u8>, ProverError>;
    fn verify_challenge_proof(&self, challenge: &[u8], proof: &[u8]) -> Result<bool, ProverError>;

    fn generate_acceptor_proof(&self, challenge: &[u8]) -> Result<Vec<u8>, ProverError>;
    fn verify_acceptor_proof(&self, challenge: &[u8], proof: &[u8]) -> Result<bool, ProverError>;
}
