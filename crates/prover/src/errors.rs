#[derive(Debug, Clone, thiserror::Error)]
pub enum ProverError {
    #[error("Proof generation error: {0}")]
    ProofGenerationError(String),
    #[error("Proof verification error: {0}")]
    ProofVerificationError(String),
    #[error("Setup error: {0}")]
    SetupError(String),
    #[error("Invalid number of public signals: expected {expected}, got {got}")]
    InvalidNumberOfPublicSignals { expected: usize, got: usize },
    #[error("Invalid proof")]
    InvalidProof,
}
