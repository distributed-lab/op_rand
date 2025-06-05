#[derive(Debug, Clone)]
pub enum ProverError {
    ProofGenerationError(String),
    ProofVerificationError(String),
    SetupError(String),
}

impl std::fmt::Display for ProverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProofGenerationError(e) => write!(f, "Proof generation error: {}", e),
            Self::ProofVerificationError(e) => write!(f, "Proof verification error: {}", e),
            Self::SetupError(e) => write!(f, "Setup error: {}", e),
        }
    }
}
