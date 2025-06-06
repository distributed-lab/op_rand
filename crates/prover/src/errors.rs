#[derive(Debug, Clone)]
pub enum ProverError {
    ProofGenerationError(String),
    ProofVerificationError(String),
    SetupError(String),
    InvalidNumberOfPublicSignals { expected: usize, got: usize },
    InvalidProof,
}

impl std::fmt::Display for ProverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProofGenerationError(e) => write!(f, "Proof generation error: {}", e),
            Self::ProofVerificationError(e) => write!(f, "Proof verification error: {}", e),
            Self::SetupError(e) => write!(f, "Setup error: {}", e),
            Self::InvalidNumberOfPublicSignals { expected, got } => {
                write!(
                    f,
                    "Invalid number of public signals: expected {}, got {}",
                    expected, got
                )
            }
            Self::InvalidProof => write!(f, "Invalid proof"),
        }
    }
}
