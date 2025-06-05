pub enum ProverError {
    InvalidProof,
    InvalidSignature,
}

impl std::fmt::Display for ProverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidProof => write!(f, "Invalid proof"),
            Self::InvalidSignature => write!(f, "Invalid signature"),
        }
    }
}
