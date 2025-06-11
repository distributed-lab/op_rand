mod prover;

pub use prover::OpRandProver;

/// op_rand proof containing either a challenger or acceptor proof
pub struct OpRandProof {
    proof: Vec<u8>,
    vk: Vec<u8>,
}

impl OpRandProof {
    /// Creates a new `OpRandProof`
    pub fn new(proof: Vec<u8>, vk: Vec<u8>) -> Self {
        Self { proof, vk }
    }

    /// Returns the proof
    pub fn proof(&self) -> &[u8] {
        &self.proof
    }

    /// Returns the verification key
    pub fn vk(&self) -> &[u8] {
        &self.vk
    }

    /// Extracts the public signals from the proof
    pub fn extract_public_signals(&self, n_signals: usize) -> Vec<&[u8]> {
        let proof = self.proof();
        let mut result = Vec::new();

        // Extract n_signals number of 32-byte chunks as public signals
        for i in 0..n_signals {
            let start = i * 32;
            let end = start + 32;

            if end <= proof.len() {
                let chunk = &proof[start..end];
                result.push(chunk);
            }
        }

        result
    }
}
