mod prover;

pub use prover::OpRandProver;

pub struct OpRandProof {
    proof: Vec<u8>,
    vk: Vec<u8>,
}

impl OpRandProof {
    pub fn new(proof: Vec<u8>, vk: Vec<u8>) -> Self {
        Self { proof, vk }
    }

    pub fn proof(&self) -> &[u8] {
        &self.proof
    }

    pub fn vk(&self) -> &[u8] {
        &self.vk
    }

    /// Processes a binary proof file and converts it to JSON format
    ///
    /// # Arguments
    /// * `n_signals` - Number of 32-byte signal chunks to extract
    ///
    /// # Returns
    /// * `Vec<&[u8]>` - Public signals
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
