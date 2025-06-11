use eyre::OptionExt;
use lazy_static::lazy_static;
use serde_json::Value;
use std::fs;

/// Metadata for a circuit. Used to load the bytecode from a JSON file
pub struct CircuitMetadata {
    pub bytecode: String,
}

impl CircuitMetadata {
    /// Creates a new `CircuitMetadata` from a JSON file
    pub fn from_file(path: &str) -> eyre::Result<Self> {
        let content = fs::read_to_string(path)?;
        let json: Value = serde_json::from_str(&content)?;

        let bytecode = json
            .get("bytecode")
            .and_then(|v| v.as_str())
            .ok_or_eyre("Missing or invalid 'bytecode' field in JSON")?;

        Ok(Self {
            bytecode: bytecode.to_string(),
        })
    }
}

lazy_static! {
    /// Bytecode for the challenger circuit
    pub static ref CHALLENGER_CIRCUIT_BYTECODE: String = {
        CircuitMetadata::from_file(
            "circuits/crates/challenger_circuit/target/challenger_circuit.json",
        )
        .map(|metadata| metadata.bytecode)
        .unwrap_or_else(|e| {
            eprintln!("Failed to load challenger circuit bytecode: {}", e);
            String::new()
        })
    };

    /// Bytecode for the acceptor circuit
    pub static ref ACCEPTOR_CIRCUIT_BYTECODE: String = {
        CircuitMetadata::from_file("circuits/crates/acceptor_circuit/target/acceptor_circuit.json")
            .map(|metadata| metadata.bytecode)
            .unwrap_or_else(|e| {
                eprintln!("Failed to load acceptor circuit bytecode: {}", e);
                String::new()
            })
    };
}
