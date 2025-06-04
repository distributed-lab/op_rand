use super::secp256k1::curve_params::Secp256k1;
use ripemd160::ripemd160;
use std::hash::sha256;

pub fn point_to_bytes(point: Secp256k1) -> [u8; 64] {
    let mut bytes = [0; 64];

    let x_bytes: [u8; 32] = point.x.to_be_bytes::<32>();
    let y_bytes: [u8; 32] = point.y.to_be_bytes::<32>();

    for i in 0..32 {
        bytes[i] = x_bytes[i];
        bytes[i + 32] = y_bytes[i];
    }

    bytes
}

pub fn point_to_address(point: Secp256k1) -> [u8; 20] {
    let bytes = point_to_bytes(point);
    let sha256_hash = sha256(bytes);
    let ripemd160_hash = ripemd160(sha256_hash);

    ripemd160_hash
}
