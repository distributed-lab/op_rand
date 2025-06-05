use super::secp256k1::curve_params::Secp256k1;
use ripemd160::ripemd160;
use std::hash::sha256;

pub fn point_to_bytes(point: Secp256k1) -> [u8; 33] {
    let mut bytes = [0; 33];

    // Determine the prefix byte based on y coordinate parity
    // 0x02 if y is even, 0x03 if y is odd
    let y_is_odd = point.y.to_be_bytes::<32>()[31] & 1;
    bytes[0] = if y_is_odd == 1 { 0x03 } else { 0x02 };

    // Add the x-coordinate (32 bytes)
    let x_bytes: [u8; 32] = point.x.to_be_bytes::<32>();
    for i in 0..32 {
        bytes[i + 1] = x_bytes[i];
    }

    bytes
}

pub fn point_to_address(point: Secp256k1) -> [u8; 20] {
    let bytes = point_to_bytes(point);
    let sha256_hash = sha256(bytes);
    let ripemd160_hash = ripemd160(sha256_hash);

    ripemd160_hash
}
