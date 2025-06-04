use super::secp256k1::Secp256k1;
use ripemd160::ripemd160;
use std::hash::sha256;

pub fn point_to_bytes(point: Secp256k1) -> [u8; 64] {
    let mut bytes = [0; 64];
    let x_limbs = point.x.get_limbs_slice();

    let mut byte_index = 0;

    // Process x coordinate limbs (first 32 bytes)
    for limb in x_limbs {
        let limb_bytes = limb.to_be_bytes();
        let limb_len = limb_bytes.len();

        // Copy limb bytes to the result array
        for i in 0..limb_len {
            if byte_index < 32 {
                bytes[byte_index] = limb_bytes[i];
                byte_index += 1;
            }
        }
    }

    // Reset index for y coordinate (starts at byte 32)
    byte_index = 32;
    let y_limbs = point.y.get_limbs_slice();

    // Process y coordinate limbs (next 32 bytes)
    for limb in y_limbs {
        let limb_bytes = limb.to_be_bytes();
        let limb_len = limb_bytes.len();

        // Copy limb bytes to the result array
        for i in 0..limb_len {
            if byte_index < 64 {
                bytes[byte_index] = limb_bytes[i];
                byte_index += 1;
            }
        }
    }

    bytes
}

pub fn point_to_address(point: Secp256k1) -> [u8; 20] {
    let bytes = point_to_bytes(point);
    let sha256_hash = sha256(bytes);
    let ripemd160_hash = ripemd160(sha256_hash);
    ripemd160_hash
}
