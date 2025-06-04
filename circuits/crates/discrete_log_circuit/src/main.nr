fn main(
    // First rank commitments
    a1: Field,
    a2: Field,
    // Second rank commitments
    H1_x: pub [u8; 32],
    H1_y: pub [u8; 32],
    H2_x: pub [u8; 32],
    H2_y: pub [u8; 32],
    // Challenger's public key
    PK_x: pub [u8; 32],
    PK_y: pub [u8; 32],
    // Generator point
    G_x: pub [u8; 32],
    G_y: pub [u8; 32],
    // Challenger's Bitcoin address.
    // It's either hash160(PK+A1) or hash160(PK+A2)
    ADDR: pub [u8; 20],
) {}

#[test]
fn test_main() {}
