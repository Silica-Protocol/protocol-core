use silica_models::crypto::{ChertKeyPair, utils};

fn main() -> anyhow::Result<()> {
    println!("Testing blockchain core crypto module...");

    // Test key generation
    let keypair = ChertKeyPair::generate_ed25519()?;
    println!("✓ Ed25519 key generation works");

    // Test address generation
    let address = keypair.address("ACCOUNT");
    println!("✓ Address generation: {}", address);

    // Verify address format
    if address.starts_with("0x") && address.len() == 42 {
        println!("✓ Address format: 0x prefixed, 42 characters");
    } else {
        eprintln!("✗ Address format incorrect: {}", address);
        return Err(anyhow::anyhow!("Address format error"));
    }

    // Test signing
    let data = b"test transaction";
    let signature = keypair.sign(data)?;
    let is_valid = keypair.verify(data, &signature)?;

    if is_valid {
        println!("✓ Signature verification works");
    } else {
        eprintln!("✗ Signature verification failed");
        return Err(anyhow::anyhow!("Signature verification failed"));
    }

    // Test address verification utility
    let addr_valid = utils::verify_address(&address, &keypair.public_key, "ACCOUNT");
    if addr_valid {
        println!("✓ Address verification utility works");
    } else {
        eprintln!("✗ Address verification utility failed");
        return Err(anyhow::anyhow!("Address verification failed"));
    }

    println!("✓ Blockchain core crypto module tests passed");
    Ok(())
}
