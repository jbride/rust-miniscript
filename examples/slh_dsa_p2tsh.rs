//! SLH-DSA P2TSH Example
//!
//! This example demonstrates how to create a P2TSH descriptor with SLH-DSA
//! post-quantum cryptography support using OP_SUCCESS127.
//!
//! The script created is: <32-byte-slh-dsa-key> OP_SUCCESS127 (0x7f)
//!
//! This example demonstrates:
//! 1. Creating P2TSH addresses with SLH-DSA keys (miniscript vs bitcoin crate)
//! 2. Multi-leaf taptrees combining Schnorr and SLH-DSA
//! 3. **NEW: Custom Satisfier implementation for automatic witness building**
//! 4. **NEW: Using the extended Satisfier trait with lookup_slh_dsa_sig()**
//!
//! This requires:
//! - Modified bitcoin crate with SLH-DSA support via bitcoinpqc
//! - Bitcoin Core with PQC support for validation

use std::str::FromStr;
use std::collections::HashMap;

use bitcoin::{Network, XOnlyPublicKey, ScriptBuf, Address};
use bitcoin::p2tsh::{P2tshScriptBuf, P2tshBuilder, P2tshSpendInfo};
use bitcoin::taproot::{TapNodeHash, TapTree as BitcoinTapTree, TapLeafHash};
use bitcoin::hex::DisplayHex;
use miniscript::descriptor::{Tsh, TapTree, SlhDsaPublicKey};
use miniscript::{Miniscript, Tap, Satisfier, MiniscriptKey, ToPublicKey, NoSecp256k1Key};
use miniscript::plan::AssetProvider;

// Add bitcoinpqc imports
use bitcoinpqc::{generate_keypair, Algorithm, KeyPair};
use bitcoin::secp256k1::rand::{thread_rng, RngCore};
use bitcoin::secp256k1::Secp256k1;

fn main() {
    println!("=== SLH-DSA P2TSH Example ===\n");

    // Generate SLH-DSA keypair using bitcoinpqc
    let random_data = get_random_bytes(128);
    let slh_dsa_keypair: KeyPair = generate_keypair(Algorithm::SLH_DSA_128S, &random_data)
        .expect("Failed to generate SLH-DSA-128S keypair");
    let slh_dsa_pubkey_bytes = &slh_dsa_keypair.public_key.bytes[..32];
    
    println!("SLH-DSA Public Key (hex): {}", slh_dsa_pubkey_bytes.to_lower_hex_string());
    
    // Convert SLH-DSA bytes to SlhDsaPublicKey for use with miniscript
    // This allows both miniscript and low-level bitcoin crate to use the SAME key
    let slh_dsa_key = SlhDsaPublicKey::from_slice(slh_dsa_pubkey_bytes)
        .expect("Failed to create SlhDsaPublicKey from SLH-DSA bytes");
    
    println!("SLH-DSA key as SlhDsaPublicKey: {}", slh_dsa_key);
    
    // Generate Schnorr keypair
    let secp = Secp256k1::new();
    let schnorr_xonly_pub_key = generate_demo_schnorr_key(&secp);
    println!("\nSchnorr key: {}", schnorr_xonly_pub_key);

    // Demonstrate single-leaf P2TSH using miniscript with SAME SLH-DSA key
    let address_miniscript = single_leaf_via_miniscript(slh_dsa_key);
    
    // Demonstrate single-leaf P2TSH using low-level bitcoin crate with SAME SLH-DSA key
    let address_bitcoin_slh = single_leaf_via_bitcoin_crate(slh_dsa_pubkey_bytes);
    
    // Compare the two approaches
    compare_single_leaf_addresses(address_miniscript, address_bitcoin_slh);
    
    print_spending_requirements();
    
    demonstrate_multi_leaf_p2tsh(&secp, slh_dsa_key);
    
    demonstrate_satisfier_trait(&slh_dsa_keypair, slh_dsa_key);

}

/// Generate a demo Schnorr key for miniscript demonstrations
/// (Required because SLH-DSA keys are not secp256k1 curve points)
fn generate_demo_schnorr_key(secp: &Secp256k1<bitcoin::secp256k1::All>) -> XOnlyPublicKey {
    let (_, public_key) = secp.generate_keypair(&mut thread_rng());
    let (x_only_pubkey, _) = public_key.x_only_public_key();
    XOnlyPublicKey::from_slice(&x_only_pubkey.serialize())
        .expect("Failed to parse public key")
}

/// Demonstrate single-leaf P2TSH & SLH-DSA using miniscript high-level API
fn single_leaf_via_miniscript(slh_dsa_key: SlhDsaPublicKey) -> Address {
    println!("\n=== Single-Leaf P2TSH via Miniscript ===");
    
    // Create a Miniscript that compiles to: <32-byte-slh-dsa-key> OP_SUCCESS127
    //
    // Note: NoSecp256k1Key is a placeholder type parameter for Miniscript<Pk, Ctx>
    // - The slh_dsa_pk() method uses the concrete SlhDsaPublicKey type internally
    // - NoSecp256k1Key satisfies the MiniscriptKey trait requirement without providing
    //   actual secp256k1 key functionality
    // - This makes the code self-documenting: it clearly indicates this miniscript
    //   contains only post-quantum keys, no secp256k1 keys
    let ms: Miniscript<NoSecp256k1Key, Tap> = Miniscript::slh_dsa_pk(slh_dsa_key);
    
    println!("\nMiniscript: {}", ms);
    println!("Miniscript (debug): {:?}", ms);
    
    // Get the compiled script
    let script = ms.encode();
    println!("\nCompiled Script: {}", script);
    println!("Script hex: {}", script.to_hex_string());
    println!("Script size: {} bytes", script.len());

    // Create a TapTree with this single leaf
    let tap_tree = TapTree::leaf(ms);
    println!("\nTapTree created with 1 leaf");

    // Create a P2TSH descriptor
    let tsh = Tsh::new(Some(tap_tree))
        .expect("Failed to create Tsh descriptor");

    println!("\nP2TSH Descriptor: {}", tsh);

    // Get the script pubkey
    let script_pubkey = tsh.script_pubkey();
    println!("\nScript PubKey: {}", script_pubkey.as_script());
    println!("Script PubKey hex: {}", script_pubkey.as_script().to_hex_string());

    // Get the address (regtest for example)
    let address = tsh.address(Network::Regtest);
    println!("\nP2TSH Address (miniscript): {}", address);

    // Calculate maximum satisfaction weight
    match tsh.max_weight_to_satisfy() {
        Ok(weight) => {
            println!("\nMaximum satisfaction weight: {} WU", weight.to_wu());
            println!("  (SLH-DSA signature: ~7856 bytes + script + control block)");
        }
        Err(e) => println!("\nError calculating weight: {}", e),
    }
    
    address
}

/// Demonstrate single-leaf P2TSH using low-level bitcoin crate with SLH-DSA key
fn single_leaf_via_bitcoin_crate(slh_dsa_pubkey_bytes: &[u8]) -> Address {
    println!("\n=== Single-Leaf P2TSH via Low-Level Bitcoin Crate ===");
    
    // Build script manually: OP_PUSHBYTES_32 <32-byte-key> OP_SUCCESS127
    let mut slh_dsa_script_bytes = vec![0x20]; // OP_PUSHBYTES_32
    slh_dsa_script_bytes.extend_from_slice(slh_dsa_pubkey_bytes);
    slh_dsa_script_bytes.push(0x7f); // OP_SUCCESS127
    let slh_dsa_leaf_script = ScriptBuf::from_bytes(slh_dsa_script_bytes);
    
    println!("SLH-DSA leaf script: {}", slh_dsa_leaf_script.to_hex_string());
    
    // Create P2tshBuilder with single leaf (weight 1) using SLH-DSA key
    let huffman_entries_slh = vec![(1u32, slh_dsa_leaf_script.clone())];
    let p2tsh_builder_slh = P2tshBuilder::with_huffman_tree(huffman_entries_slh)
        .expect("Failed to create P2tshBuilder");
    
    // Finalize to get spend info with merkle root
    let p2tsh_spend_info_slh = p2tsh_builder_slh.finalize()
        .expect("Failed to finalize P2tshBuilder");
    let merkle_root_slh = p2tsh_spend_info_slh.merkle_root
        .expect("Expected merkle root");
    
    println!("Merkle root: {}", merkle_root_slh);
    
    // Create P2TSH address from merkle root
    let address = Address::p2tsh(Some(merkle_root_slh), Network::Regtest);
    println!("P2TSH Address (bitcoin crate, SLH-DSA): {}", address);
    
    address
}

/// Compare addresses from miniscript and low-level bitcoin crate approaches
fn compare_single_leaf_addresses(address_miniscript: Address, address_bitcoin: Address) {
    println!("\n📊 Address Comparison:");
    println!("  Miniscript (using SLH-DSA): {}", address_miniscript);
    println!("  Bitcoin (using SLH-DSA):    {}", address_bitcoin);
    if address_miniscript.to_string() == address_bitcoin.to_string() {
        println!("\n  ✓ MATCH! Both methods produce the same address");
        println!("  Both approaches now use the SAME SLH-DSA key!");
    } else {
        println!("\n  ✗ MISMATCH! Addresses differ - this should not happen!");
    }
}

/// Print requirements for spending a P2TSH output
fn print_spending_requirements() {
    println!("\n=== To Spend This Output ===");
    println!("Witness required:");
    println!("  1. SLH-DSA signature (7856 bytes) + sighash type (1 byte)");
    println!("  2. Leaf script: <32-byte-key> OP_SUCCESS127");
    println!("  3. Control block (merkle proof)");
}

/// Demonstrate multi-leaf P2TSH combining Schnorr and SLH-DSA
fn demonstrate_multi_leaf_p2tsh(secp: &Secp256k1<bitcoin::secp256k1::All>, demo_slh_key: SlhDsaPublicKey) {
    println!("\n=== Multi-Leaf Example (Hybrid: Schnorr + SLH-DSA) ===");
    
    // Generate a proper Schnorr keypair using secp256k1
    let (_, schnorr_public_key) = secp.generate_keypair(&mut thread_rng());
    let (schnorr_x_only_pubkey, _) = schnorr_public_key.x_only_public_key();
    
    // Convert secp256k1::XOnlyPublicKey to bitcoin::XOnlyPublicKey
    let schnorr_key = XOnlyPublicKey::from_slice(&schnorr_x_only_pubkey.serialize())
        .expect("Failed to parse schnorr key");
    
    println!("Schnorr Public Key: {}", schnorr_key);
    
    // Create multi-leaf P2TSH via miniscript
    let address_miniscript = create_multi_leaf_miniscript(schnorr_key, demo_slh_key);
    
    // Create the same multi-leaf P2TSH via low-level bitcoin crate
    let address_bitcoin = create_multi_leaf_bitcoin_crate(schnorr_key, demo_slh_key);
    
    // Compare addresses
    println!("\n📊 Address Comparison (Multi-Leaf: Schnorr + SLH-DSA demo):");
    println!("  Miniscript: {}", address_miniscript);
    println!("  Bitcoin:    {}", address_bitcoin);
    if address_miniscript.to_string() == address_bitcoin.to_string() {
        println!("  ✓ MATCH! Both methods produce the same address");
        println!("  (When using the same keys, both approaches generate identical addresses)");
    } else {
        println!("  ✗ MISMATCH! Addresses differ");
    }
}

/// Create multi-leaf P2TSH using miniscript
fn create_multi_leaf_miniscript(schnorr_key: XOnlyPublicKey, slh_dsa_key: SlhDsaPublicKey) -> Address {
    
    // Create two miniscripts
    // Note: When mixing Schnorr and SLH-DSA leaves in the same tree, we use XOnlyPublicKey
    // as the common type parameter since TapTree requires all leaves to have the same Pk type.
    // For SLH-DSA, this is just a placeholder - the actual key is the concrete SlhDsaPublicKey.
    let ms_schnorr: Miniscript<XOnlyPublicKey, Tap> = 
        Miniscript::from_ast(miniscript::Terminal::Check(
            std::sync::Arc::new(Miniscript::from_ast(
                miniscript::Terminal::PkK(schnorr_key)
            ).unwrap())
        )).unwrap();
    
    let ms_slh_dsa: Miniscript<XOnlyPublicKey, Tap> = 
        Miniscript::slh_dsa_pk(slh_dsa_key);
    
    // Create a taptree with two leaves
    let left_tree = TapTree::leaf(ms_schnorr);
    let right_tree = TapTree::leaf(ms_slh_dsa);
    let combined_tree = TapTree::combine(left_tree, right_tree)
        .expect("Failed to combine trees");
    
    println!("\nCreated TapTree with 2 leaves:");
    println!("  - Leaf 0: Traditional Schnorr (pk)");
    println!("  - Leaf 1: Post-quantum SLH-DSA");
    
    let tsh_multi = Tsh::new(Some(combined_tree))
        .expect("Failed to create multi-leaf Tsh");
    
    println!("\nMulti-leaf P2TSH Descriptor: {}", tsh_multi);
    
    let address = tsh_multi.address(Network::Regtest);
    println!("Multi-leaf P2TSH Address (miniscript): {}", address);
    
    address
}

/// Create multi-leaf P2TSH using low-level bitcoin crate
fn create_multi_leaf_bitcoin_crate(schnorr_key: XOnlyPublicKey, slh_dsa_key: SlhDsaPublicKey) -> Address {
    
    // Script 1: Schnorr - OP_PUSHBYTES_32 <32-byte-key> OP_CHECKSIG
    let mut schnorr_script_bytes = vec![0x20]; // OP_PUSHBYTES_32
    schnorr_script_bytes.extend_from_slice(&schnorr_key.serialize());
    schnorr_script_bytes.push(0xac); // OP_CHECKSIG
    let schnorr_leaf_script = ScriptBuf::from_bytes(schnorr_script_bytes);
    
    // Script 2: SLH-DSA - OP_PUSHBYTES_32 <32-byte-slh-dsa-key> OP_SUCCESS127
    let mut slh_dsa_leaf_script_bytes = vec![0x20]; // OP_PUSHBYTES_32
    slh_dsa_leaf_script_bytes.extend_from_slice(slh_dsa_key.as_slice());
    slh_dsa_leaf_script_bytes.push(0x7f); // OP_SUCCESS127
    let slh_dsa_leaf_script = ScriptBuf::from_bytes(slh_dsa_leaf_script_bytes);
    
    println!("Schnorr leaf script: {}", schnorr_leaf_script.to_hex_string());
    println!("SLH-DSA leaf script: {}", slh_dsa_leaf_script.to_hex_string());
    
    // Create P2tshBuilder with two leaves (using same keys as miniscript for comparison)
    let huffman_entries_multi = vec![
        (1u32, schnorr_leaf_script.clone()),
        (1u32, slh_dsa_leaf_script.clone()),
    ];
    let p2tsh_builder_multi = P2tshBuilder::with_huffman_tree(huffman_entries_multi)
        .expect("Failed to create multi-leaf P2tshBuilder");
    
    // Finalize to get spend info with merkle root
    let p2tsh_spend_info_multi = p2tsh_builder_multi.finalize()
        .expect("Failed to finalize multi-leaf P2tshBuilder");
    let merkle_root_multi = p2tsh_spend_info_multi.merkle_root
        .expect("Expected merkle root");
    
    println!("Multi-leaf merkle root: {}", merkle_root_multi);
    
    // Create P2TSH address from merkle root
    let address = Address::p2tsh(Some(merkle_root_multi), Network::Regtest);
    println!("Multi-leaf P2TSH Address (bitcoin crate): {}", address);
    
    address
}

/// Custom Satisfier that provides SLH-DSA signatures
/// This demonstrates the extended Satisfier trait with lookup_slh_dsa_sig
struct SlhDsaSatisfier {
    /// Map of SLH-DSA public keys to their signatures
    slh_dsa_sigs: HashMap<SlhDsaPublicKey, Vec<u8>>,
}

impl SlhDsaSatisfier {
    /// Create a new satisfier with SLH-DSA signatures
    fn new() -> Self {
        Self {
            slh_dsa_sigs: HashMap::new(),
        }
    }
    
    /// Add a signature for a specific SLH-DSA public key
    fn add_slh_dsa_sig(&mut self, pk: SlhDsaPublicKey, sig: Vec<u8>) {
        self.slh_dsa_sigs.insert(pk, sig);
    }
}

/// Implement the Satisfier trait for our custom satisfier
/// All methods use default implementations except lookup_slh_dsa_sig
/// Note: AssetProvider is automatically implemented via blanket impl
impl<Pk: MiniscriptKey + ToPublicKey> Satisfier<Pk> for SlhDsaSatisfier {
    fn lookup_slh_dsa_sig(&self, pk: &SlhDsaPublicKey) -> Option<Vec<u8>> {
        self.slh_dsa_sigs.get(pk).cloned()
    }
}
/// Demonstrate the Satisfier trait extension for SLH-DSA
fn demonstrate_satisfier_trait(slh_dsa_keypair: &KeyPair, slh_dsa_key: SlhDsaPublicKey) {
    println!("\n=== Satisfier Trait Extension Demo ===");
    println!("This demonstrates automatic witness building using the extended Satisfier trait\n");
    
    // Create a miniscript with SLH-DSA
    //
    // Note: NoSecp256k1Key is a placeholder type parameter for Miniscript<Pk, Ctx>
    // - The slh_dsa_pk() method uses the concrete SlhDsaPublicKey type internally
    // - NoSecp256k1Key satisfies the MiniscriptKey trait requirement without providing
    //   actual secp256k1 key functionality
    // - This makes the code self-documenting: it clearly indicates this miniscript
    //   contains only post-quantum keys, no secp256k1 keys
    let ms: Miniscript<NoSecp256k1Key, Tap> = Miniscript::slh_dsa_pk(slh_dsa_key);
    println!("Miniscript: {}", ms);
    
    // Create a dummy message to sign
    let message = b"Hello, post-quantum world!";
    println!("\nMessage to sign: {:?}", String::from_utf8_lossy(message));
    
    // Generate SLH-DSA signature using bitcoinpqc
    println!("\nGenerating SLH-DSA signature (this may take a moment)...");
    let slh_dsa_signature = bitcoinpqc::sign(&slh_dsa_keypair.secret_key, message)
        .expect("Failed to sign with SLH-DSA");
    
    // SLH-DSA signature with sighash byte (using ALL = 0x01 for this example)
    let mut sig_with_sighash = slh_dsa_signature.bytes.to_vec();
    sig_with_sighash.push(0x01); // SIGHASH_ALL
    
    println!("✓ SLH-DSA signature generated!");
    println!("  Signature size: {} bytes", slh_dsa_signature.bytes.len());
    println!("  With sighash: {} bytes", sig_with_sighash.len());
    
    // Method 1: Using custom Satisfier (NEW!)
    println!("\n--- Method 1: Automatic Witness via Satisfier ---");
    let mut satisfier = SlhDsaSatisfier::new();
    satisfier.add_slh_dsa_sig(slh_dsa_key, sig_with_sighash.clone());
    
    // This now works! The satisfy() method will use our custom satisfier
    match ms.satisfy(&satisfier) {
        Ok(witness_vec) => {
            println!("✅ SUCCESS! Witness automatically generated:");
            println!("  Witness stack items: {}", witness_vec.len());
            for (i, item) in witness_vec.iter().enumerate() {
                if item.len() > 100 {
                    println!("  [{}]: {} bytes (signature)", i, item.len());
                } else {
                    println!("  [{}]: {} bytes", i, item.len());
                }
            }
            
            // Verify the witness contains our signature
            if witness_vec.len() > 0 && witness_vec[0] == sig_with_sighash {
                println!("\n  ✓ Witness contains correct SLH-DSA signature!");
            }
        }
        Err(e) => {
            println!("❌ Error: {:?}", e);
        }
    }
    
}

fn get_random_bytes(size: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; size];
    thread_rng().fill_bytes(&mut bytes);
    bytes
}

