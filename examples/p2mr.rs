// SPDX-License-Identifier: CC0-1.0

use std::collections::HashMap;
use std::str::FromStr;

use miniscript::bitcoin::key::{Keypair, XOnlyPublicKey};
use miniscript::bitcoin::secp256k1::rand;
use miniscript::bitcoin::{Network, WitnessVersion};
use miniscript::descriptor::DescriptorType;
use miniscript::descriptor::SlhDsaPublicKey;
use miniscript::policy::Concrete;
use miniscript::{translate_hash_fail, Descriptor, Miniscript, Tap, Translator, NoSecp256k1Key};

// Refer to https://github.com/sanket1729/adv_btc_workshop/blob/master/workshop.md#creating-a-taproot-descriptor
// for a detailed explanation of the policy and it's compilation

struct StrPkTranslator {
    pk_map: HashMap<String, XOnlyPublicKey>,
}

impl Translator<String> for StrPkTranslator {
    type TargetPk = XOnlyPublicKey;
    type Error = ();

    fn pk(&mut self, pk: &String) -> Result<XOnlyPublicKey, Self::Error> {
        self.pk_map.get(pk).copied().ok_or(())
    }

    // We don't need to implement these methods as we are not using them in the policy.
    // Fail if we encounter any hash fragments. See also translate_hash_clone! macro.
    translate_hash_fail!(String, XOnlyPublicKey, Self::Error);
}

fn main() {
    let pol_str = "or(
        99@thresh(2,
            pk(hA), pk(S)
        ),1@or(
            99@pk(Ca),
            1@and(pk(In), older(9))
            )
        )"
    .replace(&[' ', '\n', '\t'][..], "");

    println!("pol_str = {}", pol_str);

    let pol = Concrete::<String>::from_str(&pol_str).unwrap();
    let desc = pol.compile_mr().unwrap();

    println!("compileddesc = {}", desc);

    let expected_desc =
        Descriptor::<String>::from_str("mr({and_v(v:pk(In),older(9)),and_v(v:pk(hA),pk(S))})")
            .unwrap();
    assert_eq!(desc, expected_desc, "failed to compile mr descriptor");

    // Check whether the descriptors are safe.
    assert!(desc.sanity_check().is_ok());

    // Descriptor type and version should match respectively for taproot
    let desc_type = desc.desc_type();
    assert_eq!(desc_type, DescriptorType::Mr);
    assert_eq!(desc_type.segwit_version().unwrap(), WitnessVersion::V3);

    if let Descriptor::Mr(ref p) = desc {

        // Iterate through scripts
        let mut iter = p.leaves();
        let mut next = iter.next().unwrap();
        assert_eq!(
            (next.depth(), next.miniscript().as_ref()),
            (
                1u8,
                &Miniscript::<String, Tap>::from_str("and_v(vc:pk_k(In),older(9))").unwrap()
            )
        );
        next = iter.next().unwrap();
        assert_eq!(
            (next.depth(), next.miniscript().as_ref()),
            (1u8, &Miniscript::<String, Tap>::from_str("and_v(v:pk(hA),pk(S))").unwrap())
        );
        assert_eq!(iter.next(), None);
    }

    let mut pk_map = HashMap::new();

    // We require secp for generating a random XOnlyPublicKey
    let secp = secp256k1::Secp256k1::new();
    let key_pair = Keypair::new(&secp, &mut rand::thread_rng());

    let pubkeys = hardcoded_xonlypubkeys();
    pk_map.insert("hA".to_string(), pubkeys[0]);
    pk_map.insert("S".to_string(), pubkeys[1]);
    pk_map.insert("Ca".to_string(), pubkeys[2]);
    pk_map.insert("In".to_string(), pubkeys[3]);
    let mut t = StrPkTranslator { pk_map };

    let real_desc = desc.translate_pk(&mut t).unwrap();

    println!("real_desc = {}", real_desc);

    // Max satisfaction weight for compilation, corresponding to the script-path spend
    // `and_v(PUBKEY_1,PUBKEY_2) at tap tree depth 1, having:
    //
    //     max_witness_size = varint(control_block_size) + control_block size +
    //                        varint(script_size) + script_size + max_satisfaction_size
    //                      = 1 + 65 + 1 + 68 + 132 = 269
    let max_sat_wt = real_desc.max_weight_to_satisfy().unwrap().to_wu();
    assert_eq!(max_sat_wt, 267);

    // Compute the bitcoin address and check if it matches
    let network = Network::Regtest;
    let addr = real_desc.address(network).unwrap();
    let expected_addr = bitcoin::Address::from_str(
        "bcrt1r0n0nvyp5xwcp577k9hpycyuaec6va20sey7fv349ssuxpzlvjyesnk4t7l",
    )
    .unwrap()
    .assume_checked();
    assert_eq!(addr, expected_addr);

    // ============================================================
    // SLH-DSA Post-Quantum Cryptography Example
    // ============================================================
    println!("\n=== SLH-DSA Post-Quantum Example ===\n");
    
    slh_dsa_example();
}

/// Demonstrates the use of SLH-DSA (post-quantum cryptography) Terminal
/// This creates a P2MR descriptor with a leaf script: <slh-dsa-key> OP_SUCCESS127
fn slh_dsa_example() {
    // Example SLH-DSA public key (32 bytes)
    // In production, this would come from bitcoinpqc::generate_keypair()
    let slh_dsa_key_bytes: [u8; 32] = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
    ];
    
    let slh_dsa_pubkey = SlhDsaPublicKey::from_bytes(slh_dsa_key_bytes);
    println!("SLH-DSA Public Key: {}", slh_dsa_pubkey);

    // Create a miniscript using the new slh_dsa_pk terminal
    // This generates: <32-byte-key> OP_SUCCESS127 (0x7f)
    // Note: NoSecp256k1Key is a placeholder since SLH-DSA uses a concrete type
    let slh_dsa_ms: Miniscript<NoSecp256k1Key, Tap> = 
        Miniscript::slh_dsa_pk(slh_dsa_pubkey);
    
    println!("SLH-DSA Miniscript: {}", slh_dsa_ms);
    
    // Get the compiled script
    let script = slh_dsa_ms.encode();
    println!("Script bytes: {}", script.to_hex_string());
    println!("Script size: {} bytes", script.len());
    
    // Create a TapTree with the SLH-DSA leaf
    use miniscript::descriptor::{TapTree, Mr};
    let tap_tree = TapTree::leaf(slh_dsa_ms);
    let mr_desc = Mr::new(Some(tap_tree))
        .expect("Failed to create P2MR descriptor");
    
    println!("\nP2MR Descriptor: {}", mr_desc);
    
    // Get the address
    let address = mr_desc.address(Network::Regtest);
    println!("P2MR Address: {}", address);
    
    // Calculate satisfaction weight
    // SLH-DSA signatures are ~7856 bytes (much larger than Schnorr's 64 bytes!)
    match mr_desc.max_weight_to_satisfy() {
        Ok(weight) => {
            println!("\nMaximum satisfaction weight: {} WU", weight.to_wu());
            println!("  (This includes the large SLH-DSA signature: ~7857 bytes)");
        }
        Err(e) => println!("Error: {}", e),
    }
    
    // Example 2: Hybrid approach - mixing traditional and post-quantum
    println!("\n=== Hybrid Schnorr + SLH-DSA Example ===\n");
    
    let traditional_key = hardcoded_xonlypubkeys()[0];
    
    // Create traditional Schnorr leaf (pk wrapped in check)
    let schnorr_ms: Miniscript<XOnlyPublicKey, Tap> = 
        Miniscript::from_str(&format!("pk({})", traditional_key)).unwrap();
    
    println!("Schnorr Miniscript: {}", schnorr_ms);
    println!("SLH-DSA Miniscript: {}", slh_dsa_ms);
    
    // Create two-leaf taptree
    let left_tree = TapTree::leaf(schnorr_ms);
    let right_tree = TapTree::leaf(slh_dsa_ms);
    let hybrid_tree = TapTree::combine(left_tree, right_tree)
        .expect("Failed to combine trees");
    
    let hybrid_mr = Mr::new(Some(hybrid_tree))
        .expect("Failed to create hybrid P2MR");
    
    println!("\nHybrid P2MR Descriptor: {}", hybrid_mr);
    println!("  - Leaf 0 (depth 1): Traditional Schnorr signature");
    println!("  - Leaf 1 (depth 1): Post-quantum SLH-DSA signature");
    
    let hybrid_address = hybrid_mr.address(Network::Regtest);
    println!("\nHybrid P2MR Address: {}", hybrid_address);
    
    // Iterate through the leaves
    println!("\nLeaves in hybrid taptree:");
    for (idx, leaf) in hybrid_mr.leaves().enumerate() {
        println!("  Leaf {}: depth={}, script={}", 
            idx, 
            leaf.depth(), 
            leaf.miniscript()
        );
    }
    
    println!("\n=== Benefits of This Approach ===");
    println!("✓ Quantum-resistant: SLH-DSA protects against quantum attacks");
    println!("✓ Hybrid option: Can mix traditional and PQ signatures");
    println!("✓ Flexible: User chooses which leaf to spend");
    println!("✓ Future-proof: Ready for post-quantum era");
    
    println!("\n=== Script Breakdown ===");
    println!("Traditional: <schnorr-sig(64)> <pubkey(32)> CHECKSIG");
    println!("SLH-DSA:     <slh-dsa-sig(7856)> <pubkey(32)> OP_SUCCESS127");
    println!("\nOP_SUCCESS127 (0x7f) triggers immediate script success per BIP-342");
    println!("Actual signature verification happens in consensus layer");
}

fn hardcoded_xonlypubkeys() -> Vec<XOnlyPublicKey> {
    let serialized_keys: [[u8; 32]; 4] = [
        [
            22, 37, 41, 4, 57, 254, 191, 38, 14, 184, 200, 133, 111, 226, 145, 183, 245, 112, 100,
            42, 69, 210, 146, 60, 179, 170, 174, 247, 231, 224, 221, 52,
        ],
        [
            194, 16, 47, 19, 231, 1, 0, 143, 203, 11, 35, 148, 101, 75, 200, 15, 14, 54, 222, 208,
            31, 205, 191, 215, 80, 69, 214, 126, 10, 124, 107, 154,
        ],
        [
            202, 56, 167, 245, 51, 10, 193, 145, 213, 151, 66, 122, 208, 43, 10, 17, 17, 153, 170,
            29, 89, 133, 223, 134, 220, 212, 166, 138, 2, 152, 122, 16,
        ],
        [
            50, 23, 194, 4, 213, 55, 42, 210, 67, 101, 23, 3, 195, 228, 31, 70, 127, 79, 21, 188,
            168, 39, 134, 58, 19, 181, 3, 63, 235, 103, 155, 213,
        ],
    ];
    let mut keys: Vec<XOnlyPublicKey> = vec![];
    for key in serialized_keys {
        keys.push(XOnlyPublicKey::from_slice(&key).unwrap());
    }
    keys
}
