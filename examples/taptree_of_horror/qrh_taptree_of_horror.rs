use std::str::FromStr;

use bitcoin::absolute::LockTime;
use bitcoin::consensus::encode::serialize;
use bitcoin::hashes::Hash;
use bitcoin::hex::{Case, DisplayHex};
use bitcoin::transaction::Version;
use bitcoin::{Address, Amount, Network, Psbt, PublicKey, Sequence, TxIn, TxOut};
use helper_fns::{produce_grim_hash, produce_kelly_hash, produce_key_pairs};
use miniscript::descriptor::DescriptorSecretKey;
use miniscript::policy::Concrete;
use miniscript::psbt::PsbtExt;
use miniscript::{Descriptor, DescriptorPublicKey};
mod helper_fns;

pub const KEYS_PER_PERSONA: usize = 9;

fn main() {
    let secp: &secp256k1::Secp256k1<secp256k1::All> = &secp256k1::Secp256k1::new();

    // ====== 1. Setup Hardcoded Values for all of the Personas ======

    // Define derivation paths that will be used
    let normal_path = "86'/1'/0'/0";
    let unhardened_path = "86/1/0/0";
    let weird_path = "69'/420'/999999999'/8008135'";

    // Hard coded regtest tprvs that will be used.
    let alice = format!("tprv8ZgxMBicQKsPeZjVFDhZR5wjfCvFNev9qKGPDPC77p5cAEgEMUCR8Cecaf8pYfY7NTz8QcjVnP8uR8NedPz8o7iG7qWgnFMyQy9BAhMVZgb/{normal_path}/*");
    let bob = format!("tprv8ZgxMBicQKsPeHy2kPPVzYpbUqwTVBjSthMJUcGyqUiXk8eZTQ6xrJKEmdX8NYJKLLGCHGjuByqz2ahJXp52E8zCUV7njziJzwN7V7zfrKZ/{normal_path}/*");
    let charlie = format!("tprv8ZgxMBicQKsPdYaiWLUQCprj7Ej9Ka5GEq6giWHgTnbJvdLWnSuYnsF5sonVh6iy2HzvfkfxRDAmWEXNo3SJWTHCXM6XuxVZvqxtEyjdC29/{normal_path}/*");
    let dave = format!("tprv8ZgxMBicQKsPfCRUoMSWthoE8aJKr7De5YkxS1y55PuiSoi5ACyYUbas8Kv4vVtDzhKnBgY7cVSuogg2QLqtFcSZVv4ZTeBEzkzSnF9cSUT/{weird_path}/*");
    let eve = format!("tprv8ZgxMBicQKsPdYD5umCPZeh6tMqKfQATctqJbycgJ5N1rrJ15cHMgxds5iYENHZHmkMiXccAqUFx2k3ZNwU9qxPMjrKvTbCtgLFxk7mjMWD/{normal_path}/*");
    let frank = format!("tprv8ZgxMBicQKsPemyPyxqZ85T1UjpToCbLQ7uSn4JpbtwMBCodjvrLbgjBZeGgT4tMHdHCqyieDwCNzE7RrtRMVCQjPKQbGJzrg5vfn4eT7og/{normal_path}/*");
    let heather = format!("tprv8ZgxMBicQKsPefp99xLkwnQbU9LEEb8v4Aig3o4hwnjbaYotixkbJv3Ssmog68ptHij2LgExefNU96DYJKtFbDazTr1jm48twYhQLG775qw/{normal_path}/*");
    let ian = format!("tprv8ZgxMBicQKsPfGsuwfAdg3xPP452wreLk7ZEgusb8zdMqh1fyKGKnzFbxyxeHY3qhg8ESDRp5F6RgWiQGcvkmLyERcMys5V8DuT4gvxMDmS/{unhardened_path}/*");
    let judy = format!("tprv8ZgxMBicQKsPcz4VcN87e2e9k1LHDBLLajbVSAKAedpm1qakjtRT5xrdnmsQARWAfwg3REr6sNd5YHeWuWkHVvyey3rYmq9xYorMvwY3XAB/{normal_path}/*");
    let liam = format!("tprv8ZgxMBicQKsPcycCJ2v7B1utZrhWJNdQTBm7m9eR6iX1D9a9YvjbCNeT6dTEdMh4JziVCHD4YHQ7AXkZNMLfaBVf3CCiVWQLxwdU2SnrPcT/{normal_path}/*");
    let s_backup_1 = format!("tprv8ZgxMBicQKsPetPYYt5GUtNmQPChghNDBLbgJXz3cTZopeDrxHMendLpujaBHMPX3dXLZcv2NkgAvxMeuf1jWBU3iYxdeJAhktdeM9cKcYF/{normal_path}/*");
    let x_backup_2 = format!("tprv8ZgxMBicQKsPdf55kYg8pVPrUaW3VLZyt8XwxwrvSPkpskxDah1mAWypsTTZJeomWPrGf4e5RyT4zVzENHrwAsXxJP2EPYbfrYLRVFC1rLb/{normal_path}/*");

    // define DescriptorSecretKeys
    let a_descriptor_desc_secret = DescriptorSecretKey::from_str(&alice).unwrap();
    let b_descriptor_desc_secret = DescriptorSecretKey::from_str(&bob).unwrap();
    let c_descriptor_desc_secret = DescriptorSecretKey::from_str(&charlie).unwrap();
    let d_descriptor_desc_secret = DescriptorSecretKey::from_str(&dave).unwrap();
    let e_descriptor_desc_secret = DescriptorSecretKey::from_str(&eve).unwrap();
    let f_descriptor_desc_secret = DescriptorSecretKey::from_str(&frank).unwrap();
    let h_descriptor_desc_secret = DescriptorSecretKey::from_str(&heather).unwrap();
    let i_descriptor_desc_secret = DescriptorSecretKey::from_str(&ian).unwrap();
    let j_descriptor_desc_secret = DescriptorSecretKey::from_str(&judy).unwrap();
    let l_descriptor_desc_secret = DescriptorSecretKey::from_str(&liam).unwrap();
    let s_descriptor_desc_secret = DescriptorSecretKey::from_str(&s_backup_1).unwrap();
    let x_descriptor_desc_secret = DescriptorSecretKey::from_str(&x_backup_2).unwrap();
    let grim = produce_grim_hash("sovereignty through knowledge");
    let kelly = produce_kelly_hash("the ultimate pre-preimage");

    println!("grim  hash: {:?}", grim.0);
    println!("kelly hash: {:?}", kelly.0);

    // ====== 2. Derive Keys, Preimages, Hashes, and Timelocks for Policy and Signing ======

    let (a_pks, a_prvs) = produce_key_pairs(a_descriptor_desc_secret, secp, normal_path, "alice");
    let (b_pks, b_prvs) = produce_key_pairs(b_descriptor_desc_secret, secp, normal_path, "bob");
    let (c_pks, c_prvs) = produce_key_pairs(c_descriptor_desc_secret, secp, normal_path, "charlie");
    let (d_pks, d_prvs) = produce_key_pairs(d_descriptor_desc_secret, secp, weird_path, "dave");
    let (e_pks, e_prvs) = produce_key_pairs(e_descriptor_desc_secret, secp, normal_path, "eve");
    let (f_pks, f_prvs) = produce_key_pairs(f_descriptor_desc_secret, secp, normal_path, "frank");
    let (h_pks, h_prvs) = produce_key_pairs(h_descriptor_desc_secret, secp, normal_path, "heather");
    let (i_pks, i_prvs) = produce_key_pairs(i_descriptor_desc_secret, secp, unhardened_path, "ian");
    let (j_pks, j_prvs) = produce_key_pairs(j_descriptor_desc_secret, secp, normal_path, "judy");
    let (l_pks, l_prvs) = produce_key_pairs(l_descriptor_desc_secret, secp, normal_path, "liam");
    let (s_pks, _s_prvs) =
        produce_key_pairs(s_descriptor_desc_secret, secp, normal_path, "s_backup1");
    let (x_pks, _x_prvs) =
        produce_key_pairs(x_descriptor_desc_secret, secp, normal_path, "x_backup2");

    // For this example we are grabbing the 9 keys for each persona
    let [a0, a1, a2, a3, a4, a5, a6, a7, a8]: [PublicKey; KEYS_PER_PERSONA] =
        a_pks[..].try_into().unwrap();
    let [b0, b1, b2, b3, b4, b5, b6, b7, b8]: [PublicKey; KEYS_PER_PERSONA] =
        b_pks[..].try_into().unwrap();
    let [c0, c1, c2, c3, c4, c5, c6, c7, c8]: [PublicKey; KEYS_PER_PERSONA] =
        c_pks[..].try_into().unwrap();
    let [d0, d1, d2, d3, d4, d5, d6, d7, d8]: [PublicKey; KEYS_PER_PERSONA] =
        d_pks[..].try_into().unwrap();
    let [e0, e1, e2, e3, e4, e5, e6, e7, e8]: [PublicKey; KEYS_PER_PERSONA] =
        e_pks[..].try_into().unwrap();
    let [f0, f1, f2, f3, f4, f5, f6, f7, f8]: [PublicKey; KEYS_PER_PERSONA] =
        f_pks[..].try_into().unwrap();
    let [h0, h1, h2, h3, h4, h5, h6, h7, h8]: [PublicKey; KEYS_PER_PERSONA] =
        h_pks[..].try_into().unwrap();
    let [i0, i1, i2, i3, i4, i5, i6, i7, i8]: [PublicKey; KEYS_PER_PERSONA] =
        i_pks[..].try_into().unwrap();
    let [j0, j1, j2, j3, j4, j5, j6, j7, j8]: [PublicKey; KEYS_PER_PERSONA] =
        j_pks[..].try_into().unwrap();
    let [l0, l1, l2, l3, l4, l5, l6, l7, l8]: [PublicKey; KEYS_PER_PERSONA] =
        l_pks[..].try_into().unwrap();
    let [_s0, _s1, s2, _s3, s4, s5, _s6, s7, s8]: [PublicKey; KEYS_PER_PERSONA] =
        s_pks[..].try_into().unwrap();
    let [_x0, _x1, x2, _x3, x4, x5, x6, _x7, x8]: [PublicKey; KEYS_PER_PERSONA] =
        x_pks[..].try_into().unwrap();

    // Hashes that will also be used in the policy.
    let g = grim.1;
    let k = kelly.1;
    // Absolute timelocks that were used at TABConf 6, The event took place Oct 23-26 and more spending paths for the puzzle became available during the conference.
    let oct_23_morning: u32 = 1729692000; // Oct 23, 10:00 AM EST
    let oct_24_evening: u32 = 1729819800; // Oct 24, 09:30 PM EST
    let oct_25_afternoon: u32 = 1729877400; // Oct 25, 01:30 PM EST
    let oct_26_morning: u32 = 1729942200; // Oct 26, 07:30 AM EST

    // ====== 3. Create Taptree Policy and Descriptor ======

    // NOTE: the spend path that will be satisfied at PSBT finailization time is the first fragment of this policy.
    // Being the first branch in the outermost or() gives this fragment a high base probability ( when ordering of the taptree is conducted ).
    let pol_str = format!(
            "or(
                and(
                    thresh(10, pk({a0}), pk({b0}), pk({c0}), pk({d0}), pk({e0}), pk({f0}), pk({h0}), pk({i0}), pk({j0}), pk({l0})),
                    thresh(3, sha256({k}), ripemd160({g}), after({oct_23_morning}))
                ),
                or(
                    or(
                        and(
                            thresh(8, pk({a1}), pk({b1}), pk({c1}), pk({e1}), pk({f1}), pk({h1}), pk({i1}), pk({j1}), pk({l1})),
                            thresh(3, pk({d1}), sha256({k}), after({oct_24_evening}))
                        ),
                        and(
                            thresh(4, pk({a2}), pk({b2}), pk({c2}), pk({e2}), pk({f2}), pk({h2}), pk({i2}), pk({l2})),
                            and(
                                thresh(4, pk({d2}), pk({j2}), ripemd160({g}), after({oct_24_evening})),
                                or(pk({s2}), pk({x2}))
                            )
                        )
                    ),
                    or(
                        or(
                            or(
                                and(
                                    thresh(6, pk({a3}), pk({b3}), pk({c3}), pk({e3}), pk({f3}), pk({h3}), pk({i3}), pk({l3})),
                                    thresh(4, pk({d3}), pk({j3}),  sha256({k}), after({oct_25_afternoon}))
                                ),
                                thresh(14, pk({a8}), pk({b8}), pk({c8}), pk({d8}), pk({e8}), pk({f8}), pk({h8}), pk({i8}), pk({j8}), pk({l8}), pk({s8}), pk({x8}), sha256({k}), ripemd160({g}))
                            ),
                            or(
                                and(
                                    thresh(9, pk({a4}), pk({b4}), pk({c4}), pk({d4}), pk({e4}), pk({f4}), pk({h4}), pk({i4}),  pk({j4}), pk({l4}), pk({s4}), pk({x4})),
                                    thresh(2, sha256({k}), after({oct_26_morning}))
                                ),
                                and(
                                    thresh(10, pk({a5}), pk({b5}), pk({c5}), pk({d5}), pk({e5}), pk({f5}), pk({h5}), pk({i5}),  pk({j5}), pk({l5}), pk({s5}), pk({x5})),
                                    after({oct_26_morning})
                                )
                            )
                        ),
                        or(
                            and(
                                thresh(4, pk({a6}), pk({b6}), pk({c6}), pk({e6}), pk({f6}), pk({h6}), pk({i6}), pk({l6})),
                                thresh(5, pk({d6}), pk({x6}), pk({j6}), ripemd160({g}), after({oct_25_afternoon}))
                            ),
                            and(
                                thresh(4, pk({a7}), pk({b7}), pk({c7}), pk({e7}), pk({f7}), pk({h7}), pk({i7}), pk({l7})),
                                thresh(5, pk({d7}), pk({s7}), pk({j7}), ripemd160({g}), after({oct_25_afternoon}))
                            )
                        )
                    )
                )
            )"
    )
    .replace(&[' ', '\n', '\t'][..], "");

    // Create the policy descriptor
    let pol = Concrete::<DescriptorPublicKey>::from_str(&pol_str).unwrap();
    let policy_desc: Descriptor<DescriptorPublicKey> = pol.compile_qrh().unwrap();
    //println!("\ndescriptor is: {}\n", policy_desc);

    // Get the derived descriptor at index 0 and log the script address
    let derived_descriptor = policy_desc.at_derivation_index(0).unwrap();
    let script_address = derived_descriptor.address(Network::Regtest).unwrap();
    let funding_script_pubkey = derived_descriptor.script_pubkey();
    println!("funding address: {}", script_address);
    println!("funding script pubkey: {}", funding_script_pubkey);

    // Print out the script of the highest probability spend path.
    // (which also happens to correspond to the same spend path that is satisfied at PSBT finalization time).
    if let Descriptor::Qrh(qrh) = &derived_descriptor {
        if let Some(tap_tree) = qrh.tap_tree() {
            println!("\n=== Last Tap Tree Leaf ===");
            if let Some(last_leaf) = tap_tree.leaves().next_back() {
                let leaf_script = last_leaf.miniscript().encode();
                let leaf_script_hex = leaf_script.to_hex_string();
                println!("Last leaf script (hex): {}", leaf_script_hex);
                println!("Last leaf script (asm): {}", leaf_script);
                println!("---");
            }
        }
    }

    // Assert that the descriptor is a QRH descriptor
    match &policy_desc {
        Descriptor::Qrh(qrh) => {
            assert!(qrh.tap_tree().is_some());
        }
        _ => panic!("tap tree is not correct"),
    }

    // ====== 4. Construct an Unsigned Transaction from the Tapscript ======

    let tx_in = TxIn {
        previous_output: bitcoin::OutPoint {
            txid: "8888888899999999aaaaaaaabbbbbbbbccccccccddddddddeeeeeeeeffffffff"
                .parse()
                .unwrap(),
            vout: 0,
        },
        sequence: Sequence(0),
        //        sequence: Sequence(40),
        ..Default::default()
    };

    let destination_address =
        Address::from_str("bcrt1p2tl8zasepqe3j6m7hx4tdmqzndddr5wa9ugglpdzgenjwv42rkws66dk5a")
            .unwrap();
    let destination_output: TxOut = TxOut {
        value: bitcoin::Amount::from_sat(99_999_000),
        script_pubkey: destination_address.assume_checked().script_pubkey(),
    };

    let time = oct_23_morning;

    let unsigned_tx = bitcoin::Transaction {
        version: Version::TWO,
        lock_time: LockTime::from_time(time).unwrap(),
        input: vec![tx_in],
        output: vec![destination_output],
    };

    let unsigned_tx_test_string = serialize(&unsigned_tx).to_hex_string(Case::Lower);
    assert!(unsigned_tx_test_string == "0200000001ffffffffeeeeeeeeddddddddccccccccbbbbbbbbaaaaaaaa99999999888888880000000000000000000118ddf5050000000022512052fe7176190833196b7eb9aab6ec029b5ad1d1dd2f108f85a246672732aa1d9d60011967");
    let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).unwrap();

    let prev_amount = Amount::from_sat(100_000_000);
    let funding_witness_utxo =
        TxOut { value: prev_amount, script_pubkey: funding_script_pubkey };

    // Tell the PSBT what we're spending from - the actual UTXO data that exists on the blockchain
    psbt.inputs[0].witness_utxo = Some(funding_witness_utxo); // reference the funding UTXO as input 0 of this tx

    // Tell Psbt about the descriptor so it can sign with it .  In particular, the following metadata is added to the PSBT:
    // - All pub keys in the descriptor (from all spend paths)
    // - All tapleaf scripts in the taptree
    // - All key derivation paths needed for any possible spend
    // - The complete taptree structure
    psbt.update_input_with_descriptor(0, &derived_descriptor)
        .unwrap();

    // ====== 5. Sign and Create a Spending Transaction ======

    let secp: &secp256k1::Secp256k1<secp256k1::All> = &secp256k1::Secp256k1::new();

    // how you would sign using the leaf that uses index 0 keys
    let _res = psbt.sign(&a_prvs[0], secp).unwrap();
    let _res = psbt.sign(&b_prvs[0], secp).unwrap();
    let _res = psbt.sign(&c_prvs[0], secp).unwrap();
    let _res = psbt.sign(&d_prvs[0], secp).unwrap();
    let _res = psbt.sign(&e_prvs[0], secp).unwrap();
    let _res = psbt.sign(&f_prvs[0], secp).unwrap();
    let _res = psbt.sign(&h_prvs[0], secp).unwrap();
    let _res = psbt.sign(&i_prvs[0], secp).unwrap();
    let _res = psbt.sign(&j_prvs[0], secp).unwrap();
    let _res = psbt.sign(&l_prvs[0], secp).unwrap();

    psbt.inputs[0]
        .sha256_preimages
        .insert(kelly.1, kelly.0.to_byte_array().to_vec());

    psbt.inputs[0]
        .ripemd160_preimages
        .insert(grim.1, grim.0.to_byte_array().to_vec());

    // Finalize PSBT now that we have all the required signatures and hash preimages.
    // spend path selection happens implicitly in the finalize step based on the signatures and pre-images provided.
    // (As per the 1st spend path)
    psbt.finalize_mut(secp).unwrap();

    // Now extract the tx
    let signed_tx = psbt.extract_tx().unwrap();
    let raw_tx = bitcoin::consensus::encode::serialize(&signed_tx).to_hex_string(Case::Lower);

    let test_raw_tx = "02000000000101ffffffffeeeeeeeeddddddddccccccccbbbbbbbbaaaaaaaa99999999888888880000000000000000000118ddf5050000000022512052fe7176190833196b7eb9aab6ec029b5ad1d1dd2f108f85a246672732aa1d9d0e209250ecce1169d94cf17baaecddcef779ff1b0d07d347d24afcd5b2231f95a500209562ef4e826d891eaa72f2cee753b80a3f7f6b5aed07b850227e83546fa61857402f498d0fd1e59e98ebde7744a82c99bb85e562184c8cf48e9967d51f5c9a0b6b34281aea7f5759b3336a2a68961b8d0a393a309a03c66dda87649a52fd718d424051ed4198883426378f9d3e154269e05a701f18d2fc18041e69da2d27ff66ec232032b92c20ddf984435f97c45cca07b675f6ee968162f847856db214a94c0c6b40c4496a96e5499ddb09de0bf1531f0f3c93b046166a65195c6940dc68ea6a62de8fc315652ddf5d688cff1432f0ef3620fd942d9303f5a3d1689851483031362f4049f5dc16f9172eb0d38fab181156e71d5d4a79395846264cfd90ba8475da76608742ba8e9ded4f2ead1afd0c641f9421ff1deb8b43ea4255d0710460e4a1783f40086faab6b59b2ebd714c2de1c9c10c7744c53ad009756dd9f3b9b6922cff33c595e2f837623a6c498de3e11671c670263fc6e69acecf377cb456c69c576527c240ca7c15e3caca6183c5b91afa22658c51bc45e762e5be5af0c2045a7ba3a65a5607d274109afbdf885dbf2c725ab16edfd0da5b5bebb63fcddb58583cf94dd059403c90cfa2075b335aa41b5eeaa8a0c1abe32863b0965fd04d7bc06ec19b9af65f74efd404d99f0cc7778c82be40bf70b136f365bd19d1af7a2d7e37b52544ce784096a2646e9c95ff88dbe287f2a56e617a878abf80ef6341ced111724d8d3c4d8c5eb6e6d52825cc8a7ee70dd6bb8039ffcdf441c182438b2cd0546d99841f680a409143ed7235601fe9f96c8a3afc190af93f795c0dde48139e1bd639b4cbc2c9102b2708e0f63ffb2ff5572f0b397543879ad7a552cca2534b36bc7adbed80f4fd4022e827cee6cd4fe15d3ff6d294a99b35d08b2a6122eafccadff2cd2831fd8b84ce0953a5a49ad972e763b84106706ea4d5342c016032c49b17dd27322eddad69fd9c0120fe88003d0bcb15d1628edff84046255758baf205d42ce460b6fb4595b983f2ecad20eecd6dba68fd0ec5d4baa0052db8084cb15a55503b78cfee5ef31c35cd98d846ad20529c1e24d86bf35b35133a81bf1e8c21759f3a83cfb38f18eae1d5b8292ff4bead2083835dbe036944f18783e0a525babe23965a2b4fdeca2d2d84997fc6ff0fb06aad204aeb360d05ad743b838ad27c56b78f08668aeba77f2f1fc439ac80f970e57328ad2062c4d094ce7a28414102bacccb06947053e07e4da53ad96e5724565f09436dfcad20f6e5c74176d69d44a97220a694237d8e719fae4a029942aadb28a9b491b40e31ad20dc7ea580c6887971614260d91069c4d398cc80ecc6cbb4ab59099e110ad3bb8bad2059fa3dfd7286d59f9b3853fb0cdd13c4760508f672435be40057b9e02eb937bdad20aa90f13a1c98abc5620d3f379d20b8c28ddf8f46772a0d0af6b7deb7bf3a1ee1ad82012088a8202db9cdb5e102541f19b455fa798e0cb009f5faa6358b9d3507858caf797bca418882012088a6148d60757ec290d055be92da400cff617b0423cb14880460011967b121c1326f8afc8b0ef3f1cc0428893a40e48b9419807a4fd8f8673b62840ef216d5f660011967";
    assert!(raw_tx == test_raw_tx,
        "assertion failed: raw_tx: {}\ntest_raw_tx: {}",
        raw_tx,
        test_raw_tx
    );

    println!("raw_tx: {}", raw_tx);
}
