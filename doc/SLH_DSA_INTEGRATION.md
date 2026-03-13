SLH-DSA Post-Quantum Cryptography Integration for P2MR

- [1. Overview](#1-overview)
- [2. Usage in P2MR](#2-usage-in-p2mr)
  - [2.1. Creating a P2MR Descriptor with SLH-DSA](#21-creating-a-p2mr-descriptor-with-slh-dsa)
  - [2.2. Script Output](#22-script-output)
  - [2.3. Witness Structure](#23-witness-structure)
- [3. SlhDsaPublicKey Type](#3-slhdsapublickey-type)
- [4. NoSecp256k1Key Placeholder Type](#4-nosecp256k1key-placeholder-type)
- [5. Technical Details](#5-technical-details)
  - [5.1. OP\_SUCCESS127](#51-op_success127)
  - [5.2. SLH-DSA Signature Size](#52-slh-dsa-signature-size)
  - [5.3. Comparison with Traditional Signatures](#53-comparison-with-traditional-signatures)
- [6. Integration with Existing Code](#6-integration-with-existing-code)
  - [6.1. Architecture Note: Concrete Type vs Generic Type Parameter](#61-architecture-note-concrete-type-vs-generic-type-parameter)
- [7. Files Modified](#7-files-modified)
- [8. Implementation Status](#8-implementation-status)
  - [8.1. ✅ Completed](#81--completed)
  - [8.2. ⚠️ Partial/Limited](#82-️-partiallimited)
  - [8.3. ❌ Not Yet Implemented](#83--not-yet-implemented)
  - [8.4. Next Steps](#84-next-steps)
- [9. Known Limitations](#9-known-limitations)
- [10. References](#10-references)
- [11. Notes](#11-notes)
- [12. Appendix](#12-appendix)
  - [12.1. Changes Made](#121-changes-made)
    - [12.1.1. New Terminal Variant: `Terminal::SlhDsaPk`](#1211-new-terminal-variant-terminalslhdsapk)
    - [12.1.2. Script Encoding](#1212-script-encoding)
    - [12.1.3. Miniscript Constructor](#1213-miniscript-constructor)
    - [12.1.4. Script Properties (ExtData)](#1214-script-properties-extdata)
    - [12.1.5. Satisfaction Logic](#1215-satisfaction-logic)
      - [12.1.5.1. Satisfier Trait Extension](#12151-satisfier-trait-extension)
      - [12.1.5.2. Satisfaction Implementation](#12152-satisfaction-implementation)
      - [12.1.5.3. AssetProvider Trait Extension](#12153-assetprovider-trait-extension)
      - [12.1.5.4. PSBT Support Status](#12154-psbt-support-status)
      - [12.1.5.5. When Satisfaction Logic Becomes Important](#12155-when-satisfaction-logic-becomes-important)
        - [12.1.5.5.1. Creating Spending Witnesses (Most Critical)](#121551-creating-spending-witnesses-most-critical)
        - [12.1.5.5.2. PSBT (Partially Signed Bitcoin Transaction) Workflows](#121552-psbt-partially-signed-bitcoin-transaction-workflows)
        - [12.1.5.5.3. Transaction Analysis \& Estimation](#121553-transaction-analysis--estimation)
        - [12.1.5.5.4. Using the Satisfier Trait Extension](#121554-using-the-satisfier-trait-extension)
        - [12.1.5.5.5. Practical Example](#121555-practical-example)
        - [12.1.5.5.6. Summary](#121556-summary)
    - [12.1.6. Display Support](#1216-display-support)



## 1. Overview

This document describes the integration of SLH-DSA (Stateless Hash-Based Digital Signature Algorithm) post-quantum cryptography into rust-miniscript for use with P2MR (Pay-to-Taproot-Script-Hash) descriptors.

## 2. Usage in P2MR

### 2.1. Creating a P2MR Descriptor with SLH-DSA

```rust
use miniscript::{Miniscript, Tap, NoSecp256k1Key};
use miniscript::descriptor::{MR, TapTree, SlhDsaPublicKey};
use bitcoin::Network;

// Create a SlhDsaPublicKey from a 32-byte array
let key_bytes: [u8; 32] = /* your 32-byte SLH-DSA public key */;
let slh_dsa_key = SlhDsaPublicKey::from_bytes(key_bytes);

// Create a miniscript with SLH-DSA public key
// Note: NoSecp256k1Key is a placeholder type since slh_dsa_pk uses concrete SlhDsaPublicKey
let ms: Miniscript<NoSecp256k1Key, Tap> = Miniscript::slh_dsa_pk(slh_dsa_key);

// Use in a taptree for P2MR
let mr = Mr::new(Some(TapTree::leaf(ms)))?;

// Get the address
let address = mr.address(Network::Bitcoin);
```

See `examples/slh_dsa_p2mr.rs` for a complete working example including signature creation and multi-leaf taptrees.

### 2.2. Script Output

The resulting script will be:
```
OP_PUSHBYTES_32 <32-byte-slh-dsa-pubkey> OP_SUCCESS127
```

### 2.3. Witness Structure

To spend from this output, provide:
```
Witness:
  - <7856-byte-slh-dsa-signature> <sighash-type-byte>
  - <leaf-script>
  - <control-block>
```

## 3. SlhDsaPublicKey Type

**Location:** `src/descriptor/key.rs:19-86`

The `SlhDsaPublicKey` type encapsulates a 32-byte SLH-DSA public key:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SlhDsaPublicKey([u8; 32]);
```

**Key methods:**
- `from_bytes([u8; 32]) -> Self` - Create from a 32-byte array
- `from_slice(&[u8]) -> Result<Self, SlhDsaKeyError>` - Create from a slice (validates length)
- `as_bytes() -> &[u8; 32]` - Get reference to underlying bytes
- `as_slice() -> &[u8]` - Get byte slice view
- Implements `Display` - formats as lowercase hex string

**Error type:**
```rust
pub enum SlhDsaKeyError {
    InvalidLength(usize),
}
```

## 4. NoSecp256k1Key Placeholder Type

**Location:** `src/lib.rs:216-246`

The `NoSecp256k1Key` type is a placeholder used as the generic `Pk` parameter in `Miniscript<Pk, Ctx>` when the miniscript contains only post-quantum or other non-secp256k1 keys:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NoSecp256k1Key;

impl MiniscriptKey for NoSecp256k1Key {
    type Sha256 = sha256::Hash;
    type Hash256 = hash256::Hash;
    type Ripemd160 = ripemd160::Hash;
    type Hash160 = hash160::Hash;
}
```

**Purpose:**
- Serves as a type-safe placeholder for `Miniscript<Pk, Ctx>` when SLH-DSA keys are used
- Makes code more self-documenting than using arbitrary secp256k1 key types
- Satisfies the `MiniscriptKey` trait bound without providing actual key functionality

**Usage:**

**For pure SLH-DSA miniscripts (recommended):**
```rust
// Clear and explicit - indicates no secp256k1 keys are used
let ms: Miniscript<NoSecp256k1Key, Tap> = Miniscript::slh_dsa_pk(slh_dsa_key);
let tree = TapTree::leaf(ms);
let mr = Mr::new(Some(tree))?;
```

**For mixed trees combining Schnorr and SLH-DSA leaves:**
```rust
// When mixing key types, use XOnlyPublicKey since TapTree requires a single Pk type
let ms_schnorr: Miniscript<XOnlyPublicKey, Tap> = /* ... */;
let ms_slh_dsa: Miniscript<XOnlyPublicKey, Tap> = Miniscript::slh_dsa_pk(slh_dsa_key);
let tree = TapTree::combine(TapTree::leaf(ms_schnorr), TapTree::leaf(ms_slh_dsa))?;
```

**Note:** `NoSecp256k1Key` implements `ToPublicKey` with `unreachable!()` methods that should never be called in practice, since SLH-DSA operations use the concrete `SlhDsaPublicKey` type internally.

## 5. Technical Details

### 5.1. OP_SUCCESS127

- Opcode: `0x7f` (originally OP_SUBSTR)
- Defined in BIP-342 as an OP_SUCCESS opcode
- Causes immediate script success when executed
- Allows for future soft-fork upgrades
- Actual signature verification happens in consensus layer

### 5.2. SLH-DSA Signature Size

- **Algorithm:** SLH-DSA-128S
- **Public Key:** 32 bytes
- **Signature:** 7856 bytes
- **With SIGHASH:** 7857 bytes total

### 5.3. Comparison with Traditional Signatures

| Type | Public Key Size | Signature Size | Script Size |
|------|----------------|----------------|-------------|
| ECDSA | 33-65 bytes | 73 bytes | 34-66 bytes |
| Schnorr | 32 bytes | 64 bytes | 33 bytes |
| SLH-DSA | 32 bytes | 7856 bytes | 34 bytes |

## 6. Integration with Existing Code

All standard miniscript operations now support SlhDsaPk:
- ✅ Clone
- ✅ PartialEq/Eq
- ✅ Hash
- ✅ Display/Debug
- ✅ Script encoding
- ✅ Satisfaction building (requires custom `Satisfier` with `lookup_slh_dsa_sig` implementation)
- ✅ Type checking
- ⚠️ Key translation (skipped - uses concrete type)
- ⚠️ ForEachKey iteration (skipped - uses concrete type)

### 6.1. Architecture Note: Concrete Type vs Generic Type Parameter

The `Terminal::SlhDsaPk` variant uses a concrete `SlhDsaPublicKey` type rather than the generic `Pk` type parameter. This design decision was made because:

1. **SLH-DSA keys are not secp256k1 keys:** They're 32-byte hash-based values, not elliptic curve points
2. **No MiniscriptKey trait implementation:** SLH-DSA keys don't implement `MiniscriptKey` and its associated traits
3. **Separate validation mechanism:** OP_SUCCESS127 handles validation differently than CHECKSIG operations

**Implications:**
- Key translation operations skip `SlhDsaPk` terminals (see `src/miniscript/mod.rs:669`)
- `ForEachKey` trait doesn't iterate over SLH-DSA keys
- The `Satisfier` trait has been extended with `lookup_slh_dsa_sig()` to handle SLH-DSA signatures separately
- SLH-DSA keys must be provided as concrete `SlhDsaPublicKey` values, not as generic key types
- Custom satisfiers are required to provide SLH-DSA signature lookup functionality

## 7. Files Modified

1. `src/miniscript/decode.rs` - Terminal enum definition
2. `src/miniscript/astelem.rs` - Script encoding
3. `src/miniscript/display.rs` - Display formatting (added `DisplayNode::SlhDsaKey`)
4. `src/miniscript/mod.rs` - Constructor and utilities
5. `src/miniscript/types/mod.rs` - Type checking
6. `src/miniscript/types/extra_props.rs` - Property calculations
7. `src/miniscript/satisfy.rs` - Satisfier trait extension, Placeholder variant, blanket impls, and satisfaction logic
8. `src/descriptor/key.rs` - `SlhDsaPublicKey` type definition
9. `src/lib.rs` - `NoSecp256k1Key` placeholder type definition
10. `examples/slh_dsa_p2mr.rs` - Updated to use `NoSecp256k1Key`
11. `examples/mr.rs` - Updated to use `NoSecp256k1Key` and `SlhDsaPublicKey` properly
9. `src/policy/semantic.rs` - Added `SlhDsaKey` policy variant
10. `src/policy/mod.rs` - Added lifting from `Terminal::SlhDsaPk` to `Semantic::SlhDsaKey`
11. `src/plan.rs` - AssetProvider trait extension for planning/analysis
12. `src/psbt/mod.rs` - PsbtInputSatisfier implementation (with TODO for PSBT field support)
13. `src/util.rs` - Added `SlhDsaSig` placeholder size calculation
14. `examples/slh_dsa_p2mr.rs` - Example demonstrating P2MR with SLH-DSA and custom Satisfier

## 8. Implementation Status

### 8.1. ✅ Completed

1. **Core Miniscript Integration:** `Terminal::SlhDsaPk` variant with script encoding
2. **Type System:** `SlhDsaPublicKey` type in `src/descriptor/key.rs`
3. **Display Support:** Fragment name `"slh_dsa_pk"` and `DisplayNode::SlhDsaKey`
4. **Policy Semantic Support:** `Policy::SlhDsaKey` variant added to semantic policies
5. **Policy Lifting:** Miniscript can be lifted to semantic policy with SLH-DSA keys
6. **Satisfier Trait Extension:** `lookup_slh_dsa_sig` method added to `Satisfier` trait
7. **AssetProvider Extension:** `provider_lookup_slh_dsa_sig` method added for planning
8. **Satisfaction Logic:** Automatic witness building via custom satisfiers
9. **Blanket Impl Updates:** `&S` and `&mut S` impls delegate `lookup_slh_dsa_sig` properly
10. **Placeholder Support:** `Placeholder::SlhDsaSig` variant for template-based satisfaction
11. **Examples:** `examples/slh_dsa_p2mr.rs` demonstrates custom Satisfier implementation and usage

### 8.2. ⚠️ Partial/Limited

1. **PSBT Satisfaction:** `PsbtInputSatisfier` returns `None` - users need custom satisfiers with proprietary fields
2. **Policy Compilation:** Semantic policy exists but compiler doesn't generate SLH-DSA scripts from policies

### 8.3. ❌ Not Yet Implemented

1. **Miniscript String Parsing:** Cannot parse `slh_dsa_pk(KEY)` from strings (no case in `from_tree()`)
2. **Descriptor String Parsing:** Cannot parse descriptors containing SLH-DSA keys from strings
3. **PSBT Support:** Status unknown - likely needs work for SLH-DSA signature integration
4. **Comprehensive Testing:** No test files found in `/tests` directory for SLH-DSA functionality

### 8.4. Next Steps

1. **High Priority:**
   - Add `"slh_dsa_pk"` case to `Miniscript::from_tree()` in `src/miniscript/mod.rs` (~line 923)
   - Add policy compiler support to generate SLH-DSA scripts from `Policy::SlhDsaKey`
   - Propose PSBT field extension for SLH-DSA signatures (requires BIP proposal and bitcoin crate support)

2. **Medium Priority:**
   - Add comprehensive unit tests for satisfaction logic with custom satisfiers
   - Document custom satisfier patterns for PSBT workflows
   - Test and document proprietary PSBT field usage for SLH-DSA

3. **Low Priority:**
   - Performance optimization for large SLH-DSA signatures
   - Additional examples demonstrating custom satisfiers
   - Multi-party signing coordination patterns

## 9. Known Limitations

1. **No String Parsing:** You cannot parse miniscript strings containing `slh_dsa_pk(...)` - you must construct them programmatically using `Miniscript::slh_dsa_pk()`

2. **Custom Satisfier Required:** The `satisfy()` method requires a custom `Satisfier` implementation that provides SLH-DSA signatures via `lookup_slh_dsa_sig()`. Default satisfiers like `()` will return `Witness::Impossible`.

3. **PSBT Support Limited:** `PsbtInputSatisfier` returns `None` for SLH-DSA signatures. Users must implement custom satisfiers that read from proprietary PSBT fields or build witnesses manually.

4. **Key Translation Not Supported:** Generic key translation operations skip `SlhDsaPk` terminals because they use a concrete type.

5. **ForEachKey Doesn't Iterate:** The `ForEachKey` trait doesn't visit SLH-DSA keys since they're not part of the generic `Pk` system.

6. **Policy Compiler Doesn't Generate SLH-DSA:** While `Policy::SlhDsaKey` exists, the policy compiler doesn't yet automatically generate miniscripts with SLH-DSA from policies.

## 10. References

- BIP-342: Validation of Taproot Scripts
- BIP-341: Taproot: SegWit version 1 spending rules
- NIST FIPS 205: Stateless Hash-Based Digital Signature Standard
- [bitcoinpqc crate](https://crates.io/crates/bitcoinpqc) - SLH-DSA implementation

## 11. Notes

- The actual cryptographic verification is handled by the consensus layer (Bitcoin Core with PQC support)
- OP_SUCCESS opcodes skip script execution, making the script always valid from the Script VM perspective
- Signature verification must be done externally by modified Bitcoin Core nodes
- This implementation is compatible with the existing Bitcoin Core PQC branch

## 12. Appendix

### 12.1. Changes Made

#### 12.1.1. New Terminal Variant: `Terminal::SlhDsaPk`

Added a new terminal variant to represent SLH-DSA public key validation using OP_SUCCESS127:

**Location:** `src/miniscript/decode.rs:187-190`

```rust
/// `<32-byte-slh-dsa-key> OP_SUCCESS127` - Post-quantum signature validation
/// This uses OP_SUCCESS (0x7f) as defined in BIP-342 for tapscript upgrades.
/// The actual signature verification happens in consensus code.
SlhDsaPk(crate::descriptor::SlhDsaPublicKey),
```

**Note:** Unlike other terminals, `SlhDsaPk` uses a concrete `SlhDsaPublicKey` type rather than the generic `Pk` type parameter, since SLH-DSA keys are not secp256k1 curve points and don't implement `MiniscriptKey`.

#### 12.1.2. Script Encoding

**Location:** `src/miniscript/astelem.rs:178-185`

The SlhDsaPk terminal encodes as:
- `OP_PUSHBYTES_32` (0x20)
- 32-byte SLH-DSA public key
- `OP_SUCCESS127` (0x7f, repurposed from OP_SUBSTR)

```rust
Terminal::SlhDsaPk(ref pk) => {
    // Encode as: <32-byte-key> OP_SUCCESS127 (0x7f)
    // OP_SUCCESS opcodes cause immediate script success per BIP-342
    // Push the raw 32 bytes directly since SLH-DSA keys are not secp256k1 keys
    builder
        .push_slice(pk.as_bytes())
        .push_opcode(opcodes::all::OP_SUBSTR) // 0x7f - repurposed as OP_SUCCESS127
}
```

#### 12.1.3. Miniscript Constructor

**Location:** `src/miniscript/mod.rs:204-216`

```rust
/// The `slh_dsa_pk` combinator - Post-quantum signature scheme.
/// Encodes as: <32-byte-key> OP_SUCCESS127 (0x7f)
/// 
/// Takes a SLH-DSA (SPHINCS+) post-quantum public key which is just
/// a 32-byte value (not a secp256k1 curve point).
pub fn slh_dsa_pk(pk: crate::descriptor::SlhDsaPublicKey) -> Self {
    Self {
        node: Terminal::SlhDsaPk(pk),
        ty: types::Type::pk_k(), // Same type properties as pk_k
        ext: types::extra_props::ExtData::slh_dsa_pk::<Ctx>(),
        phantom: PhantomData,
    }
}
```

#### 12.1.4. Script Properties (ExtData)

**Location:** `src/miniscript/types/extra_props.rs:239-255`

```rust
pub fn slh_dsa_pk<Ctx: ScriptContext>() -> Self {
    ExtData {
        pk_cost: 34, // 1 byte (OP_PUSHBYTES_32) + 32 bytes (key) + 1 byte (OP_SUCCESS127)
        has_free_verify: false,
        ops: OpLimits::new(0, Some(0), Some(0)), // OP_SUCCESS doesn't count as an op
        stack_elem_count_sat: Some(1), // Just the signature
        stack_elem_count_dissat: Some(1), // Empty signature for dissatisfaction
        max_sat_size: Some((7857, 7857)), // SLH-DSA-128S signature (7856 bytes) + sighash byte
        max_dissat_size: Some((1, 1)), // Empty signature
        timelock_info: TimelockInfo::default(),
        exec_stack_elem_count_sat: Some(1), // pushes the signature
        exec_stack_elem_count_dissat: Some(1),
        tree_height: 0,
    }
}
```

#### 12.1.5. Satisfaction Logic

**Location:** `src/miniscript/satisfy.rs:1308-1323, 1646-1652`

##### 12.1.5.1. Satisfier Trait Extension

The `Satisfier` trait has been extended with a dedicated method for SLH-DSA signature lookup:

**Location:** `src/miniscript/satisfy.rs:93-106`
```rust
/// Given a SLH-DSA public key, look up a post-quantum signature with that key.
///
/// SLH-DSA (Stateless Hash-Based Digital Signature Algorithm) signatures are much larger
/// than ECDSA/Schnorr signatures (~7856 bytes for SLH-DSA-128S). The returned signature
/// should include the sighash byte as the final byte.
///
/// This method is separate from the generic `Pk` signature lookups because `SlhDsaPublicKey`
/// is a concrete type that doesn't implement `MiniscriptKey` or `ToPublicKey`.
fn lookup_slh_dsa_sig(
    &self,
    _: &crate::descriptor::SlhDsaPublicKey,
) -> Option<Vec<u8>> {
    None
}
```

##### 12.1.5.2. Satisfaction Implementation

**Satisfaction:**
```rust
Terminal::SlhDsaPk(ref pk) => Satisfaction {
    // SLH-DSA signatures are much larger (~7856 bytes) than ECDSA/Schnorr
    // Look up the signature using the dedicated slh_dsa_sig lookup method
    let stack = if let Some(sig) = stfr.lookup_slh_dsa_sig(pk) {
        Witness::Stack(vec![sig])
    } else {
        // Signatures cannot be forged
        Witness::Impossible
    };
    Satisfaction {
        stack,
        has_sig: true,
        relative_timelock: None,
        absolute_timelock: None,
    }
},
```

**Dissatisfaction (empty signature):**
```rust
Terminal::SlhDsaPk(..) => Satisfaction {
    // Dissatisfaction for SLH-DSA is an empty signature
    stack: Witness::push_0(),
    has_sig: false,
    relative_timelock: None,
    absolute_timelock: None,
},
```

##### 12.1.5.3. AssetProvider Trait Extension

The `AssetProvider` trait (used for planning/analysis) has also been extended:

**Location:** `src/plan.rs:89-98`
```rust
/// Given a SLH-DSA public key, look up a post-quantum signature with that key.
///
/// Returns the size of the signature if found. SLH-DSA-128S signatures are typically
/// 7857 bytes (7856 bytes + 1 sighash byte).
fn provider_lookup_slh_dsa_sig(&self, _: &crate::descriptor::SlhDsaPublicKey) -> Option<usize> {
    None
}
```

##### 12.1.5.4. PSBT Support Status

**Location:** `src/psbt/mod.rs:336-357`

The `PsbtInputSatisfier` includes the `lookup_slh_dsa_sig` method, but currently returns `None` because the bitcoin crate's PSBT format doesn't yet have dedicated fields for SLH-DSA signatures. Users have two options:

1. **Implement a custom satisfier** that reads SLH-DSA signatures from PSBT proprietary fields
2. **Manually construct witnesses** outside of the PSBT workflow

Example custom satisfier:
```rust
struct MySlhDsaSatisfier<'a> {
    base: PsbtInputSatisfier<'a>,
    slh_dsa_sigs: HashMap<SlhDsaPublicKey, Vec<u8>>,
}

impl<Pk: MiniscriptKey + ToPublicKey> Satisfier<Pk> for MySlhDsaSatisfier<'_> {
    // Delegate all methods to base...
    fn lookup_ecdsa_sig(&self, pk: &Pk) -> Option<bitcoin::ecdsa::Signature> {
        self.base.lookup_ecdsa_sig(pk)
    }
    
    // Override SLH-DSA lookup
    fn lookup_slh_dsa_sig(&self, pk: &SlhDsaPublicKey) -> Option<Vec<u8>> {
        self.slh_dsa_sigs.get(pk).cloned()
    }
    
    // ... other methods
}
```

##### 12.1.5.5. When Satisfaction Logic Becomes Important

The satisfaction/dissatisfaction logic becomes critical in these specific scenarios:

###### 12.1.5.5.1. Creating Spending Witnesses (Most Critical)
The satisfaction logic is used when you need to **spend from a P2MR output** containing an SLH-DSA key. When you call methods like:
- `satisfy()` on a miniscript to build a witness stack
- PSBT operations that automatically construct witnesses
- Any wallet software trying to sign and spend transactions

**Current Impact:** Since satisfaction returns `Witness::Unavailable`, you **cannot use the automatic witness building features**. You must manually construct the witness with the 7857-byte SLH-DSA signature.

###### 12.1.5.5.2. PSBT (Partially Signed Bitcoin Transaction) Workflows
PSBTs rely on the satisfaction logic to:
- Determine what signatures are needed
- Build partial witnesses that can be combined
- Finalize transactions with complete witness data

**Current Impact:** PSBT workflows won't work automatically with SLH-DSA keys.

###### 12.1.5.5.3. Transaction Analysis & Estimation
The satisfaction data is used to:
- **Estimate transaction fees** (via `max_sat_size: 7857 bytes`)
- Determine if you have the necessary keys/data to spend
- Calculate witness weight for fee estimation
- Analyze spending paths in complex scripts

**Current Impact:** While the `ExtData` provides size estimates, you can't use `Satisfier`-based analysis tools.

###### 12.1.5.5.4. Using the Satisfier Trait Extension

**The Solution:** The `Satisfier` trait has been extended with a dedicated SLH-DSA method:
```rust
fn lookup_slh_dsa_sig(&self, pk: &SlhDsaPublicKey) -> Option<Vec<u8>>;
```

This approach keeps SLH-DSA as a **parallel system** alongside the generic `Pk` type, rather than forcing `SlhDsaPublicKey` to implement `MiniscriptKey` (which is impossible since SLH-DSA keys cannot be converted to secp256k1 keys).

**How to Use:** Implement a custom `Satisfier` that provides SLH-DSA signatures:

```rust
use std::collections::HashMap;

struct MySlhDsaSatisfier {
    slh_dsa_sigs: HashMap<SlhDsaPublicKey, Vec<u8>>,
}

impl<Pk: MiniscriptKey + ToPublicKey> Satisfier<Pk> for MySlhDsaSatisfier {
    fn lookup_slh_dsa_sig(&self, pk: &SlhDsaPublicKey) -> Option<Vec<u8>> {
        self.slh_dsa_sigs.get(pk).cloned()
    }
    // ... other methods use default implementations or custom logic
}

// Use it:
let satisfier = MySlhDsaSatisfier { 
    slh_dsa_sigs: my_signature_map 
};
let witness = ms.satisfy(&satisfier)?; // Now works!
```

Now wallets/tools can:
- ✅ Look up SLH-DSA signatures from a signature database
- ✅ Build complete witnesses programmatically  
- ✅ Support SLH-DSA alongside ECDSA/Schnorr

###### 12.1.5.5.5. Practical Example

```rust
// ✅ NOW WORKS with custom Satisfier:
struct MySlhDsaSatisfier {
    slh_dsa_sigs: HashMap<SlhDsaPublicKey, Vec<u8>>,
}

impl<Pk: MiniscriptKey + ToPublicKey> Satisfier<Pk> for MySlhDsaSatisfier {
    fn lookup_slh_dsa_sig(&self, pk: &SlhDsaPublicKey) -> Option<Vec<u8>> {
        self.slh_dsa_sigs.get(pk).cloned()
    }
}

let ms = Miniscript::slh_dsa_pk(slh_key);
let mut sigs = HashMap::new();
sigs.insert(slh_key, slh_dsa_signature);
let satisfier = MySlhDsaSatisfier { slh_dsa_sigs: sigs };
let witness = ms.satisfy(&satisfier)?; // ✅ Works!

// ❌ Default satisfiers (like ()) won't work:
let witness = ms.satisfy(&())?; // Returns Impossible (no signature available)

// ✅ Manual construction still works for simple cases:
let witness = Witness::from_slice(&[
    slh_dsa_signature, // 7857 bytes
    leaf_script,
    control_block,
]);
```

###### 12.1.5.5.6. Summary

The satisfaction logic becomes critical **as soon as you try to spend** from a P2MR output with SLH-DSA keys. 

**Current Status:**
1. ✅ **Satisfier trait extended:** The `lookup_slh_dsa_sig` method allows custom satisfiers to provide signatures
2. ✅ **Satisfaction logic implemented:** Will look up signatures and build witnesses automatically
3. ✅ **AssetProvider extended:** Planning/analysis tools can work with SLH-DSA
4. ⚠️ **PSBT support partial:** Users must implement custom satisfiers or use proprietary fields
5. ⚠️ **Default satisfiers won't help:** Empty satisfiers like `()` will return `Impossible` (no signatures available)

**What Works Now:**
- ✅ Custom satisfiers with SLH-DSA signature lookup
- ✅ Automatic witness construction via `ms.satisfy()`
- ✅ Fee estimation via `ExtData` properties
- ✅ Manual witness construction (as before)

**What Needs Custom Implementation:**
- ⚠️ PSBT workflows (need custom satisfier reading from proprietary fields)
- ⚠️ Multi-party signing coordination
- ⚠️ Hardware wallet integration

#### 12.1.6. Display Support

**Location:** `src/miniscript/display.rs:134, 279`

- Fragment name: `"slh_dsa_pk"`
- Display tree: `Tree::Unary(DisplayNode::SlhDsaKey(pk))`

A dedicated `DisplayNode::SlhDsaKey` variant was added to handle the concrete `SlhDsaPublicKey` type separately from the generic key type.

