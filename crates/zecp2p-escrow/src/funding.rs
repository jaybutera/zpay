//! The funding transaction, spec 4.2 - and an honest account of which half of
//! it this crate can build.
//!
//! # What is here
//!
//! [`escrow_address`] and [`FundingPlan`] give the client everything it needs to
//! be *paid into*: the redeem script, the P2SH scriptPubKey, the `t3` address,
//! and the exact outpoint to watch. Once an output exists at that address, the
//! release and refund paths in `tx.rs` are complete and tested, and a live node
//! has parsed both.
//!
//! # What is not here, and why
//!
//! Spec 4.2 wants the user to fund from its *shielded* pool. That is not a
//! transaction this crate can build, and the reason is not effort:
//!
//! - An Orchard spend needs a `Note`, its `FullViewingKey`, and a `MerklePath`
//!   witnessed against the note commitment tree at a specific anchor.
//! - Finding the note means trial-decrypting every Orchard action since the
//!   wallet's birthday. Building the path means holding the commitment tree.
//!   Proving needs `orchard::circuit::ProvingKey::build`, which is a large
//!   one-time computation.
//! - None of that comes from the RPC surface an escrow needs. `gettxout` and
//!   `sendrawtransaction` say nothing about notes, and the hosted endpoint does
//!   not expose `z_gettreestate` at all (`Method not found`, checked
//!   2026-09-02). A `zcash_client_backend` wallet syncing against
//!   `lightwalletd` is the supported way to get there.
//!
//! **TODO(shielded-funding):** build the Orchard leg on a
//! `zcash_client_backend` wallet once a lightwalletd endpoint or a local node
//! is available. Until then a funding transaction is produced by an existing
//! wallet - Zashi, `zcash-cli z_sendmany`, or a faucet - paying the address this
//! module computes. The escrow does not care how the output got there: the
//! release and refund spend a transparent P2SH outpoint either way, and nothing
//! in the protocol reads the funding transaction's inputs.
//!
//! The cost of the stub is privacy for the *funding* leg only, and only when
//! the funder pays from a transparent address. It changes no security property
//! of the escrow: sections 4.3, 4.4 and 5 are about spending the outpoint.

use crate::script::{p2sh_script_pubkey, redeem_script, CompressedPubkey, ScriptError};

/// Mainnet P2SH prefix, `t3`.
pub const MAINNET_P2SH_PREFIX: [u8; 2] = [0x1c, 0xbd];
/// Testnet P2SH prefix, `t2`.
pub const TESTNET_P2SH_PREFIX: [u8; 2] = [0x1c, 0xba];

/// Which network an address is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressNetwork {
    Main,
    Test,
}

impl AddressNetwork {
    fn prefix(&self) -> [u8; 2] {
        match self {
            AddressNetwork::Main => MAINNET_P2SH_PREFIX,
            AddressNetwork::Test => TESTNET_P2SH_PREFIX,
        }
    }
}

/// Everything the funder needs, and everything the client needs to watch for
/// the result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FundingPlan {
    pub redeem_script: Vec<u8>,
    pub script_pubkey: Vec<u8>,
    /// Base58Check, `t3` on mainnet and `t2` on testnet.
    pub address: String,
    pub amount_zat: u64,
}

/// Computes the escrow address to pay into.
pub fn escrow_address(
    u_pub: &CompressedPubkey,
    l_pub: &CompressedPubkey,
    refund_height: u64,
    amount_zat: u64,
    network: AddressNetwork,
) -> Result<FundingPlan, ScriptError> {
    let redeem = redeem_script(u_pub, l_pub, refund_height)?;
    let script_pubkey = p2sh_script_pubkey(&redeem);
    // The scriptPubKey is OP_HASH160 <20 bytes> OP_EQUAL, so the hash sits at a
    // fixed offset.
    let address = base58check(&network.prefix(), &script_pubkey[2..22]);
    Ok(FundingPlan {
        redeem_script: redeem,
        script_pubkey,
        address,
        amount_zat,
    })
}

/// The address for a known hash160, so the encoder can be checked against a
/// vector from a live node.
pub fn escrow_address_from_hash(hash: &[u8; 20], network: AddressNetwork) -> String {
    base58check(&network.prefix(), hash)
}

const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Base58Check over a two-byte version prefix and a 20-byte hash.
fn base58check(prefix: &[u8; 2], hash: &[u8]) -> String {
    use sha2::{Digest, Sha256};

    let mut payload = Vec::with_capacity(prefix.len() + hash.len() + 4);
    payload.extend_from_slice(prefix);
    payload.extend_from_slice(hash);
    let checksum = Sha256::digest(Sha256::digest(&payload));
    payload.extend_from_slice(&checksum[..4]);

    // Leading zero bytes become leading '1's, then the rest is base 58.
    let zeros = payload.iter().take_while(|b| **b == 0).count();
    let mut digits: Vec<u8> = Vec::new();
    for byte in &payload[zeros..] {
        let mut carry = *byte as u32;
        for d in digits.iter_mut() {
            carry += (*d as u32) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }

    let mut out = String::with_capacity(zeros + digits.len());
    for _ in 0..zeros {
        out.push('1');
    }
    for d in digits.iter().rev() {
        out.push(ALPHABET[*d as usize] as char);
    }
    out
}


/// The ZIP 244 sighash for one P2PKH input of a transaction that may spend
/// several, for the funding helpers.
///
/// Not part of the protocol: the escrow never spends P2PKH. It exists so a
/// funding run can move coin into an escrow address without a wallet.
///
/// ZIP 244 commits to every input's outpoint, value and scriptPubKey, so a
/// transaction spending more than one output cannot be signed an input at a
/// time from single-input sighashes: each signature has to be taken over the
/// whole input set. `inputs` is therefore the complete set, in the order the
/// transaction will carry them, and `index` says which of them is being
/// signed.
pub fn p2pkh_sighash_multi(
    branch_id: u32,
    inputs: &[(zcash_transparent::bundle::OutPoint, Vec<u8>, u64)],
    index: usize,
    vout: &[zcash_transparent::bundle::TxOut],
) -> Result<[u8; 32], String> {
    use zcash_primitives::transaction::sighash::{signature_hash, SignableInput};
    use zcash_primitives::transaction::txid::TxIdDigester;
    use zcash_primitives::transaction::{TransactionData, TxVersion};
    use zcash_protocol::consensus::BranchId;
    use zcash_protocol::value::Zatoshis;
    use zcash_script::script::Code;
    use zcash_transparent::address::Script;
    use zcash_transparent::bundle::{Bundle, TxIn, TxOut};
    use zcash_transparent::sighash::{SighashType, SignableInput as TSignable};

    if inputs.is_empty() {
        return Err("no inputs to sign".to_string());
    }
    let (_, spk_signed, value_signed) = inputs.get(index).ok_or("input index out of range")?;

    let prevouts: Vec<TxOut> = inputs
        .iter()
        .map(|(_, spk, value)| {
            TxOut::new(
                Zatoshis::const_from_u64(*value),
                Script(Code(spk.clone())),
            )
        })
        .collect();
    let vin: Vec<TxIn<crate::tx::EscrowEffects>> = inputs
        .iter()
        .map(|(outpoint, _, _)| TxIn::from_parts(outpoint.clone(), (), 0xffff_ffff))
        .collect();
    let bundle = Bundle::<crate::tx::EscrowEffects> {
        vin,
        vout: vout.to_vec(),
        authorization: crate::tx::EscrowEffects::for_inputs(prevouts),
    };
    let data = TransactionData::<crate::tx::EscrowUnauthorized>::from_parts(
        TxVersion::V5,
        BranchId::try_from(branch_id).map_err(|_| "unknown branch id".to_string())?,
        0,
        0.into(),
        Some(bundle),
        None,
        None,
        None,
    );
    let b = data.transparent_bundle().ok_or("no transparent bundle")?;
    let code = Script(Code(spk_signed.clone()));
    let spk = Script(Code(spk_signed.clone()));
    let input = TSignable::from_parts(
        b,
        SighashType::ALL,
        index,
        &code,
        &spk,
        Zatoshis::const_from_u64(*value_signed),
    )
    .map_err(|_| "bad input index".to_string())?;
    let parts = data.digest(TxIdDigester);
    Ok(*signature_hash(&data, &SignableInput::Transparent(input), &parts).as_ref())
}

/// The ZIP 244 sighash for a transaction spending a single P2PKH input.
///
/// A thin wrapper over [`p2pkh_sighash_multi`] for the one-input case, which is
/// what the regtest funding helper spends.
pub fn p2pkh_sighash(
    branch_id: u32,
    outpoint: &zcash_transparent::bundle::OutPoint,
    script_pubkey: &[u8],
    value_zat: u64,
    vout: &[zcash_transparent::bundle::TxOut],
) -> Result<[u8; 32], String> {
    p2pkh_sighash_multi(
        branch_id,
        &[(outpoint.clone(), script_pubkey.to_vec(), value_zat)],
        0,
        vout,
    )
}
