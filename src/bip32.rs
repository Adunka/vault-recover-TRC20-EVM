//! BIP-32 hierarchical key derivation, narrowed to what wallet recovery
//! needs: private → private child derivation down a fixed path.
//!
//! Public derivation and extended-key serialization are intentionally
//! absent — recovery walks `m/44'/coin'/0'/0/index` from a seed and reads
//! off the leaf private key, nothing more. secp256k1 group arithmetic is
//! delegated to the `secp256k1` bindings; getting scalar addition mod n
//! wrong here would make the tool silently fail to find correct seeds, so
//! it is not something to hand-roll.

use hmac::{Hmac, Mac};
use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use sha2::Sha512;

const HARDENED: u32 = 0x8000_0000;

/// An extended private key: the 32-byte scalar plus its chain code.
#[derive(Clone)]
pub struct XPriv {
    secret: SecretKey,
    chain_code: [u8; 32],
}

impl XPriv {
    /// BIP-32 master key: `HMAC-SHA512("Bitcoin seed", seed)`, left half
    /// the key, right half the chain code.
    pub fn master(seed: &[u8]) -> Self {
        let i = hmac_sha512(b"Bitcoin seed", seed);
        let (il, ir) = i.split_at(32);
        Self {
            // A seed producing an out-of-range master key has probability
            // ~2^-127; treating it as unrecoverable input is correct.
            secret: SecretKey::from_slice(il).expect("valid master key"),
            chain_code: ir.try_into().unwrap(),
        }
    }

    /// Derive one child. `index >= 2^31` selects hardened derivation.
    ///
    /// Returns `None` only for the negligibly rare case where the tweak is
    /// out of range or yields the zero key — BIP-32 says skip such an
    /// index, and for a fixed recovery path it simply means this seed does
    /// not derive here.
    pub fn derive_child(&self, index: u32) -> Option<Self> {
        let mut mac = HmacSha512::new_from_slice(&self.chain_code).expect("any key length");
        if index >= HARDENED {
            mac.update(&[0x00]);
            mac.update(&self.secret.secret_bytes());
        } else {
            mac.update(&PublicKey::from_secret_key(secp(), &self.secret).serialize());
        }
        mac.update(&index.to_be_bytes());
        let i = mac.finalize().into_bytes();
        let (il, ir) = i.split_at(32);

        let tweak = Scalar::from_be_bytes((*il).try_into().unwrap()).ok()?;
        let secret = self.secret.add_tweak(&tweak).ok()?;
        Some(Self {
            secret,
            chain_code: ir.try_into().unwrap(),
        })
    }

    /// Walk a full path from this key.
    pub fn derive_path(&self, path: &DerivationPath) -> Option<Self> {
        let mut key = self.clone();
        for &index in &path.0 {
            key = key.derive_child(index)?;
        }
        Some(key)
    }

    pub fn private_key_bytes(&self) -> [u8; 32] {
        self.secret.secret_bytes()
    }

    /// The 65-byte uncompressed public key (`0x04 || X || Y`), which the
    /// address encoders hash.
    pub fn public_key_uncompressed(&self) -> [u8; 65] {
        PublicKey::from_secret_key(secp(), &self.secret).serialize_uncompressed()
    }
}

/// A parsed BIP-32 path such as `m/44'/60'/0'/0/0`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivationPath(Vec<u32>);

impl DerivationPath {
    /// Parse `m/a'/b/...`; apostrophe or `h` marks a hardened index.
    pub fn parse(s: &str) -> Result<Self, PathError> {
        let mut parts = s.split('/');
        match parts.next() {
            Some("m") => {}
            _ => return Err(PathError::MissingMaster),
        }
        let mut indices = Vec::new();
        for part in parts {
            let (digits, hardened) = match part.strip_suffix(['\'', 'h', 'H']) {
                Some(rest) => (rest, true),
                None => (part, false),
            };
            let mut value: u32 = digits.parse().map_err(|_| PathError::BadIndex)?;
            if value >= HARDENED {
                return Err(PathError::IndexTooLarge);
            }
            if hardened {
                value += HARDENED;
            }
            indices.push(value);
        }
        Ok(Self(indices))
    }

    /// Replace the final (address) index — the component a recovery search
    /// sweeps when the exact account slot is unknown.
    pub fn with_last(&self, index: u32) -> Self {
        let mut indices = self.0.clone();
        if let Some(last) = indices.last_mut() {
            *last = index;
        }
        Self(indices)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathError {
    MissingMaster,
    BadIndex,
    IndexTooLarge,
}

type HmacSha512 = Hmac<Sha512>;

fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    let mut mac = HmacSha512::new_from_slice(key).expect("any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// One reusable signing context. secp256k1 contexts are expensive to build
/// and safe to share across threads, so recovery workers all borrow this.
fn secp() -> &'static Secp256k1<secp256k1::All> {
    use std::sync::OnceLock;
    static CTX: OnceLock<Secp256k1<secp256k1::All>> = OnceLock::new();
    CTX.get_or_init(Secp256k1::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_parsing() {
        let p = DerivationPath::parse("m/44'/60'/0'/0/0").unwrap();
        assert_eq!(p.0, vec![44 + HARDENED, 60 + HARDENED, HARDENED, 0, 0]);
        assert_eq!(
            DerivationPath::parse("m/44'/195'/0'/0/7").unwrap().0.last(),
            Some(&7)
        );
        assert_eq!(DerivationPath::parse("44/0"), Err(PathError::MissingMaster));
        assert_eq!(DerivationPath::parse("m/x"), Err(PathError::BadIndex));
    }

    #[test]
    fn with_last_replaces_only_the_leaf() {
        let p = DerivationPath::parse("m/44'/60'/0'/0/0").unwrap();
        let q = p.with_last(5);
        assert_eq!(q.0, vec![44 + HARDENED, 60 + HARDENED, HARDENED, 0, 5]);
    }

    #[test]
    fn bip32_master_from_known_seed() {
        // BIP-32 spec test vector 1: seed 000102...0f.
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = XPriv::master(&seed);
        assert_eq!(
            hex::encode(master.private_key_bytes()),
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
        );
        assert_eq!(
            hex::encode(master.chain_code),
            "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508"
        );
    }

    #[test]
    fn bip32_hardened_child_vector() {
        // BIP-32 spec vector 1, path m/0'.
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let child = XPriv::master(&seed).derive_child(HARDENED).unwrap();
        assert_eq!(
            hex::encode(child.private_key_bytes()),
            "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea"
        );
    }

    #[test]
    fn bip32_mixed_path_vector() {
        // Same vector, path m/0'/1 — a non-hardened child of a hardened
        // parent, which exercises the public-key branch of CKDpriv.
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let key = XPriv::master(&seed)
            .derive_path(&DerivationPath::parse("m/0'/1").unwrap())
            .unwrap();
        assert_eq!(
            hex::encode(key.private_key_bytes()),
            "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368"
        );
    }
}
