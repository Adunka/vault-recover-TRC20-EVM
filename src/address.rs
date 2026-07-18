//! Deriving the on-chain address from a public key, for the two families
//! this tool targets.
//!
//! Both chains take the same first step — keccak256 of the uncompressed
//! public key, low 20 bytes — and diverge only in presentation: EVM
//! hex-encodes with an EIP-55 case checksum, TRON prepends `0x41` and
//! Base58Check-encodes. That shared core is why one recovery pipeline
//! serves both.

use tiny_keccak::{Hasher, Keccak};

/// Which address family a target belongs to. Also selects the BIP-44 coin
/// type used during derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Chain {
    /// Ethereum and every EVM chain — BIP-44 coin type 60.
    Evm,
    /// TRON — BIP-44 coin type 195.
    Tron,
}

impl Chain {
    pub fn coin_type(self) -> u32 {
        match self {
            Chain::Evm => 60,
            Chain::Tron => 195,
        }
    }

    /// The default account path for this chain, address index 0.
    pub fn default_path(self) -> String {
        format!("m/44'/{}'/0'/0/0", self.coin_type())
    }
}

/// The raw 20-byte account identifier both chains share: `keccak256(pub[1..])`
/// truncated to the low 20 bytes.
pub fn account_hash20(uncompressed_pubkey: &[u8; 65]) -> [u8; 20] {
    let mut keccak = Keccak::v256();
    keccak.update(&uncompressed_pubkey[1..]);
    let mut out = [0u8; 32];
    keccak.finalize(&mut out);
    out[12..].try_into().unwrap()
}

/// EIP-55 mixed-case checksummed hex address, `0x`-prefixed.
pub fn evm_address(hash20: &[u8; 20]) -> String {
    let hex = hex_lower(hash20);
    // A nibble is uppercased when the corresponding nibble of
    // keccak256(lowercase_hex_ascii) is >= 8.
    let mut keccak = Keccak::v256();
    keccak.update(hex.as_bytes());
    let mut digest = [0u8; 32];
    keccak.finalize(&mut digest);

    let mut out = String::with_capacity(42);
    out.push_str("0x");
    for (i, ch) in hex.chars().enumerate() {
        let hash_nibble = (digest[i / 2] >> (4 * (1 - (i % 2)))) & 0x0f;
        if ch.is_ascii_alphabetic() && hash_nibble >= 8 {
            out.push(ch.to_ascii_uppercase());
        } else {
            out.push(ch);
        }
    }
    out
}

/// TRON Base58Check address: `Base58Check(0x41 || hash20)`, which always
/// renders as a `T`-leading 34-character string.
pub fn tron_address(hash20: &[u8; 20]) -> String {
    let mut payload = Vec::with_capacity(21);
    payload.push(0x41);
    payload.extend_from_slice(hash20);
    // `.with_check()` appends the 4-byte double-SHA256 checksum TRON uses.
    bs58::encode(payload).with_check().into_string()
}

/// Render the address for `chain` from a public key.
pub fn address_for(chain: Chain, uncompressed_pubkey: &[u8; 65]) -> String {
    let hash = account_hash20(uncompressed_pubkey);
    match chain {
        Chain::Evm => evm_address(&hash),
        Chain::Tron => tron_address(&hash),
    }
}

/// A target address the user is recovering toward, stored in a
/// case/format-normalized form so comparison is exact and cheap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub chain: Chain,
    /// The canonical 20-byte identifier, decoded once so each candidate is
    /// a 20-byte compare rather than a re-encode.
    hash20: [u8; 20],
}

impl Target {
    /// Parse a user-supplied address, inferring the chain from its shape:
    /// `0x`-hex is EVM, a `T`-leading Base58Check string is TRON.
    pub fn parse(input: &str) -> Result<Self, AddressError> {
        let input = input.trim();
        if let Some(hex) = input
            .strip_prefix("0x")
            .or_else(|| input.strip_prefix("0X"))
        {
            let bytes = decode_hex20(hex).ok_or(AddressError::BadEvm)?;
            return Ok(Self {
                chain: Chain::Evm,
                hash20: bytes,
            });
        }
        if input.starts_with('T') {
            let decoded = bs58::decode(input)
                .with_check(None)
                .into_vec()
                .map_err(|_| AddressError::BadTron)?;
            // 0x41 prefix + 20 bytes; the checksum was already verified.
            if decoded.len() != 21 || decoded[0] != 0x41 {
                return Err(AddressError::BadTron);
            }
            let hash20 = decoded[1..].try_into().unwrap();
            return Ok(Self {
                chain: Chain::Tron,
                hash20,
            });
        }
        Err(AddressError::Unrecognized)
    }

    /// Does this public key derive to the target? A 20-byte comparison —
    /// the format-specific encoding was resolved at parse time.
    pub fn matches(&self, uncompressed_pubkey: &[u8; 65]) -> bool {
        account_hash20(uncompressed_pubkey) == self.hash20
    }

    pub fn render(&self) -> String {
        match self.chain {
            Chain::Evm => evm_address(&self.hash20),
            Chain::Tron => tron_address(&self.hash20),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressError {
    BadEvm,
    BadTron,
    Unrecognized,
}

impl std::fmt::Display for AddressError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            AddressError::BadEvm => "not a valid 0x-prefixed 20-byte address",
            AddressError::BadTron => "not a valid TRON Base58Check address",
            AddressError::Unrecognized => "address is neither EVM (0x…) nor TRON (T…)",
        };
        f.write_str(msg)
    }
}

fn decode_hex20(hex: &str) -> Option<[u8; 20]> {
    if hex.len() != 40 {
        return None;
    }
    let mut out = [0u8; 20];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eip55_checksum_reference() {
        // The canonical EIP-55 example addresses.
        let cases = [
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
            "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
        ];
        for expected in cases {
            let bytes = decode_hex20(&expected[2..].to_lowercase()).unwrap();
            assert_eq!(evm_address(&bytes), expected);
        }
    }

    #[test]
    fn tron_addresses_are_well_formed() {
        let addr = tron_address(&[0x11; 20]);
        assert!(addr.starts_with('T'));
        assert_eq!(addr.len(), 34);
        // Round-trips through the parser back to the same bytes.
        let parsed = Target::parse(&addr).unwrap();
        assert_eq!(parsed.chain, Chain::Tron);
        assert_eq!(parsed.hash20, [0x11; 20]);
    }

    #[test]
    fn target_infers_chain_and_compares_by_bytes() {
        let evm = Target::parse("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed").unwrap();
        assert_eq!(evm.chain, Chain::Evm);
        // Case-insensitive on input; canonical on output.
        let lower = Target::parse("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed").unwrap();
        assert_eq!(evm, lower);

        assert!(matches!(
            Target::parse("nonsense"),
            Err(AddressError::Unrecognized)
        ));
        assert!(matches!(Target::parse("0x1234"), Err(AddressError::BadEvm)));
    }
}
