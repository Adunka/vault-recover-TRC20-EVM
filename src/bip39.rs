//! BIP-39: mnemonic ↔ entropy, checksum validation, and seed derivation.
//!
//! The checksum is the lever this whole tool pulls. A 12-word mnemonic
//! carries 4 checksum bits, so only 1 in 16 otherwise-valid word
//! combinations is a real mnemonic; for a single missing word that means
//! ~128 candidates out of 2048, and the pruning compounds as more of the
//! phrase is known. Computing the seed (PBKDF2, 2048 rounds) is the
//! expensive step, so we only ever reach it for checksum-valid candidates.

use hmac::Hmac;
use sha2::{Digest, Sha256, Sha512};

/// Number of words in a mnemonic. The variants are exactly those BIP-39
/// allows; the discriminant is the word count itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum WordCount {
    W12 = 12,
    W15 = 15,
    W18 = 18,
    W21 = 21,
    W24 = 24,
}

impl WordCount {
    pub fn from_len(len: usize) -> Option<Self> {
        Some(match len {
            12 => Self::W12,
            15 => Self::W15,
            18 => Self::W18,
            21 => Self::W21,
            24 => Self::W24,
            _ => return None,
        })
    }

    pub const fn words(self) -> usize {
        self as usize
    }

    /// Entropy bits = 11 bits per word minus the checksum tail.
    pub const fn entropy_bits(self) -> usize {
        self.words() * 11 - self.checksum_bits()
    }

    /// Checksum bits = entropy_bits / 32, which for BIP-39 sizes is also
    /// `words / 3`.
    pub const fn checksum_bits(self) -> usize {
        self.words() / 3
    }
}

/// Are these word indices a checksum-valid mnemonic?
///
/// Packs the 11-bit indices into the entropy||checksum bit string, then
/// checks the trailing bits against the leading bits of SHA-256(entropy).
pub fn checksum_valid(indices: &[u16]) -> bool {
    let Some(wc) = WordCount::from_len(indices.len()) else {
        return false;
    };
    let (entropy, actual_checksum) = split_entropy_checksum(indices, wc);
    expected_checksum(&entropy, wc) == actual_checksum
}

/// Given every index except one unknown position, return the *only* word
/// values that complete a valid checksum.
///
/// This is the hot path for single-word recovery: instead of trying all
/// 2048 words and validating each, we still iterate the 2048 candidates
/// but stop at the checksum test before any key derivation. The set it
/// returns is small (≈128 for a 12-word phrase).
pub fn completions_for_missing(indices: &[u16], missing: usize) -> Vec<u16> {
    let mut scratch = indices.to_vec();
    (0..2048u16)
        .filter(|&candidate| {
            scratch[missing] = candidate;
            checksum_valid(&scratch)
        })
        .collect()
}

/// Split packed indices into (entropy bytes, checksum value in low bits).
fn split_entropy_checksum(indices: &[u16], wc: WordCount) -> (Vec<u8>, u32) {
    let mut bits = BitString::new();
    for &index in indices {
        bits.push_u11(index);
    }
    let entropy = bits.take_bytes(wc.entropy_bits());
    let checksum = bits.take_low_bits(wc.checksum_bits());
    (entropy, checksum)
}

fn expected_checksum(entropy: &[u8], wc: WordCount) -> u32 {
    let hash = Sha256::digest(entropy);
    // The checksum is the top `checksum_bits` bits of the hash.
    let bits = wc.checksum_bits();
    let mut value = 0u32;
    for i in 0..bits {
        let byte = hash[i / 8];
        let bit = (byte >> (7 - (i % 8))) & 1;
        value = (value << 1) | bit as u32;
    }
    value
}

/// Derive the 64-byte BIP-39 seed from a mnemonic and optional passphrase
/// (the "25th word"). NFKD normalization is a no-op for the ASCII English
/// list, so the words are joined with single spaces as-is.
pub fn mnemonic_to_seed(words: &[&str], passphrase: &str) -> [u8; 64] {
    let sentence = words.join(" ");
    let salt = format!("mnemonic{passphrase}");
    let mut seed = [0u8; 64];
    pbkdf2::pbkdf2::<Hmac<Sha512>>(sentence.as_bytes(), salt.as_bytes(), 2048, &mut seed)
        .expect("HMAC accepts keys of any length");
    seed
}

/// A big-endian bit accumulator for packing 11-bit words and slicing the
/// result back into bytes and a trailing checksum.
struct BitString {
    bits: Vec<bool>,
    read: usize,
}

impl BitString {
    fn new() -> Self {
        Self {
            bits: Vec::new(),
            read: 0,
        }
    }

    fn push_u11(&mut self, value: u16) {
        for i in (0..11).rev() {
            self.bits.push((value >> i) & 1 == 1);
        }
    }

    fn take_bytes(&mut self, count: usize) -> Vec<u8> {
        let mut out = vec![0u8; count / 8];
        for (i, byte) in out.iter_mut().enumerate() {
            let mut b = 0u8;
            for j in 0..8 {
                b = (b << 1) | self.bits[self.read + i * 8 + j] as u8;
            }
            *byte = b;
        }
        self.read += count;
        out
    }

    fn take_low_bits(&mut self, count: usize) -> u32 {
        let mut value = 0u32;
        for _ in 0..count {
            value = (value << 1) | self.bits[self.read] as u32;
            self.read += 1;
        }
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wordlist::{index_of, WORDS};

    fn indices(sentence: &str) -> Vec<u16> {
        sentence
            .split_whitespace()
            .map(|w| index_of(w).unwrap())
            .collect()
    }

    const ABANDON_ABOUT: &str = "abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon abandon abandon about";

    #[test]
    fn official_seed_vector() {
        // BIP-39 spec vector 0: all-zero entropy, passphrase "TREZOR".
        let words: Vec<&str> = ABANDON_ABOUT.split_whitespace().collect();
        let seed = mnemonic_to_seed(&words, "TREZOR");
        assert_eq!(
            hex::encode(seed),
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553\
             1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
        );
    }

    #[test]
    fn valid_and_invalid_checksums() {
        assert!(checksum_valid(&indices(ABANDON_ABOUT)));
        // "about" is the correct checksum word; "abandon" in its place is
        // a bit pattern that fails the trailing hash bits.
        let mut broken = indices(ABANDON_ABOUT);
        broken[11] = 0; // abandon
        assert!(!checksum_valid(&broken));
    }

    #[test]
    fn single_missing_word_recovers_the_original() {
        let full = indices(ABANDON_ABOUT);
        let completions = completions_for_missing(&full, 11);
        // The real last word must be among the checksum-valid completions,
        // and the set is a small fraction of the 2048 words.
        assert!(completions.contains(&3), "‘about’ completes the checksum");
        assert!(
            completions.len() < 200,
            "checksum prunes hard: {}",
            completions.len()
        );
        // Every returned word genuinely validates.
        for c in &completions {
            let mut trial = full.clone();
            trial[11] = *c;
            assert!(checksum_valid(&trial));
            let _ = WORDS[*c as usize];
        }
    }
}
