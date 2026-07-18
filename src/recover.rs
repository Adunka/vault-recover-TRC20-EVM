//! The recovery search engine.
//!
//! # What makes this recovery and not a scanner
//!
//! Every search is anchored to a **target address the user supplies** — the
//! address of the wallet they are trying to get back into. A candidate is a
//! hit only when it *derives to that address*. The engine never inspects
//! on-chain balances and has no notion of "find a wallet with money in it";
//! it answers exactly one question: "which completion of the phrase I
//! already mostly have unlocks the address I already know is mine?"
//!
//! That anchor is also what makes the search finish. Recovering one or two
//! missing words from a known 12-word backup is a few million candidates at
//! most, and the BIP-39 checksum discards fifteen-sixteenths of those before
//! the expensive step — the PBKDF2 seed stretch — ever runs.

use std::sync::atomic::{AtomicU64, Ordering};

use rayon::prelude::*;

use crate::address::{address_for, Chain, Target};
use crate::bip32::{DerivationPath, XPriv};
use crate::bip39::{checksum_valid, mnemonic_to_seed, WordCount};
use crate::wordlist::WORDS;

/// A single position in the phrase, and what the user knows about it.
#[derive(Debug, Clone)]
pub enum Slot {
    /// The word is known exactly.
    Known(u16),
    /// Nothing is known — any of the 2048 words.
    Any,
    /// One of a short list of possibilities (a smudged word narrowed to a
    /// handful, or "either X or Y").
    OneOf(Vec<u16>),
}

impl Slot {
    fn candidates(&self) -> Vec<u16> {
        match self {
            Slot::Known(i) => vec![*i],
            Slot::Any => (0..2048u16).collect(),
            Slot::OneOf(list) => list.clone(),
        }
    }
}

/// A fully specified recovery problem.
pub struct Puzzle {
    pub slots: Vec<Slot>,
    pub target: Target,
    /// Passphrases (the optional BIP-39 "25th word") to try per candidate.
    /// Defaults to a single empty passphrase.
    pub passphrases: Vec<String>,
    /// Sweep address indices `0..account_range` of the standard path, for
    /// when the funds might sit at index 3 rather than 0.
    pub account_range: u32,
}

impl Puzzle {
    pub fn new(slots: Vec<Slot>, target: Target) -> Self {
        Self {
            slots,
            target,
            passphrases: vec![String::new()],
            account_range: 1,
        }
    }

    /// Reject shapes the engine cannot or should not run, with a reason.
    pub fn validate(&self) -> Result<Plan, PuzzleError> {
        let wc = WordCount::from_len(self.slots.len())
            .ok_or(PuzzleError::BadWordCount(self.slots.len()))?;

        let candidates: Vec<Vec<u16>> = self.slots.iter().map(Slot::candidates).collect();
        if let Some(pos) = candidates.iter().position(Vec::is_empty) {
            return Err(PuzzleError::EmptySlot(pos));
        }

        // Mixed-radix size of the raw candidate space, saturating so an
        // over-broad puzzle reports as "too large" instead of overflowing.
        let mut total: u128 = 1;
        for c in &candidates {
            total = total.saturating_mul(c.len() as u128);
        }
        if total > MAX_CANDIDATES {
            return Err(PuzzleError::SearchTooLarge { candidates: total });
        }

        Ok(Plan {
            candidates,
            total: total as u64,
            word_count: wc,
        })
    }
}

/// The largest raw candidate space the engine will attempt. Beyond this the
/// checksum-valid remainder alone would be hundreds of millions of PBKDF2
/// derivations — the user needs to narrow the phrase further (prefixes,
/// known positions) rather than wait days. Two fully-unknown words sit
/// comfortably under it; three do not.
const MAX_CANDIDATES: u128 = 1u128 << 40;

/// A validated puzzle, ready to run.
pub struct Plan {
    candidates: Vec<Vec<u16>>,
    total: u64,
    word_count: WordCount,
}

impl Plan {
    pub fn total_candidates(&self) -> u64 {
        self.total
    }

    /// Rough count of candidates that will survive the checksum and reach
    /// seed derivation — one in 2^(word_count/3).
    pub fn estimated_derivations(&self) -> u64 {
        self.total >> self.word_count.checksum_bits()
    }
}

/// The outcome of a search.
pub struct Report {
    pub solution: Option<Solution>,
    /// How many candidates were examined (checksum-tested).
    pub examined: u64,
}

/// A recovered phrase and the address it unlocks.
#[derive(Debug, Clone)]
pub struct Solution {
    pub words: Vec<&'static str>,
    pub passphrase: String,
    pub path: String,
    pub address: String,
    pub private_key_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PuzzleError {
    BadWordCount(usize),
    EmptySlot(usize),
    SearchTooLarge { candidates: u128 },
}

impl std::fmt::Display for PuzzleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PuzzleError::BadWordCount(n) => {
                write!(f, "a mnemonic has 12/15/18/21/24 words, got {n}")
            }
            PuzzleError::EmptySlot(i) => {
                write!(f, "position {} has no candidate words", i + 1)
            }
            PuzzleError::SearchTooLarge { candidates } => write!(
                f,
                "search space is {candidates} candidates; narrow the phrase \
                 (more known words, or prefixes for the smudged ones)"
            ),
        }
    }
}

/// Run the search. `on_progress` is called periodically with the number of
/// candidates examined so far, for UI; pass a no-op to ignore it.
pub fn search(puzzle: &Puzzle, plan: &Plan, on_progress: impl Fn(u64) + Sync) -> Report {
    let examined = AtomicU64::new(0);
    let base_path = DerivationPath::parse(&puzzle.target_default_path()).expect("valid path");

    let solution = (0..plan.total).into_par_iter().find_map_any(|n| {
        // Report progress cheaply and only occasionally.
        let count = examined.fetch_add(1, Ordering::Relaxed);
        if count % PROGRESS_STRIDE == 0 {
            on_progress(count);
        }

        let indices = decode(n, &plan.candidates);
        if !checksum_valid(&indices) {
            return None;
        }
        try_candidate(&indices, puzzle, &base_path)
    });

    Report {
        solution,
        examined: examined.load(Ordering::Relaxed),
    }
}

/// Test one checksum-valid candidate against the target across all
/// passphrases and swept address indices.
fn try_candidate(indices: &[u16], puzzle: &Puzzle, base_path: &DerivationPath) -> Option<Solution> {
    let words: Vec<&'static str> = indices.iter().map(|&i| WORDS[i as usize]).collect();
    let chain = puzzle.target.chain;

    for passphrase in &puzzle.passphrases {
        let seed = mnemonic_to_seed(&words, passphrase);
        let master = XPriv::master(&seed);
        for index in 0..puzzle.account_range {
            let path = base_path.with_last(index);
            let Some(key) = master.derive_path(&path) else {
                continue;
            };
            let pubkey = key.public_key_uncompressed();
            if puzzle.target.matches(&pubkey) {
                return Some(Solution {
                    words: words.clone(),
                    passphrase: passphrase.clone(),
                    path: format!("m/44'/{}'/0'/0/{}", chain.coin_type(), index),
                    address: address_for(chain, &pubkey),
                    private_key_hex: hex::encode(key.private_key_bytes()),
                });
            }
        }
    }
    None
}

impl Puzzle {
    fn target_default_path(&self) -> String {
        self.target.chain.default_path()
    }
}

/// How often to fire the progress callback (in candidates). A power of two
/// so the modulo is a mask.
const PROGRESS_STRIDE: u64 = 1 << 16;

/// Decode a linear index into a per-slot word assignment (mixed radix,
/// least-significant slot last).
fn decode(mut n: u64, candidates: &[Vec<u16>]) -> Vec<u16> {
    let mut out = vec![0u16; candidates.len()];
    for (slot, cands) in out.iter_mut().zip(candidates).rev() {
        let radix = cands.len() as u64;
        *slot = cands[(n % radix) as usize];
        n /= radix;
    }
    out
}

/// Convenience: infer a chain's coin type without a `Target`, used by
/// callers that already know the chain.
pub fn coin_type(chain: Chain) -> u32 {
    chain.coin_type()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wordlist::index_of;

    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon \
                          abandon abandon abandon abandon abandon about";
    // The EVM address this phrase derives to at m/44'/60'/0'/0/0.
    const EVM_ADDR: &str = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94";

    fn known_slots() -> Vec<Slot> {
        PHRASE
            .split_whitespace()
            .map(|w| Slot::Known(index_of(w).unwrap()))
            .collect()
    }

    #[test]
    fn decode_is_mixed_radix() {
        let cands = vec![vec![10, 20], vec![30, 40, 50]];
        // n = 4 -> (4 / 3 = 1, 4 % 3 = 1) -> slot0=cands0[1]=20, slot1=cands1[1]=40
        assert_eq!(decode(4, &cands), vec![20, 40]);
        assert_eq!(decode(0, &cands), vec![10, 30]);
        assert_eq!(decode(5, &cands), vec![20, 50]);
    }

    #[test]
    fn recovers_a_single_missing_word() {
        // Blank the last word; the engine must find it by matching the
        // known EVM address, not by any balance lookup.
        let mut slots = known_slots();
        slots[11] = Slot::Any;
        let target = Target::parse(EVM_ADDR).unwrap();
        let puzzle = Puzzle::new(slots, target);
        let plan = puzzle.validate().unwrap();
        assert_eq!(plan.total_candidates(), 2048);

        let report = search(&puzzle, &plan, |_| {});
        let sol = report.solution.expect("word recovered");
        assert_eq!(sol.words.last(), Some(&"about"));
        assert_eq!(sol.address, EVM_ADDR);
        assert_eq!(sol.path, "m/44'/60'/0'/0/0");
    }

    #[test]
    fn recovers_two_missing_words() {
        let mut slots = known_slots();
        slots[0] = Slot::Any;
        slots[11] = Slot::Any;
        let puzzle = Puzzle::new(slots, Target::parse(EVM_ADDR).unwrap());
        let plan = puzzle.validate().unwrap();
        let report = search(&puzzle, &plan, |_| {});
        let sol = report.solution.expect("both words recovered");
        assert_eq!(sol.words[0], "abandon");
        assert_eq!(sol.words[11], "about");
    }

    #[test]
    fn wrong_target_yields_no_solution() {
        let mut slots = known_slots();
        slots[11] = Slot::Any;
        // A valid but unrelated address: nothing in the search space
        // derives to it, so recovery correctly reports failure rather than
        // inventing a match.
        let other = Target::parse("0x0000000000000000000000000000000000000001").unwrap();
        let puzzle = Puzzle::new(slots, other);
        let plan = puzzle.validate().unwrap();
        assert!(search(&puzzle, &plan, |_| {}).solution.is_none());
    }

    #[test]
    fn tron_recovery_uses_coin_type_195() {
        // Same phrase, recovered against its TRON address — exercises the
        // 195 derivation path and Base58Check matching.
        let tron = address_for(
            Chain::Tron,
            &XPriv::master(&mnemonic_to_seed(
                &PHRASE.split_whitespace().collect::<Vec<_>>(),
                "",
            ))
            .derive_path(&DerivationPath::parse("m/44'/195'/0'/0/0").unwrap())
            .unwrap()
            .public_key_uncompressed(),
        );
        let mut slots = known_slots();
        slots[11] = Slot::Any;
        let puzzle = Puzzle::new(slots, Target::parse(&tron).unwrap());
        let plan = puzzle.validate().unwrap();
        let sol = search(&puzzle, &plan, |_| {})
            .solution
            .expect("tron recovered");
        assert_eq!(sol.path, "m/44'/195'/0'/0/0");
        assert!(sol.address.starts_with('T'));
    }

    #[test]
    fn oversized_search_is_refused() {
        // Four fully-unknown words (2^44) exceed the cap; the engine
        // declines with guidance instead of running for days. Three
        // (2^33) is permitted — a long but real recovery scenario the CLI
        // gates behind a time estimate.
        let mut slots = known_slots();
        for slot in slots.iter_mut().take(4) {
            *slot = Slot::Any;
        }
        let puzzle = Puzzle::new(slots, Target::parse(EVM_ADDR).unwrap());
        assert!(matches!(
            puzzle.validate(),
            Err(PuzzleError::SearchTooLarge { .. })
        ));
    }

    #[test]
    fn derivation_estimate_tracks_checksum_pruning() {
        // Two unknown words: 2048^2 raw candidates, one in sixteen
        // surviving the 12-word checksum.
        let mut slots = known_slots();
        slots[0] = Slot::Any;
        slots[5] = Slot::Any;
        let puzzle = Puzzle::new(slots, Target::parse(EVM_ADDR).unwrap());
        let plan = puzzle.validate().unwrap();
        assert_eq!(plan.total_candidates(), 2048 * 2048);
        assert_eq!(plan.estimated_derivations(), 2048 * 2048 / 16);
    }
}
