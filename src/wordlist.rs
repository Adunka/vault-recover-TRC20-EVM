//! The BIP-39 English wordlist, embedded at compile time.
//!
//! The list is sorted and every word has a unique 4-letter prefix — both
//! guaranteed by the spec — so index lookup is a binary search and typo
//! correction can lean on the prefix property.

/// All 2048 words, index-ordered (index *is* the 11-bit value the word
/// encodes).
pub static WORDS: [&str; 2048] = build_words();

const fn build_words() -> [&'static str; 2048] {
    // `include_str!` gives the newline-separated list; split it into a
    // fixed array at compile time so lookups touch no allocation.
    let raw = include_str!("english.txt");
    let bytes = raw.as_bytes();
    let mut out: [&str; 2048] = [""; 2048];
    let mut word_start = 0;
    let mut i = 0;
    let mut count = 0;
    while i <= bytes.len() {
        let at_end = i == bytes.len();
        if at_end || bytes[i] == b'\n' {
            if i > word_start {
                // SAFETY: the source is ASCII, so any byte-aligned slice
                // of it is valid UTF-8; this is a compile-time constant.
                let (_, rest) = bytes.split_at(word_start);
                let (word, _) = rest.split_at(i - word_start);
                out[count] = match std::str::from_utf8(word) {
                    Ok(w) => w,
                    Err(_) => panic!("wordlist is not UTF-8"),
                };
                count += 1;
            }
            word_start = i + 1;
        }
        i += 1;
    }
    if count != 2048 {
        panic!("wordlist must contain exactly 2048 words");
    }
    out
}

/// The 11-bit index of `word`, or `None` if it is not in the list.
///
/// Binary search over the sorted list — O(log 2048) = 11 comparisons.
pub fn index_of(word: &str) -> Option<u16> {
    WORDS.binary_search(&word).ok().map(|i| i as u16)
}

/// Candidate words sharing a prefix with `stem`, for typo correction. The
/// unique-4-prefix property means a 4-plus-character stem yields at most
/// one hit, but shorter stems (a smudged backup) can widen the net.
pub fn with_prefix(stem: &str) -> impl Iterator<Item = (u16, &'static str)> {
    // The list is sorted, so the matches form one contiguous run; find its
    // start, then take while the prefix holds.
    let stem = stem.to_owned();
    let start = WORDS.partition_point(|w| **w < *stem);
    WORDS[start..]
        .iter()
        .take_while(move |w| w.starts_with(&stem))
        .enumerate()
        .map(move |(offset, w)| ((start + offset) as u16, *w))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints_and_ordering() {
        assert_eq!(WORDS[0], "abandon");
        assert_eq!(WORDS[2047], "zoo");
        assert_eq!(WORDS[2], "able");
        assert!(WORDS.windows(2).all(|w| w[0] < w[1]), "sorted, no dups");
    }

    #[test]
    fn round_trip_index() {
        assert_eq!(index_of("abandon"), Some(0));
        assert_eq!(index_of("zoo"), Some(2047));
        assert_eq!(index_of("about"), Some(3));
        assert_eq!(index_of("notaword"), None);
    }

    #[test]
    fn prefix_matches_are_contiguous_and_complete() {
        let hits: Vec<_> = with_prefix("aban").map(|(_, w)| w).collect();
        assert_eq!(hits, vec!["abandon"]);
        // A short stem fans out; every hit must actually carry the prefix.
        assert!(with_prefix("ab").count() > 1);
        assert!(with_prefix("ab").all(|(_, w)| w.starts_with("ab")));
        assert_eq!(with_prefix("zzzz").count(), 0);
    }
}
