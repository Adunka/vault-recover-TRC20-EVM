<div align="center">

# vault·recover

**Recover your own BIP-39 seed phrase — for EVM and TRON wallets.**

You remember most of your phrase but a word or two is gone, smudged, or you
are unsure of the order. You know the address the wallet lives at. This tool
fills the gaps by deriving every candidate and matching it against *your*
address — locally, on the cores you choose, with no network and no balance
lookups.

[![ci](https://github.com/Adunka/vault-recover-TRC20-EVM/actions/workflows/ci.yml/badge.svg)](https://github.com/Adunka/vault-recover-TRC20-EVM/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
[![rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org)

</div>

```
  vault·recover
  recover your own seed phrase — evm & tron

  matches candidates against an address you own.
  no network, no balance lookups, no transfers.
  ───────────────────────────────────────────────────────────

  03  phrase
      type your words in order; use * for each word you don't remember
      ****** ****** ****** ****** ****** ****** ****** ****** ****** ****** ****** ******
```

---

## The one principle everything is built around

> **This is a recovery tool, not a scanner.**

A recovery search is anchored to a **target address you supply** — the wallet
you are trying to get back into. A candidate phrase counts as a hit only when
it *derives to that address*. That single design choice draws a bright line:

| | Recovery (this tool) | Balance scanning (not this tool) |
|---|---|---|
| **Starting point** | most of *your* phrase + *your* address | fragments of *anyone's* phrase |
| **Success test** | candidate derives to *your* address | candidate has money on-chain |
| **Network** | never contacted | required (to read balances) |
| **What it finds** | the wallet you already own | strangers' funded wallets |

Because matching is a local 20-byte comparison against an address you provide,
the tool **never opens a socket**, never reads chain state, and has no concept
of "find a wallet with a balance." It also has no key-sweeping or transfer
code. If you don't know the address, it cannot help you — which is exactly the
property that keeps it a recovery tool.

This is also *why it is fast*: an address match is instant, so the only real
cost is the cryptography, and the BIP-39 checksum throws most candidates away
before even that runs.

---

## Quick start

```bash
cargo build --release
./target/release/vault-recover
```

The console walks you through six steps:

```
  01  chain            evm  or  tron
  02  phrase length    12 / 15 / 18 / 21 / 24
  03  phrase           your words, * for each gap
  04  your address     the wallet you're recovering
  05  cpu cores        how many to spend (detected automatically)
  06  passphrase       BIP-39 25th word, if you set one
```

Entering the phrase is the heart of it. Type the words you remember in order,
and drop a `*` (or `?`, or any run of asterisks) wherever a word is missing:

```
  > legal winner thank year wave sausage worth * useful legal winner *
        10 known . 2 unknown
```

Mistype a word and the tool shows you the wordlist neighbours, since a wrong
word is usually a typo or a smudged letter:

```
  > ... aband ...
    'aband' is not a BIP-39 word - did you mean: abandon
```

When it finds the phrase, it prints it back numbered for copying onto a steel
backup, along with the derivation path and address it matched:

```
  recovered  in 202 ms . 4 candidates examined

     1 abandon    2 abandon    3 abandon
     4 abandon    5 abandon    6 abandon
     7 abandon    8 abandon    9 abandon
    10 abandon   11 abandon   12 about

    path       m/44'/60'/0'/0/0
    address    0x9858EfFD232B4033E47d90003D41EC34EcaEda94
```

---

## How it works

### The derivation pipeline

Every wallet address is the end of a deterministic chain that starts at the
mnemonic. Recovery runs this chain forward for each candidate and compares the
final address to your target.

```
   mnemonic words            "abandon abandon ... about"
        │
        │  BIP-39: PBKDF2-HMAC-SHA512, 2048 rounds, salt = "mnemonic"+passphrase
        ▼
   512-bit seed              c55257c3…7463b04
        │
        │  BIP-32: HMAC-SHA512("Bitcoin seed", seed) → master key + chain code
        ▼
   master key
        │
        │  BIP-44 path: m / 44' / coin' / 0' / 0 / index
        │  coin = 60 for EVM, 195 for TRON     (' = hardened child)
        ▼
   leaf private key
        │
        │  secp256k1: private → public key point (65-byte uncompressed)
        ▼
   public key
        │
        │  keccak256(pubkey[1..]) → take the low 20 bytes
        ▼
   20-byte account id ───────┬──── EVM:  "0x" + hex, EIP-55 mixed-case checksum
                             └──── TRON: 0x41 ‖ id, then Base58Check → "T…"
```

The two chains are identical until the last line — same seed stretch, same
elliptic-curve step, same keccak hash — and diverge only in how the 20 bytes
are *presented*. That shared core is why one engine recovers both.

| Chain | BIP-44 coin type | Default path | Address form |
|-------|:---:|---|---|
| EVM (Ethereum, BSC, Polygon, …) | 60 | `m/44'/60'/0'/0/0` | `0x…` EIP-55 |
| TRON | 195 | `m/44'/195'/0'/0/0` | `T…` Base58Check |

### The checksum: why partial recovery is tractable

A BIP-39 mnemonic is not free-form. The words encode entropy **plus a
checksum**: for a 12-word phrase, the final 4 bits are the top bits of
`SHA-256(entropy)`. Only 1 combination in 2⁴ = 16 is a structurally valid
mnemonic.

That is the lever the whole tool pulls. The expensive step is the seed
stretch (2048 rounds of HMAC-SHA512); the checksum test is a single SHA-256.
So the engine checks the checksum **first** and only derives a seed for the
survivors:

| Missing words | Raw candidates | Pass checksum (≈) | Seeds actually derived |
|:---:|:---:|:---:|:---:|
| 1 | 2 048 | ~128 | a few dozen before the match |
| 2 | 4 194 304 | ~262 000 | seconds–minutes on a few cores |
| 3 | 8.6 billion | ~537 million | hours; gate it behind the estimate |

For a single missing word the search is effectively instant. Each additional
unknown word multiplies the space by 2048, so the tool is at its best when you
genuinely remember most of the phrase — which, for your own backup, you
usually do.

### The search engine

Each position becomes a **slot** with a candidate set:

- a remembered word → one candidate,
- a `*` gap → all 2048 words,
- (in the library) a short list → "either X or Y", for a half-remembered word.

The engine walks the mixed-radix product of those sets in parallel with
[rayon](https://github.com/rayon-rs/rayon), and the pipeline per candidate is:

```
  decode index → fill slots → checksum? ──no──▶ discard (cheap)
                                  │ yes
                                  ▼
                         derive seed (per passphrase)
                                  ▼
                    derive m/44'/coin'/0'/0/{0..N}   (sweep a few address slots)
                                  ▼
                        address == target ? ──▶ done, stop all workers
```

`find_map_any` means the instant any core finds the match, the rest stop.

**Core selection.** Step 05 builds a rayon thread pool with exactly the number
of cores you pick, so you decide how much of the machine to spend — all of it
to finish sooner, or a few cores to keep working while it runs.

**A guard rail.** Searches above ~2⁴⁰ raw candidates (four-plus fully-unknown
words) are refused with guidance to narrow the phrase, and anything expected
to run more than ~30 seconds asks for confirmation with a time estimate first,
so nothing silently churns for days.

---

## Correctness

A recovery tool that derives addresses even slightly wrong is worse than
useless — it would fail to find a phrase that *is* correct, and you would wrongly
conclude your funds are gone. So every layer is pinned to published test
vectors, checked by `cargo test`:

| Layer | Anchored against |
|---|---|
| BIP-39 seed | Trezor spec vector 0 — seed `c55257c3…7463b04` for the all-zero entropy phrase |
| BIP-32 derivation | Spec vector 1 — master key, a hardened child `m/0'`, and a mixed child `m/0'/1` |
| EIP-55 addresses | The canonical mixed-case reference addresses |
| End-to-end EVM | `abandon…about` → `0x9858EfFD232B4033E47d90003D41EC34EcaEda94`, the widely-published address for that phrase |
| End-to-end TRON | Same phrase → `T…` via coin type 195 and Base58Check |
| Engine | Recovers 1 and 2 missing words by address match; returns *no* result for an unrelated address; refuses oversized searches |

The elliptic-curve arithmetic is delegated to the audited
[`secp256k1`](https://github.com/rust-bitcoin/rust-secp256k1) bindings rather
than hand-rolled — the one place where a subtle bug would quietly break
recovery.

```bash
cargo test          # crypto vectors + engine
cargo clippy --all-targets
cargo fmt --check
```

---

## Scope

**Handles**

- 12/15/18/21/24-word phrases, any positions unknown
- EVM and TRON, standard BIP-44 paths, a small sweep of address indices
- an optional BIP-39 passphrase (the "25th word")
- typo hints from the wordlist for mistyped words

**Deliberately absent** — these are the properties that keep it a recovery tool:

- no network access of any kind; nothing is ever sent anywhere
- no on-chain balance lookups, and no notion of "find a funded wallet"
- no key sweeping, signing, or fund-transfer code

**Not yet**

- unknown *word order* as a first-class mode (positional gaps are supported
  today; permutation search over known-but-unordered words is a natural
  extension, still anchored to the target address)
- non-standard derivation paths beyond the BIP-44 account sweep

---

## Security notes

- The tool is **offline by design**. Run it on an air-gapped machine if you
  like; it needs nothing from the network.
- A recovered phrase is printed to your terminal. Treat that output the way you
  treat the phrase itself — anyone who has it controls the wallet. Clear your
  scrollback afterwards, and move funds to a freshly generated wallet if you
  suspect the old backup was ever exposed.
- Nothing is written to disk. There is no log, no cache, no history file.

---

## Layout

```
src/
  wordlist.rs   the 2048-word BIP-39 English list, embedded; binary-search lookup
  bip39.rs      mnemonic checksum, and mnemonic → seed (PBKDF2)
  bip32.rs      HD key derivation down a BIP-44 path
  address.rs    public key → EVM (EIP-55) and TRON (Base58Check) addresses; target matching
  recover.rs    the search engine: slots, checksum pruning, parallel match
  main.rs       the console interface
```

---

## License

Dual-licensed under MIT or Apache-2.0, at your option.

<div align="center">
<sub>Recover what's yours. Nothing else.</sub>
</div>
