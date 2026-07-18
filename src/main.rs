//! Interactive terminal front-end.
//!
//! A deliberately spare console flow: pick a chain, pick a phrase length,
//! type what you remember with `*` in the gaps, name the address you're
//! recovering, choose how many cores to spend, and go. The address is
//! required by design — see the library docs and the README; this binary
//! never opens a socket.

use std::borrow::Cow;
use std::io::{self, IsTerminal, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use vault_recover::address::{Chain, Target};
use vault_recover::bip39::WordCount;
use vault_recover::recover::{search, Plan, Puzzle, PuzzleError, Slot, Solution};
use vault_recover::wordlist::{index_of, with_prefix};

// --- minimal styling -------------------------------------------------------

const RESET: &str = "\x1b[0m";
const DIM: &str = "\x1b[2m";
const BOLD: &str = "\x1b[1m";
const ACCENT: &str = "\x1b[38;5;79m"; // muted teal
const WARN: &str = "\x1b[38;5;179m"; // muted amber

/// Whether ANSI styling should be emitted. Decided once at startup:
/// enabled only for an interactive terminal that accepts VT sequences, and
/// suppressed when output is redirected or `NO_COLOR` is set.
static COLOR: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn use_color() -> bool {
    COLOR.load(std::sync::atomic::Ordering::Relaxed)
}

/// Enable colour if the environment supports it. On Windows this also flips
/// the console into virtual-terminal mode, without which the classic
/// console prints escape codes literally instead of rendering them.
fn init_term() {
    let enabled =
        std::env::var_os("NO_COLOR").is_none() && io::stdout().is_terminal() && enable_vt();
    COLOR.store(enabled, std::sync::atomic::Ordering::Relaxed);
}

#[cfg(windows)]
fn enable_vt() -> bool {
    // Turn on ENABLE_VIRTUAL_TERMINAL_PROCESSING for stdout (and stderr,
    // best-effort). Declared inline so the crate keeps a flat dependency
    // tree; these three calls are the whole of the Win32 surface we need.
    const STD_OUTPUT_HANDLE: u32 = 0xFFFF_FFF5; // (DWORD)-11
    const STD_ERROR_HANDLE: u32 = 0xFFFF_FFF4; // (DWORD)-12
    const ENABLE_VIRTUAL_TERMINAL_PROCESSING: u32 = 0x0004;

    #[link(name = "kernel32")]
    extern "system" {
        fn GetStdHandle(id: u32) -> *mut core::ffi::c_void;
        fn GetConsoleMode(handle: *mut core::ffi::c_void, mode: *mut u32) -> i32;
        fn SetConsoleMode(handle: *mut core::ffi::c_void, mode: u32) -> i32;
    }

    unsafe fn turn_on(id: u32) -> bool {
        let handle = GetStdHandle(id);
        if handle.is_null() {
            return false;
        }
        let mut mode = 0u32;
        if GetConsoleMode(handle, &mut mode) == 0 {
            return false; // not a console (redirected) -> leave colour off
        }
        SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0
    }

    unsafe {
        let stdout_ok = turn_on(STD_OUTPUT_HANDLE);
        let _ = turn_on(STD_ERROR_HANDLE);
        stdout_ok
    }
}

#[cfg(not(windows))]
fn enable_vt() -> bool {
    // POSIX terminals accept the sequences directly.
    true
}

/// Strip SGR/erase escape sequences (`ESC [ ... letter`) so the interface
/// is clean plain text when colour is disabled.
fn strip_ansi(s: &str) -> Cow<'_, str> {
    if !s.contains('\x1b') {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(ch) = chars.next() {
        if ch == '\x1b' {
            // Consume '[' and everything up to the terminating letter.
            for c in chars.by_ref() {
                if c.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(ch);
        }
    }
    Cow::Owned(out)
}

fn render(s: &str) -> Cow<'_, str> {
    if use_color() {
        Cow::Borrowed(s)
    } else {
        strip_ansi(s)
    }
}

// Output macros: format, then strip colour if disabled, then write to the
// right stream. Every print in this file goes through these.
macro_rules! outln {
    () => { println!() };
    ($($a:tt)*) => { println!("{}", render(&format!($($a)*))) };
}
macro_rules! errln {
    () => { eprintln!() };
    ($($a:tt)*) => { eprintln!("{}", render(&format!($($a)*))) };
}
macro_rules! err {
    ($($a:tt)*) => { eprint!("{}", render(&format!($($a)*))) };
}

fn rule() -> String {
    format!("{DIM}  {}{RESET}", "─".repeat(59))
}

fn banner() {
    outln!();
    outln!("  {BOLD}vault{ACCENT}·{RESET}{BOLD}recover{RESET}");
    outln!("  {DIM}recover your own seed phrase — evm & tron{RESET}");
    outln!();
    outln!("  {DIM}matches candidates against an address you own.{RESET}");
    outln!("  {DIM}no network, no balance lookups, no transfers.{RESET}");
    outln!("{}", rule());
}

fn prompt(label: &str) -> String {
    err!("  {ACCENT}>{RESET} {label}");
    let _ = io::stderr().flush();
    let mut line = String::new();
    match io::stdin().read_line(&mut line) {
        Ok(0) => {
            errln!("\n  {DIM}bye.{RESET}");
            std::process::exit(0);
        }
        Ok(_) => line.trim().to_string(),
        Err(_) => std::process::exit(1),
    }
}

fn heading(step: u8, title: &str) {
    outln!();
    outln!("  {DIM}{step:02}{RESET}  {BOLD}{title}{RESET}");
}

fn choose_chain() -> Chain {
    heading(1, "chain");
    outln!(
        "      {DIM}1{RESET}  evm   {DIM}ethereum . bsc . polygon . ...   m/44'/60'/0'/0/x{RESET}"
    );
    outln!(
        "      {DIM}2{RESET}  tron  {DIM}                              m/44'/195'/0'/0/x{RESET}"
    );
    loop {
        match prompt("").as_str() {
            "1" | "evm" | "" => return Chain::Evm,
            "2" | "tron" => return Chain::Tron,
            _ => errln!("  {WARN}enter 1 or 2{RESET}"),
        }
    }
}

fn choose_length() -> WordCount {
    heading(2, "phrase length");
    outln!("      {DIM}how many words does the full phrase have{RESET}");
    outln!("      {DIM}12 . 15 . 18 . 21 . 24{RESET}");
    loop {
        let raw = prompt("");
        if let Ok(n) = raw.parse::<usize>() {
            if let Some(wc) = WordCount::from_len(n) {
                return wc;
            }
        }
        errln!("  {WARN}enter one of 12 / 15 / 18 / 21 / 24{RESET}");
    }
}

fn read_phrase(wc: WordCount) -> Vec<Slot> {
    let n = wc.words();
    heading(3, "phrase");
    outln!("      {DIM}type your words in order; use {RESET}*{DIM} for each word you don't remember{RESET}");
    let placeholder = vec!["******"; n].join(" ");
    outln!("      {DIM}{placeholder}{RESET}");

    loop {
        let raw = prompt("");
        let tokens: Vec<&str> = raw.split_whitespace().collect();
        if tokens.len() != n {
            errln!("  {WARN}expected {n} tokens, got {}{RESET}", tokens.len());
            continue;
        }
        match build_slots(&tokens) {
            Ok(slots) => {
                let unknown = slots.iter().filter(|s| matches!(s, Slot::Any)).count();
                outln!(
                    "      {DIM}{} known . {} unknown{RESET}",
                    n - unknown,
                    unknown
                );
                return slots;
            }
            Err(bad) => report_unknown_word(bad),
        }
    }
}

fn build_slots(tokens: &[&str]) -> Result<Vec<Slot>, String> {
    let mut slots = Vec::with_capacity(tokens.len());
    for tok in tokens {
        if tok.chars().all(|c| c == '*') || *tok == "?" {
            slots.push(Slot::Any);
        } else {
            let word = tok.to_lowercase();
            match index_of(&word) {
                Some(i) => slots.push(Slot::Known(i)),
                None => return Err(word),
            }
        }
    }
    Ok(slots)
}

fn report_unknown_word(word: String) {
    err!("  {WARN}'{word}' is not a BIP-39 word{RESET}");
    let stem = &word[..word.len().min(4)];
    let suggestions: Vec<&str> = with_prefix(stem).map(|(_, w)| w).take(8).collect();
    if suggestions.is_empty() {
        errln!();
    } else {
        errln!("{DIM} - did you mean: {}{RESET}", suggestions.join(", "));
    }
}

fn read_target(chain: Chain) -> Target {
    heading(4, "your address");
    outln!("      {DIM}the wallet you're recovering - candidates are matched against this{RESET}");
    loop {
        let raw = prompt("");
        match Target::parse(&raw) {
            Ok(t) if t.chain == chain => {
                outln!("      {DIM}{}{RESET}", t.render());
                return t;
            }
            Ok(other) => errln!(
                "  {WARN}that's a {} address, but you chose {}{RESET}",
                chain_name(other.chain),
                chain_name(chain)
            ),
            Err(e) => errln!("  {WARN}{e}{RESET}"),
        }
    }
}

fn choose_cores() -> usize {
    let available = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    heading(5, "cpu cores");
    outln!("      {DIM}detected {available}; blank uses all{RESET}");
    loop {
        let raw = prompt("");
        if raw.is_empty() {
            return available;
        }
        if let Ok(n) = raw.parse::<usize>() {
            if (1..=available).contains(&n) {
                return n;
            }
        }
        errln!("  {WARN}enter 1..{available}{RESET}");
    }
}

fn read_passphrase() -> String {
    heading(6, "passphrase");
    outln!("      {DIM}BIP-39 25th word; leave blank if you never set one{RESET}");
    prompt("")
}

fn main() {
    init_term();
    banner();

    let chain = choose_chain();
    let wc = choose_length();
    let slots = read_phrase(wc);
    let target = read_target(chain);
    let cores = choose_cores();
    let passphrase = read_passphrase();

    let mut puzzle = Puzzle::new(slots, target);
    if !passphrase.is_empty() {
        puzzle.passphrases = vec![passphrase];
    }
    puzzle.account_range = 5;

    let plan = match puzzle.validate() {
        Ok(plan) => plan,
        Err(e) => {
            fail(&e);
            return;
        }
    };

    outln!("{}", rule());
    outln!(
        "  {DIM}search space{RESET}  {} candidates  {DIM}~{} to derive{RESET}",
        group(plan.total_candidates()),
        group(plan.estimated_derivations())
    );

    if !confirm_if_large(&plan) {
        outln!("  {DIM}cancelled.{RESET}");
        return;
    }

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(cores)
        .build()
        .expect("thread pool");
    outln!("  {DIM}running on {cores} core(s)...{RESET}\n");

    let counter = Arc::new(AtomicU64::new(0));
    let total = plan.total_candidates();
    let progress = spawn_progress(Arc::clone(&counter), total);

    let start = Instant::now();
    let report = pool.install(|| {
        let counter = Arc::clone(&counter);
        search(&puzzle, &plan, move |c| counter.store(c, Ordering::Relaxed))
    });
    progress.stop();
    let elapsed = start.elapsed();

    match report.solution {
        Some(sol) => show_solution(&sol, report.examined, elapsed),
        None => show_not_found(report.examined, elapsed),
    }
}

fn confirm_if_large(plan: &Plan) -> bool {
    const DERIVS_PER_SEC: u64 = 2_000;
    let secs = plan.estimated_derivations() / DERIVS_PER_SEC;
    if secs < 30 {
        return true;
    }
    outln!(
        "  {WARN}this may take on the order of {}{RESET}",
        human_duration(Duration::from_secs(secs.max(1)))
    );
    matches!(
        prompt("continue? [y/N] ").to_lowercase().as_str(),
        "y" | "yes"
    )
}

fn fail(e: &PuzzleError) {
    outln!("{}", rule());
    outln!("  {WARN}cannot start:{RESET} {e}");
}

struct Progress {
    stop: Arc<AtomicU64>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Progress {
    fn stop(mut self) {
        self.stop.store(1, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        err!("\r\x1b[2K");
        let _ = io::stderr().flush();
    }
}

fn spawn_progress(counter: Arc<AtomicU64>, total: u64) -> Progress {
    let stop = Arc::new(AtomicU64::new(0));
    let stop_flag = Arc::clone(&stop);
    let handle = std::thread::spawn(move || {
        // Only animate for a real terminal; piped output stays quiet.
        let tty = io::stderr().is_terminal();
        let mut last = 0u64;
        let mut last_at = Instant::now();
        while stop_flag.load(Ordering::Relaxed) == 0 {
            std::thread::sleep(Duration::from_millis(200));
            if !tty {
                continue;
            }
            let now = counter.load(Ordering::Relaxed);
            let dt = last_at.elapsed().as_secs_f64().max(1e-3);
            let rate = (now.saturating_sub(last)) as f64 / dt;
            last = now;
            last_at = Instant::now();
            let pct = if total > 0 {
                now as f64 / total as f64 * 100.0
            } else {
                0.0
            };
            err!(
                "\r\x1b[2K  {DIM}{:>5.1}%  {}/{}  {:.0}k/s{RESET}",
                pct,
                group(now),
                group(total),
                rate / 1000.0
            );
            let _ = io::stderr().flush();
        }
    });
    Progress {
        stop,
        handle: Some(handle),
    }
}

fn show_solution(sol: &Solution, examined: u64, elapsed: Duration) {
    outln!(
        "  {ACCENT}recovered{RESET}  {DIM}in {} . {} candidates examined{RESET}",
        human_duration(elapsed),
        group(examined)
    );
    outln!();
    for (row, chunk) in sol.words.chunks(3).enumerate() {
        let mut line = String::from("    ");
        for (col, word) in chunk.iter().enumerate() {
            let idx = row * 3 + col + 1;
            line.push_str(&format!("{DIM}{idx:>2}{RESET} {BOLD}{word:<9}{RESET} "));
        }
        outln!("{line}");
    }
    outln!();
    if !sol.passphrase.is_empty() {
        outln!("    {DIM}passphrase{RESET}  {}", sol.passphrase);
    }
    outln!("    {DIM}path{RESET}       {}", sol.path);
    outln!("    {DIM}address{RESET}    {}", sol.address);
    outln!(
        "    {DIM}priv key{RESET}   {DIM}{}{RESET}",
        sol.private_key_hex
    );
    outln!("{}", rule());
    outln!("  {WARN}keep this phrase offline. anyone who has it controls the wallet.{RESET}");
    outln!();
}

fn show_not_found(examined: u64, elapsed: Duration) {
    outln!(
        "  {WARN}no match{RESET}  {DIM}in {} . {} candidates examined{RESET}",
        human_duration(elapsed),
        group(examined)
    );
    outln!();
    outln!("  {DIM}none of the completions derive to that address. things to check:{RESET}");
    outln!("    {DIM}- the address is the one this phrase actually created{RESET}");
    outln!("    {DIM}- the phrase length is right{RESET}");
    outln!("    {DIM}- a remembered word isn't itself mistaken (mark shaky ones as {RESET}*{DIM}){RESET}");
    outln!("    {DIM}- a passphrase (25th word) was set{RESET}");
    outln!();
}

fn chain_name(chain: Chain) -> &'static str {
    match chain {
        Chain::Evm => "evm",
        Chain::Tron => "tron",
    }
}

fn group(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, ch) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            out.push(' ');
        }
        out.push(ch);
    }
    out
}

fn human_duration(d: Duration) -> String {
    let secs = d.as_secs();
    if d.as_millis() < 1000 {
        return format!("{} ms", d.as_millis());
    }
    match secs {
        0..=59 => format!("{secs}s"),
        60..=3599 => format!("{}m {}s", secs / 60, secs % 60),
        3600..=86399 => format!("{}h {}m", secs / 3600, (secs % 3600) / 60),
        _ => format!("{}d {}h", secs / 86400, (secs % 86400) / 3600),
    }
}
