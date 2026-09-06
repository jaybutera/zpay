//! What build this is, in a form a deploy script can compare.
//!
//! Finding 10: identifying a running binary meant `nm` or `strings` for a
//! symbol, so "is the hub running what I built?" had no answer short of a
//! guess. `build.rs` stamps the commit in; this renders it three ways:
//!
//! - [`describe`] for a log line and `--version`;
//! - [`STAMP`] as a fixed marker `strings` can find in a stripped binary on a
//!   host with no way to run it, which is what a deploy verify does over ssh;
//! - [`as_json`] for a status command.
//!
//! Deliberately a copy of the coordinator's rather than a shared crate. It is
//! forty lines that read three environment variables `build.rs` sets, and the
//! two `build.rs` files must exist per crate anyway - a shared crate would be
//! stamped with its *own* build's hash, which is the one thing this must never
//! report.
//!
//! Nothing here is instance-specific. It says what the *code* is, not whose
//! deployment it belongs to.

/// The commit this binary was built from, short, or `unknown`.
pub const GIT_HASH: &str = env!("ZECP2P_GIT_HASH");

/// Whether the working tree carried uncommitted changes at build time.
///
/// A `const fn` byte compare rather than `==` on `&str`, which is not const.
pub const GIT_DIRTY: bool = {
    let b = env!("ZECP2P_GIT_DIRTY").as_bytes();
    b.len() == 1 && b[0] == b'1'
};

/// Seconds since the epoch when this binary was compiled.
pub const BUILD_TIME: &str = env!("ZECP2P_BUILD_TIME");

/// The crate version from `Cargo.toml`.
pub const PKG_VERSION: &str = env!("CARGO_PKG_VERSION");

/// A marker string `strings` finds in a stripped binary.
///
/// Deliberately one contiguous literal with a distinctive prefix: a deploy
/// script greps for `zecp2p-build:` and reads to the terminator. Splitting it
/// across a `format!` would put nothing findable in `.rodata`.
///
/// # The terminator
///
/// `;` at the end, and it is load-bearing. Rust packs string literals into
/// `.rodata` back to back with no separator, so `strings` returns the stamp in
/// the middle of a run of unrelated messages: without a terminator the obvious
/// `grep -o 'zecp2p-build:[^ ]*'` swallows whatever literal the linker happened
/// to place next, and the extracted hash quietly grows a suffix. A deploy script
/// then compares that against the tree's hash and refuses every deploy, or - if
/// it compares loosely - accepts a stamp it never really parsed.
///
/// [`STAMP_END`] is the character to read up to. `deploy-hub-binary.sh` greps
/// `zecp2p-build:[^;]*`.
pub const STAMP: &str = concat!(
    "zecp2p-build:",
    env!("CARGO_PKG_NAME"),
    ":",
    env!("CARGO_PKG_VERSION"),
    ":",
    env!("ZECP2P_GIT_HASH"),
    ":",
    env!("ZECP2P_GIT_DIRTY"),
    ":",
    env!("ZECP2P_BUILD_TIME"),
    ";",
);

/// What terminates [`STAMP`]. See its note on why one is needed.
pub const STAMP_END: char = ';';

/// One line naming this build, for a log or `--version`.
pub fn describe() -> String {
    format!(
        "{} {} ({}{})",
        env!("CARGO_PKG_NAME"),
        PKG_VERSION,
        GIT_HASH,
        if GIT_DIRTY { "-dirty" } else { "" }
    )
}

/// The same facts as a JSON object, for `/health`.
pub fn as_json() -> serde_json::Value {
    serde_json::json!({
        "package": env!("CARGO_PKG_NAME"),
        "version": PKG_VERSION,
        "git_hash": GIT_HASH,
        "git_dirty": GIT_DIRTY,
        "built_at_unix": BUILD_TIME.parse::<u64>().unwrap_or(0),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The stamp has to be greppable as one literal, because that is the only
    /// way a deploy script identifies a binary it cannot execute. A refactor
    /// that builds it with `format!` would still compile and would silently
    /// break the verify step, so the shape is asserted rather than assumed.
    #[test]
    fn stamp_is_greppable_and_carries_the_hash() {
        assert!(STAMP.starts_with("zecp2p-build:zecp2p-taker:"));
        let body = STAMP.strip_suffix(STAMP_END).expect("the stamp is terminated");
        let fields: Vec<&str> = body.split(':').collect();
        assert_eq!(fields.len(), 6, "stamp is prefix, pkg, version, hash, dirty, time: {STAMP}");
        assert_eq!(fields[3], GIT_HASH);
        assert!(fields[4] == "0" || fields[4] == "1", "dirty is a flag: {}", fields[4]);
    }

    /// The terminator is what makes the stamp extractable from a stripped
    /// binary at all.
    ///
    /// Rust packs `.rodata` literals with no separator, so a `strings` line
    /// carrying the stamp also carries whatever the linker placed next to it.
    /// Without a terminator, extraction reads past the end of the stamp and the
    /// hash grows a suffix - which the deploy script then compares against the
    /// tree and refuses. This asserts the property a shell `grep -o
    /// 'zecp2p-build:[^;]*'` relies on.
    #[test]
    fn the_stamp_can_be_cut_out_of_a_run_of_adjacent_literals() {
        // What `strings` actually returns: the stamp with neighbours either side.
        let packed = format!("some earlier message{STAMP}node reachable");
        let start = packed.find("zecp2p-build:").expect("the prefix is findable");
        let rest = &packed[start..];
        let end = rest.find(STAMP_END).expect("the terminator is findable");
        let extracted = &rest[..end + 1];
        assert_eq!(extracted, STAMP, "extraction must recover the stamp exactly");

        let hash = extracted.split(':').nth(3).unwrap();
        assert_eq!(
            hash, GIT_HASH,
            "the extracted hash must be the hash, with nothing appended"
        );
    }

    /// `describe` is what goes in the startup log, so it must name the commit
    /// and must say when the tree was dirty. A build with neither is a build
    /// nobody can match to a source tree.
    #[test]
    fn describe_names_the_commit() {
        let d = describe();
        assert!(d.contains(GIT_HASH), "{d} should carry {GIT_HASH}");
        assert_eq!(d.contains("-dirty"), GIT_DIRTY);
    }

    /// `/health` consumers read these keys by name.
    #[test]
    fn json_carries_the_fields_health_publishes() {
        let v = as_json();
        assert_eq!(v["git_hash"], GIT_HASH);
        assert_eq!(v["git_dirty"], GIT_DIRTY);
        assert_eq!(v["version"], PKG_VERSION);
        assert!(v["built_at_unix"].as_u64().is_some());
    }
}
