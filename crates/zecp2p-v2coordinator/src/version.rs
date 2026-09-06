//! What build this is, in a form a deploy script can compare.
//!
//! Finding 10: identifying a running binary meant `nm` or `strings` for a
//! symbol, so "is the hub running what I built?" had no answer short of a
//! guess. `build.rs` stamps the commit in; this renders it three ways:
//!
//! - [`describe`] for a log line and `--version`;
//! - [`STAMP`] as a fixed marker `strings` can find in a stripped binary on a
//!   host with no way to run it, which is what a deploy verify does over ssh;
//! - [`as_json`] for `/health`, so an operator comparing the hub against their
//!   laptop reads it over HTTP rather than by shelling in.
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
/// script greps for `zecp2p-build:` and reads the rest of the line. Splitting it
/// across a `format!` would put nothing findable in `.rodata`.
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
);

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
        assert!(STAMP.starts_with("zecp2p-build:zecp2p-v2coordinator:"));
        let fields: Vec<&str> = STAMP.split(':').collect();
        assert_eq!(fields.len(), 6, "stamp is prefix, pkg, version, hash, dirty, time: {STAMP}");
        assert_eq!(fields[3], GIT_HASH);
        assert!(fields[4] == "0" || fields[4] == "1", "dirty is a flag: {}", fields[4]);
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
