//! Stamps the build with the commit it came from.
//!
//! Finding 10: the only way to identify a running binary was `nm` or `strings`
//! for a symbol that happened to have changed. That is not an answer anyone can
//! give under pressure, and it is the reason the hub ran a three-day-old taker
//! for three days without anyone noticing.
//!
//! Everything here degrades to a string rather than failing the build. A source
//! tarball with no `.git`, a CI checkout with no `git` on PATH, and a vendored
//! build all have to compile; what they lose is the hash, not the binary.

use std::process::Command;

fn main() {
    // Rebuild when the commit moves. `.git/HEAD` covers a checkout or a commit
    // on the current branch; the ref file covers a commit that moves the branch
    // HEAD points at.
    if let Some(git_dir) = git_dir() {
        println!("cargo:rerun-if-changed={}/HEAD", git_dir.display());
        if let Ok(head) = std::fs::read_to_string(git_dir.join("HEAD")) {
            if let Some(reference) = head.trim().strip_prefix("ref: ") {
                println!("cargo:rerun-if-changed={}/{reference}", git_dir.display());
            }
        }
    }

    println!("cargo:rustc-env=ZECP2P_GIT_HASH={}", git_hash());
    println!("cargo:rustc-env=ZECP2P_GIT_DIRTY={}", git_dirty());
    println!("cargo:rustc-env=ZECP2P_BUILD_TIME={}", build_time());
}

fn git_dir() -> Option<std::path::PathBuf> {
    let out = Command::new("git")
        .args(["rev-parse", "--absolute-git-dir"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let path = String::from_utf8(out.stdout).ok()?;
    Some(std::path::PathBuf::from(path.trim()))
}

/// The short commit hash, or `unknown` where git cannot say.
///
/// `SOURCE_DATE_EPOCH`-style overrides are honoured through
/// `ZECP2P_GIT_HASH_OVERRIDE` so a packager that builds from a tarball can put
/// the real hash back without patching this file.
fn git_hash() -> String {
    if let Ok(forced) = std::env::var("ZECP2P_GIT_HASH_OVERRIDE") {
        if !forced.trim().is_empty() {
            return forced.trim().to_string();
        }
    }
    Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Whether the tree had uncommitted changes at build time.
///
/// Worth a field of its own: "it is `1a705d4`" and "it is `1a705d4` plus
/// whatever was in the tree" are different answers to "what is running", and
/// the second one is the one that wastes an hour during an incident.
fn git_dirty() -> String {
    let dirty = Command::new("git")
        .args(["status", "--porcelain", "--untracked-files=no"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| !o.stdout.is_empty())
        .unwrap_or(false);
    if dirty { "1" } else { "0" }.to_string()
}

fn build_time() -> String {
    // No chrono here: build scripts should not drag a dependency in for one
    // timestamp. Seconds since the epoch is enough to compare two builds, and
    // the deploy script renders it.
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_else(|_| "0".to_string())
}
