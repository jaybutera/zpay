//! Per-escrow keys, spec section 2 and 5.3.
//!
//! Two properties matter. The key must be distinct per escrow, because reusing
//! one links escrows on a public chain and makes one leak lose all of them. And
//! it must be on disk before the funding transaction goes out, because losing
//! it loses the refund path and the ZEC with it.

use zecp2p_escrow::keystore::{public_key, Keystore, KeystoreError};

fn store() -> (tempfile::TempDir, Keystore) {
    let dir = tempfile::tempdir().unwrap();
    let ks = Keystore::new(dir.path());
    (dir, ks)
}

#[test]
fn every_escrow_gets_a_different_key() {
    let (_d, ks) = store();
    let mut seen = std::collections::HashSet::new();
    for i in 0..32 {
        let k = ks.create(&format!("escrow-{i}")).unwrap();
        assert!(
            seen.insert(k.secret_bytes()),
            "escrow {i} was handed a key another escrow already has"
        );
    }
    assert_eq!(seen.len(), 32);
}

#[test]
fn a_key_is_on_disk_before_it_is_returned() {
    // Spec 5.3: the client stores u_priv durably before broadcasting. If
    // `create` returned before the write landed, a crash between the two would
    // leave a funded escrow nobody can refund.
    let (_d, ks) = store();
    let key = ks.create("escrow-a").unwrap();
    let reloaded = ks.load("escrow-a").unwrap();
    assert_eq!(key.secret_bytes(), reloaded.secret_bytes());
}

#[test]
fn a_label_cannot_be_reused() {
    // Silently handing back the old key would mean two escrows sharing one,
    // which is the thing per-escrow keys exist to prevent.
    let (_d, ks) = store();
    ks.create("escrow-a").unwrap();
    assert!(matches!(
        ks.create("escrow-a"),
        Err(KeystoreError::AlreadyExists(_))
    ));
}

#[test]
fn load_or_create_is_idempotent() {
    // What a resumed run needs: the same key back, not a new one.
    let (_d, ks) = store();
    let first = ks.load_or_create("escrow-a").unwrap();
    let second = ks.load_or_create("escrow-a").unwrap();
    assert_eq!(first.secret_bytes(), second.secret_bytes());
}

#[cfg(unix)]
#[test]
fn a_key_file_is_created_owner_only_and_a_wider_one_is_refused() {
    use std::os::unix::fs::PermissionsExt;

    let (_d, ks) = store();
    ks.create("escrow-a").unwrap();
    let path = ks.path_of("escrow-a");
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "the key was created mode {mode:o}");

    // A key any other account can read can spend the escrow.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        ks.load("escrow-a"),
        Err(KeystoreError::TooOpen { .. })
    ));
}

#[test]
fn a_malformed_key_is_refused_rather_than_truncated() {
    let (d, ks) = store();
    let path = d.path().join("escrow-a.key");
    std::fs::write(&path, "not hex at all").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    assert!(matches!(
        ks.load("escrow-a"),
        Err(KeystoreError::Malformed(_))
    ));
}

#[test]
fn the_public_key_is_the_compressed_form_the_script_wants() {
    let (_d, ks) = store();
    let k = ks.create("escrow-a").unwrap();
    let pk = public_key(&k);
    assert_eq!(pk.len(), 33);
    assert!(
        pk[0] == 0x02 || pk[0] == 0x03,
        "the redeem script of spec 4.1 takes compressed keys"
    );
    // And it is the key's own public key, not some other.
    let expect = secp256k1::PublicKey::from_secret_key(&secp256k1::Secp256k1::new(), &k);
    assert_eq!(pk, expect.serialize());
}
