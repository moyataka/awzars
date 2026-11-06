//! Encrypted cookie store — ChaCha20-Poly1305 with versioned keys in the OS keyring.
//!
//! On-disk cookie file layout: `[1 byte key_id][12 byte nonce][ciphertext + 16 byte tag]`.
//! The leading byte identifies which key in the keystore was used for this file.
//!
//! The keystore is a single OS-keyring item (`{profile}:cookie_key`) holding a
//! JSON blob `{current, keys{id -> base64 key}, created_at{id -> unix seconds}}`.
//! Storing every version in the same keyring item is deliberate: macOS Keychain
//! ACLs are per-item, so reusing one item means the user grants permission once
//! and rotation never re-prompts.
//!
//! Rotation: when the current key is older than 30 days, the next encrypt
//! generates a new key, makes it current, and lazily garbage-collects keys
//! older than 90 days. This gives ~one rotation period of safety margin for
//! any in-flight cookie file written under an older key.

use crate::error::{AwzarsError, Result};
use crate::storage::keyring::{read_secret, KeyringStorage};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use keyring::Entry;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::num::NonZeroU8;
use std::sync::{Mutex, TryLockError};
use zeroize::{Zeroize, Zeroizing};

/// How long a key remains the "current" key before rotation triggers.
const ROTATION_INTERVAL_SECS: i64 = 30 * 24 * 60 * 60;

/// How long a non-current key is retained before garbage collection. Set to
/// 3× the rotation interval so a cookie file written under the previous key
/// can still be decrypted if the user does not re-authenticate immediately.
const KEY_RETENTION_SECS: i64 = 90 * 24 * 60 * 60;

/// On-disk JSON shape stored in the keyring. `current` is `u8` on the wire
/// (0 is reserved and rejected at parse time); the in-memory `CachedStore`
/// uses `NonZeroU8` so the invalid state is unrepresentable.
#[derive(Serialize, Deserialize)]
struct KeyStoreJson {
    current: u8,
    keys: BTreeMap<String, String>,
    created_at: BTreeMap<String, i64>,
}

/// In-memory keystore. `Zeroizing<[u8; 32]>` ensures key material is wiped
/// when the entry is dropped (eviction, replacement, or process cleanup).
#[derive(Clone)]
struct CachedStore {
    current: NonZeroU8,
    keys: BTreeMap<u8, Zeroizing<[u8; 32]>>,
    created_at: BTreeMap<u8, i64>,
}

/// Per-process cache of keystores. Avoids repeated keyring reads (and on
/// macOS, repeated Keychain dialogs) within a single login flow.
static STORE_CACHE: Mutex<Option<HashMap<String, CachedStore>>> = Mutex::new(None);

/// Makes `encrypt` calls take turns loading, rotating and saving a keystore,
/// so two threads never load, create or rotate the same one at once.
/// `STORE_CACHE` is never held across a keychain read (which can wait on a
/// macOS prompt), so `decrypt` and `cleanup_keys` don't wait behind one.
static KEYSTORE_LOCK: Mutex<()> = Mutex::new(());

fn now_unix_secs() -> i64 {
    chrono::Utc::now().timestamp()
}

fn generate_key() -> Result<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0u8; 32]);
    getrandom::fill(key.as_mut())
        .map_err(|e| AwzarsError::Storage(format!("Failed to generate cookie key: {}", e)))?;
    Ok(key)
}

fn parse_keystore(value: &str, now: i64) -> Result<CachedStore> {
    // Try the JSON layout first (current format).
    if let Ok(json) = serde_json::from_str::<KeyStoreJson>(value) {
        let mut keys = BTreeMap::new();
        for (id_str, b64) in &json.keys {
            let id: u8 = id_str
                .parse()
                .map_err(|_| AwzarsError::Storage(format!("Bad key id in keystore: {}", id_str)))?;
            let mut bytes = BASE64.decode(b64).map_err(|e| {
                AwzarsError::Storage(format!("Invalid cookie key in keyring: {}", e))
            })?;
            if bytes.len() != 32 {
                bytes.zeroize();
                return Err(AwzarsError::Storage("Cookie key must be 32 bytes".into()));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            bytes.zeroize();
            keys.insert(id, Zeroizing::new(arr));
        }
        let created_at: BTreeMap<u8, i64> = json
            .created_at
            .iter()
            .filter_map(|(k, v)| k.parse::<u8>().ok().map(|id| (id, *v)))
            .collect();
        let current = NonZeroU8::new(json.current).ok_or_else(|| {
            AwzarsError::Storage("Invalid cookie keystore: current key id is 0".into())
        })?;
        return Ok(CachedStore {
            current,
            keys,
            created_at,
        });
    }

    // Legacy layout: raw base64-encoded 32-byte key, no JSON, no version map.
    // Treat it as key id 1 and silently migrate on the next save.
    let mut bytes = BASE64
        .decode(value)
        .map_err(|e| AwzarsError::Storage(format!("Invalid cookie key in keyring: {}", e)))?;
    if bytes.len() != 32 {
        bytes.zeroize();
        return Err(AwzarsError::Storage("Cookie key must be 32 bytes".into()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    bytes.zeroize();

    let mut keys = BTreeMap::new();
    keys.insert(1u8, Zeroizing::new(arr));
    let mut created_at = BTreeMap::new();
    created_at.insert(1u8, now);

    Ok(CachedStore {
        current: NonZeroU8::MIN,
        keys,
        created_at,
    })
}

fn serialize_keystore(store: &CachedStore) -> Result<Zeroizing<String>> {
    // Holding the base64-encoded keys inside a Zeroizing wrapper means the
    // heap buffer is wiped on drop. The intermediate per-key base64 Strings
    // built inside `.map(...)` are still un-zeroed, but they get folded into
    // the final JSON immediately and dropped together with the temporary
    // KeyStoreJson at end of this function.
    let json = KeyStoreJson {
        current: store.current.get(),
        keys: store
            .keys
            .iter()
            .map(|(id, key)| (id.to_string(), BASE64.encode(key.as_ref())))
            .collect(),
        created_at: store
            .created_at
            .iter()
            .map(|(id, ts)| (id.to_string(), *ts))
            .collect(),
    };
    serde_json::to_string(&json)
        .map(Zeroizing::new)
        .map_err(|e| AwzarsError::Storage(format!("Failed to serialize keystore: {}", e)))
}

fn save_keystore(keyring: &KeyringStorage, store: &CachedStore) -> Result<()> {
    let entry = keyring.entry_for_field("cookie_key")?;
    save_keystore_to_entry(&entry, store)
}

fn save_keystore_to_entry(entry: &Entry, store: &CachedStore) -> Result<()> {
    let serialized = serialize_keystore(store)?;
    entry
        .set_password(&serialized)
        .map_err(|e| AwzarsError::Keyring(format!("Failed to store cookie keystore: {}", e)))?;
    Ok(())
}

fn load_or_init_store(profile: &str) -> Result<CachedStore> {
    let keyring = KeyringStorage::new(profile)?;
    let entry = keyring.entry_for_field("cookie_key")?;
    load_or_init_from_entry(&entry, now_unix_secs())
}

/// Load the keystore for decrypting. Unlike `load_or_init_store`, a missing
/// keystore is an error and nothing is created: a new key could never decrypt
/// an existing cookie file.
fn load_store(profile: &str) -> Result<CachedStore> {
    let keyring = KeyringStorage::new(profile)?;
    let entry = keyring.entry_for_field("cookie_key")?;
    load_from_entry(&entry, now_unix_secs())?.ok_or_else(|| {
        AwzarsError::Storage(
            "No cookie encryption key in the keyring (deleted, or never created) \
             — re-authenticate to regenerate"
                .into(),
        )
    })
}

/// Load the keystore from `entry`, or `None` when the entry does not exist.
/// Any other keychain read error is returned.
fn load_from_entry(entry: &Entry, now: i64) -> Result<Option<CachedStore>> {
    // `read_secret` returns the value wrapped in `Zeroizing`, so the
    // base64-encoded cookie keys are wiped from heap after we parse.
    let Some(value) = read_secret(entry, "the cookie encryption key")? else {
        return Ok(None);
    };
    let store = parse_keystore(&value, now)?;
    // If we read the legacy single-key format, persist the JSON
    // version so the next read takes the fast path.
    let is_legacy = serde_json::from_str::<KeyStoreJson>(&value).is_err();
    if is_legacy {
        save_keystore_to_entry(entry, &store)?;
    }
    Ok(Some(store))
}

/// Load the keystore from `entry`, creating and saving a new one only when
/// the entry does not exist. Any other keychain read error is returned and
/// nothing is written, so an existing keystore is never replaced because it
/// could not be read.
fn load_or_init_from_entry(entry: &Entry, now: i64) -> Result<CachedStore> {
    match load_from_entry(entry, now)? {
        Some(store) => Ok(store),
        None => {
            let key = generate_key()?;
            let mut keys = BTreeMap::new();
            keys.insert(1u8, key);
            let mut created_at = BTreeMap::new();
            created_at.insert(1u8, now);
            let store = CachedStore {
                current: NonZeroU8::MIN,
                keys,
                created_at,
            };
            save_keystore_to_entry(entry, &store)?;
            Ok(store)
        }
    }
}

/// If the current key is past its rotation window, mint a new key, make it
/// current, and GC keys past the retention window. Returns true if rotation
/// happened (caller must persist).
fn rotate_if_needed(store: &mut CachedStore) -> Result<bool> {
    let now = now_unix_secs();
    let current_age = match store.created_at.get(&store.current.get()) {
        Some(ts) => now.saturating_sub(*ts),
        None => return Ok(false),
    };
    if current_age < ROTATION_INTERVAL_SECS {
        return Ok(false);
    }

    let new_id = store
        .current
        .get()
        .checked_add(1)
        .and_then(NonZeroU8::new)
        .ok_or_else(|| {
            AwzarsError::Storage(
                "Cookie key id space exhausted (255 rotations); run `awzars delete-profile` \
                 and configure the profile again to reset"
                    .into(),
            )
        })?;

    let new_key = generate_key()?;
    store.keys.insert(new_id.get(), new_key);
    store.created_at.insert(new_id.get(), now);
    store.current = new_id;

    let cutoff = now.saturating_sub(KEY_RETENTION_SECS);
    let current_raw = store.current.get();
    let to_remove: Vec<u8> = store
        .created_at
        .iter()
        .filter(|(id, ts)| **id != current_raw && **ts < cutoff)
        .map(|(id, _)| *id)
        .collect();
    for id in to_remove {
        store.keys.remove(&id);
        store.created_at.remove(&id);
    }

    Ok(true)
}

#[cfg(test)]
fn cache_lookup(profile: &str) -> Option<(u8, [u8; 32])> {
    let guard = STORE_CACHE.lock().ok()?;
    let map = guard.as_ref()?;
    let store = map.get(profile)?;
    let key = store.keys.get(&store.current.get())?;
    Some((store.current.get(), **key))
}

fn cache_lookup_specific(profile: &str, id: u8) -> Option<Zeroizing<[u8; 32]>> {
    let guard = STORE_CACHE.lock().ok()?;
    let map = guard.as_ref()?;
    let store = map.get(profile)?;
    store.keys.get(&id).cloned()
}

/// Take the profile's store out of the cache if it holds its current key.
/// `STORE_CACHE` is held only for the take.
fn cache_take(profile: &str) -> Option<CachedStore> {
    let mut guard = STORE_CACHE.lock().ok()?;
    let map = guard.as_mut()?;
    let store = map.get(profile)?;
    if !store.keys.contains_key(&store.current.get()) {
        return None;
    }
    map.remove(profile)
}

fn cache_replace(profile: &str, store: CachedStore) {
    if let Ok(mut guard) = STORE_CACHE.lock() {
        guard
            .get_or_insert_with(HashMap::new)
            .insert(profile.to_string(), store);
    }
}

/// Wipe all in-memory key material. Call before `std::process::exit` or from
/// a panic hook so keys do not linger in heap memory after the process is gone.
pub fn cleanup_keys() {
    wipe_cache(&STORE_CACHE);
}

/// Drop every keystore in `cache`, unless its lock is held.
///
/// The panic hook calls this, and the panic may come from a thread that
/// already holds the lock (inside `encrypt` or `decrypt`). Locking a std
/// `Mutex` again on that thread may deadlock, so a held lock skips the wipe
/// instead of waiting. A poisoned lock is not held: its holder panicked and
/// released it while unwinding, so the keys are still wiped.
fn wipe_cache(cache: &Mutex<Option<HashMap<String, CachedStore>>>) {
    let mut guard = match cache.try_lock() {
        Ok(g) => g,
        Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
        Err(TryLockError::WouldBlock) => return,
    };
    // Dropping the HashMap drops every CachedStore, which drops every
    // Zeroizing<[u8; 32]>, which zeroes the bytes.
    *guard = None;
}

/// Encrypt a JSON payload for the given profile. Returns binary file contents.
///
/// Format: `[1 byte key_id][12 byte nonce][ciphertext + 16 byte tag]`.
pub fn encrypt(profile: &str, json: &[u8]) -> Result<Vec<u8>> {
    encrypt_with_loader(profile, json, load_or_init_store)
}

/// `encrypt`, with the keychain load passed in so tests can replace it.
fn encrypt_with_loader(
    profile: &str,
    json: &[u8],
    load: impl Fn(&str) -> Result<CachedStore>,
) -> Result<Vec<u8>> {
    let keyring = KeyringStorage::new(profile)?;

    // Load (cache or keyring), rotate if stale, persist + cache the result.
    let (key_id, key_bytes) = {
        // Held until the store is back in the cache. The lock guards no
        // data, so a poisoned one is still usable.
        let _turn = KEYSTORE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Take the store out of the cache (we may rotate). Without one, read
        // the keychain with STORE_CACHE unlocked, then check the cache again:
        // a store that `decrypt` cached meanwhile wins over the one read here.
        let store = match cache_take(profile) {
            Some(s) => s,
            None => {
                let loaded = load(profile)?;
                cache_take(profile).unwrap_or(loaded)
            }
        };

        // Rotate a copy. If rotating or saving fails, the store taken out
        // above goes back into the cache unchanged: the next call does not
        // read the keychain again, and a key that was never saved is never
        // used.
        let mut rotated_store = store.clone();
        let result = rotate_if_needed(&mut rotated_store).and_then(|rotated| {
            if rotated {
                save_keystore(&keyring, &rotated_store)
            } else {
                Ok(())
            }
        });
        if let Err(e) = result {
            cache_replace(profile, store);
            return Err(e);
        }
        let store = rotated_store;

        let Some(bytes) = store.keys.get(&store.current.get()).cloned() else {
            cache_replace(profile, store);
            return Err(AwzarsError::Storage(
                "Current cookie key missing from keystore".into(),
            ));
        };
        let id = store.current.get();
        cache_replace(profile, store);
        (id, bytes)
    };

    let cipher = ChaCha20Poly1305::new_from_slice(key_bytes.as_ref())
        .map_err(|e| AwzarsError::Storage(format!("Cipher init failed: {}", e)))?;

    let mut nonce_bytes = [0u8; 12];
    getrandom::fill(&mut nonce_bytes)
        .map_err(|e| AwzarsError::Storage(format!("Nonce generation failed: {}", e)))?;
    let nonce = Nonce::from(nonce_bytes);

    let ciphertext = cipher
        .encrypt(&nonce, json)
        .map_err(|e| AwzarsError::Storage(format!("Cookie encryption failed: {}", e)))?;

    let mut output = Vec::with_capacity(1 + 12 + ciphertext.len());
    output.push(key_id);
    output.extend_from_slice(&nonce_bytes);
    output.extend(ciphertext);

    Ok(output)
}

/// Decrypt binary cookie file contents back to JSON bytes.
pub fn decrypt(profile: &str, data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    decrypt_with_loader(profile, data, load_store)
}

fn decrypt_with_loader(
    profile: &str,
    data: &[u8],
    load: impl FnOnce(&str) -> Result<CachedStore>,
) -> Result<Zeroizing<Vec<u8>>> {
    if data.len() < 1 + 12 + 16 {
        return Err(AwzarsError::Storage("Cookie file too short".into()));
    }
    let key_id = data[0];
    if key_id == 0 {
        return Err(AwzarsError::Storage(
            "Cookie file has reserved key id 0".into(),
        ));
    }

    let key_bytes = if let Some(k) = cache_lookup_specific(profile, key_id) {
        k
    } else {
        let store = load(profile)?;
        let key = store
            .keys
            .get(&key_id)
            .ok_or_else(|| {
                AwzarsError::Storage(format!(
                    "Cookie file references key version {} which is no longer in the keyring \
                     (rotated out, deleted, or never existed) — re-authenticate to regenerate",
                    key_id
                ))
            })?
            .clone();
        if let Ok(mut guard) = STORE_CACHE.lock() {
            guard
                .get_or_insert_with(HashMap::new)
                .entry(profile.to_string())
                .or_insert(store);
        }
        key
    };

    let cipher = ChaCha20Poly1305::new_from_slice(key_bytes.as_ref())
        .map_err(|e| AwzarsError::Storage(format!("Cipher init failed: {}", e)))?;

    let nonce = Nonce::from_slice(&data[1..13]);
    let ciphertext = &data[13..];

    cipher
        .decrypt(nonce, ciphertext)
        .map(Zeroizing::new)
        .map_err(|e| {
            AwzarsError::Storage(format!(
                "Cookie decryption failed — keyring entry may have been deleted: {}",
                e
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delayed_decrypt_does_not_replace_a_rotated_keystore() {
        let profile = "delayed-decrypt-regression";
        let older = stale_store(1);
        let encrypted = encrypt_with_key(1, &older.keys[&1], b"session");
        let mut newer = older.clone();
        rotate_if_needed(&mut newer).unwrap();
        let expected = newer.keys[&newer.current.get()].clone();
        let plaintext: Zeroizing<Vec<u8>> = decrypt_with_loader(profile, &encrypted, |_| {
            cache_replace(profile, newer);
            Ok(older)
        })
        .unwrap();
        assert_eq!(plaintext.as_slice(), b"session");
        assert_eq!(cache_lookup_specific(profile, 2), Some(expected));
        assert_eq!(cache_take(profile).unwrap().current.get(), 2);
    }

    /// Direct encrypt/decrypt with raw keys (no keyring) for testing the crypto layer.
    fn encrypt_with_key(key_id: u8, key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
        let cipher = ChaCha20Poly1305::new_from_slice(key).unwrap();
        let mut nonce_bytes = [0u8; 12];
        getrandom::fill(&mut nonce_bytes).unwrap();
        let nonce = Nonce::from(nonce_bytes);
        let ciphertext = cipher.encrypt(&nonce, plaintext).unwrap();
        let mut output = Vec::with_capacity(1 + 12 + ciphertext.len());
        output.push(key_id);
        output.extend_from_slice(&nonce_bytes);
        output.extend(ciphertext);
        output
    }

    fn decrypt_with_key(key_id: u8, key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 1 + 12 + 16 {
            return Err(AwzarsError::Storage("Cookie file too short".into()));
        }
        if data[0] != key_id {
            return Err(AwzarsError::Storage(format!(
                "Key id mismatch: file has {}, expected {}",
                data[0], key_id
            )));
        }
        let cipher = ChaCha20Poly1305::new_from_slice(key).unwrap();
        let nonce = Nonce::from_slice(&data[1..13]);
        let ciphertext = &data[13..];
        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| AwzarsError::Storage(format!("Decryption failed: {}", e)))
    }

    #[test]
    fn generated_keys_are_random() {
        let first = generate_key().unwrap();
        let second = generate_key().unwrap();
        assert_ne!(first, second, "two generated keys must differ");
        for key in [first, second] {
            assert!(
                key.iter().any(|&byte| byte != key[0]),
                "a generated key must not repeat one byte"
            );
        }
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [42u8; 32];
        let plaintext = br#"{"version":1,"cookies":[{"name":"test","value":"abc"}]}"#;
        let encrypted = encrypt_with_key(1, &key, plaintext);
        let decrypted = decrypt_with_key(1, &key, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];
        let encrypted = encrypt_with_key(1, &key1, b"secret data");
        // Same id, different key — AEAD tag fails.
        let cipher = ChaCha20Poly1305::new_from_slice(&key2).unwrap();
        let nonce = Nonce::from_slice(&encrypted[1..13]);
        let ciphertext = &encrypted[13..];
        assert!(cipher.decrypt(nonce, ciphertext).is_err());
    }

    #[test]
    fn test_decrypt_corrupted_data_fails() {
        let key = [42u8; 32];
        let mut encrypted = encrypt_with_key(1, &key, b"secret data");
        // Flip a byte in the ciphertext
        if encrypted.len() > 20 {
            encrypted[20] ^= 0xFF;
        }
        assert!(decrypt_with_key(1, &key, &encrypted).is_err());
    }

    #[test]
    fn test_decrypt_truncated_data_fails() {
        let key = [42u8; 32];
        let encrypted = encrypt_with_key(1, &key, b"secret data");
        let truncated = &encrypted[..10];
        assert!(decrypt_with_key(1, &key, truncated).is_err());
    }

    #[test]
    fn test_decrypt_wrong_id_fails() {
        let key = [42u8; 32];
        let encrypted = encrypt_with_key(1, &key, b"secret data");
        // Asking for id 2 when file has id 1 fails.
        assert!(decrypt_with_key(2, &key, &encrypted).is_err());
    }

    fn nz(n: u8) -> NonZeroU8 {
        NonZeroU8::new(n).expect("test key id must be non-zero")
    }

    #[test]
    fn test_keystore_json_roundtrip() {
        let mut keys = BTreeMap::new();
        keys.insert(1u8, Zeroizing::new([7u8; 32]));
        keys.insert(2u8, Zeroizing::new([9u8; 32]));
        let mut created_at = BTreeMap::new();
        created_at.insert(1u8, 1_000_000);
        created_at.insert(2u8, 2_000_000);
        let store = CachedStore {
            current: nz(2),
            keys,
            created_at,
        };
        let serialized = serialize_keystore(&store).unwrap();
        let parsed = parse_keystore(&serialized, 0).unwrap();
        assert_eq!(parsed.current, nz(2));
        assert_eq!(parsed.keys.len(), 2);
        assert_eq!(*parsed.keys.get(&1).unwrap().as_ref(), [7u8; 32]);
        assert_eq!(*parsed.keys.get(&2).unwrap().as_ref(), [9u8; 32]);
    }

    #[test]
    fn test_parse_keystore_rejects_zero_current() {
        // Hand-rolled JSON with current=0 — the in-memory NonZeroU8 must reject.
        let bad = r#"{"current":0,"keys":{"1":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},"created_at":{"1":1}}"#;
        match parse_keystore(bad, 0) {
            Err(AwzarsError::Storage(_)) => {}
            Err(other) => panic!("expected Storage error, got {:?}", other),
            Ok(_) => panic!("must reject current=0"),
        }
    }

    #[test]
    fn test_legacy_format_migrates_to_v1() {
        // Legacy entry: raw base64 of 32 bytes, no JSON wrapper.
        let raw_key = [42u8; 32];
        let legacy_value = BASE64.encode(raw_key);
        let parsed = parse_keystore(&legacy_value, 1234).unwrap();
        assert_eq!(parsed.current, nz(1));
        assert_eq!(*parsed.keys.get(&1).unwrap().as_ref(), raw_key);
        assert_eq!(*parsed.created_at.get(&1).unwrap(), 1234);
    }

    #[test]
    fn test_rotation_after_interval() {
        let mut keys = BTreeMap::new();
        keys.insert(1u8, Zeroizing::new([1u8; 32]));
        let mut created_at = BTreeMap::new();
        // Pretend key 1 is far older than the rotation window.
        created_at.insert(1u8, now_unix_secs() - ROTATION_INTERVAL_SECS - 100);
        let mut store = CachedStore {
            current: nz(1),
            keys,
            created_at,
        };
        let rotated = rotate_if_needed(&mut store).unwrap();
        assert!(rotated);
        assert_eq!(store.current, nz(2));
        assert!(store.keys.contains_key(&2));
        // Key 1 is younger than retention window, so it stays.
        assert!(store.keys.contains_key(&1));
    }

    #[test]
    fn test_no_rotation_when_fresh() {
        let mut keys = BTreeMap::new();
        keys.insert(1u8, Zeroizing::new([1u8; 32]));
        let mut created_at = BTreeMap::new();
        created_at.insert(1u8, now_unix_secs());
        let mut store = CachedStore {
            current: nz(1),
            keys,
            created_at,
        };
        let rotated = rotate_if_needed(&mut store).unwrap();
        assert!(!rotated);
        assert_eq!(store.current, nz(1));
    }

    #[test]
    fn test_rotation_gcs_old_keys() {
        let mut keys = BTreeMap::new();
        keys.insert(1u8, Zeroizing::new([1u8; 32]));
        keys.insert(2u8, Zeroizing::new([2u8; 32]));
        let mut created_at = BTreeMap::new();
        // Key 1 is past retention; key 2 is past rotation but within retention.
        created_at.insert(1u8, now_unix_secs() - KEY_RETENTION_SECS - 100);
        created_at.insert(2u8, now_unix_secs() - ROTATION_INTERVAL_SECS - 100);
        let mut store = CachedStore {
            current: nz(2),
            keys,
            created_at,
        };
        let rotated = rotate_if_needed(&mut store).unwrap();
        assert!(rotated);
        assert_eq!(store.current, nz(3));
        assert!(!store.keys.contains_key(&1), "key 1 should be GC'd");
        assert!(store.keys.contains_key(&2), "key 2 should be retained");
        assert!(store.keys.contains_key(&3));
    }

    fn one_key_store() -> CachedStore {
        let mut keys = BTreeMap::new();
        keys.insert(1u8, Zeroizing::new([1u8; 32]));
        let mut created_at = BTreeMap::new();
        created_at.insert(1u8, now_unix_secs());
        CachedStore {
            current: nz(1),
            keys,
            created_at,
        }
    }

    fn cache_with_one_store() -> Mutex<Option<HashMap<String, CachedStore>>> {
        let mut map = HashMap::new();
        map.insert("p".to_string(), one_key_store());
        Mutex::new(Some(map))
    }

    #[test]
    fn wipe_cache_drops_keys_when_unlocked() {
        let cache = cache_with_one_store();
        wipe_cache(&cache);
        assert!(cache.lock().unwrap().is_none(), "keys must be wiped");
    }

    #[test]
    fn wipe_cache_returns_while_lock_is_held() {
        // A panic inside encrypt/decrypt runs the hook with the lock held.
        // The wipe must return instead of waiting for the lock. It runs on a
        // second thread with a time limit so a regression fails the test
        // rather than hanging the suite.
        let cache = cache_with_one_store();
        let returned = std::thread::scope(|s| {
            let guard = cache.lock().unwrap();
            let (tx, rx) = std::sync::mpsc::channel();
            let cache = &cache;
            s.spawn(move || {
                wipe_cache(cache);
                let _ = tx.send(());
            });
            let returned = rx.recv_timeout(std::time::Duration::from_secs(5)).is_ok();
            // Let a blocked wipe finish so the scope can end.
            drop(guard);
            returned
        });
        assert!(returned, "wipe_cache blocked on a held lock");
        assert!(
            cache.lock().unwrap().is_some(),
            "a held lock skips the wipe"
        );
    }

    #[test]
    fn wipe_cache_drops_keys_when_poisoned() {
        let cache = cache_with_one_store();
        let _ = std::thread::scope(|s| {
            s.spawn(|| {
                let _guard = cache.lock().unwrap();
                panic!("poison the cache lock");
            })
            .join()
        });
        assert!(cache.is_poisoned());
        wipe_cache(&cache);
        let guard = cache.lock().unwrap_or_else(|e| e.into_inner());
        assert!(guard.is_none(), "a poisoned lock must still be wiped");
    }

    fn mock_entry() -> Entry {
        Entry::new_with_credential(Box::new(keyring::mock::MockCredential::default()))
    }

    fn mock_of(entry: &Entry) -> &keyring::mock::MockCredential {
        entry
            .get_credential()
            .downcast_ref::<keyring::mock::MockCredential>()
            .expect("mock credential")
    }

    fn read_errors() -> Vec<keyring::Error> {
        vec![
            keyring::Error::NoStorageAccess("keychain locked".into()),
            keyring::Error::PlatformFailure("platform failure".into()),
            keyring::Error::BadEncoding(vec![0xff, 0xfe]),
        ]
    }

    #[test]
    fn load_or_init_creates_keystore_when_entry_absent() {
        let entry = mock_entry();
        let now = now_unix_secs();
        let store = load_or_init_from_entry(&entry, now).unwrap();
        assert_eq!(store.current, NonZeroU8::MIN);

        let saved = entry.get_password().expect("keystore saved");
        let parsed = parse_keystore(&saved, now).unwrap();
        assert_eq!(parsed.current, store.current);
        assert_eq!(
            *parsed.keys[&1], *store.keys[&1],
            "saved key must match the returned key"
        );
    }

    #[test]
    fn load_or_init_read_error_does_not_create_keystore() {
        for err in read_errors() {
            let entry = mock_entry();
            mock_of(&entry).set_error(err);
            assert!(load_or_init_from_entry(&entry, now_unix_secs()).is_err());
            assert!(
                matches!(entry.get_password(), Err(keyring::Error::NoEntry)),
                "nothing may be written after a read error"
            );
        }
    }

    #[test]
    fn load_or_init_read_error_keeps_existing_keystore() {
        for err in read_errors() {
            let entry = mock_entry();
            let now = now_unix_secs();
            let original = load_or_init_from_entry(&entry, now).unwrap();
            let before = entry.get_password().unwrap();

            mock_of(&entry).set_error(err);
            assert!(load_or_init_from_entry(&entry, now).is_err());

            assert_eq!(entry.get_password().unwrap(), before);
            let reloaded = load_or_init_from_entry(&entry, now).unwrap();
            assert_eq!(*reloaded.keys[&1], *original.keys[&1]);
        }
    }

    /// A one-key store whose key is past the rotation window, so the next
    /// encrypt rotates it.
    fn stale_store(current: u8) -> CachedStore {
        let mut keys = BTreeMap::new();
        keys.insert(current, Zeroizing::new([current; 32]));
        let mut created_at = BTreeMap::new();
        created_at.insert(current, now_unix_secs() - ROTATION_INTERVAL_SECS - 100);
        CachedStore {
            current: nz(current),
            keys,
            created_at,
        }
    }

    #[test]
    fn encrypt_keeps_cached_keystore_when_rotation_fails() {
        crate::storage::keyring::test_keychain::install();
        let profile = "cookie-rotation-fails";
        // Key id 255 can't rotate: the id space is exhausted.
        cache_replace(profile, stale_store(255));

        assert!(encrypt(profile, b"{}").is_err());

        assert_eq!(
            cache_lookup(profile),
            Some((255, [255u8; 32])),
            "a failed rotation must leave the keystore in the cache"
        );
    }

    #[test]
    fn encrypt_keeps_saved_keystore_when_saving_rotation_fails() {
        crate::storage::keyring::test_keychain::install();
        let profile = "cookie-rotation-save-fails";
        let entry = KeyringStorage::new(profile)
            .unwrap()
            .entry_for_field("cookie_key")
            .unwrap();
        save_keystore_to_entry(&entry, &stale_store(1)).unwrap();
        let saved = entry.get_password().unwrap();
        cache_replace(profile, stale_store(1));

        crate::storage::keyring::test_keychain::fail_writes(true);
        let result = encrypt(profile, b"{}");
        crate::storage::keyring::test_keychain::fail_writes(false);
        assert!(result.is_err());

        assert_eq!(entry.get_password().unwrap(), saved);
        // The cache keeps the saved key 1, not the unsaved rotated key 2.
        assert_eq!(cache_lookup(profile), Some((1, [1u8; 32])));
    }

    #[test]
    fn encrypt_keeps_cached_keystore_when_current_key_is_missing() {
        crate::storage::keyring::test_keychain::install();
        let profile = "cookie-current-key-missing";
        // The saved keystore names current id 1 but only holds key 2, so
        // encrypt loads it and then fails.
        let mut keys = BTreeMap::new();
        keys.insert(2u8, Zeroizing::new([2u8; 32]));
        let broken = CachedStore {
            current: nz(1),
            keys,
            created_at: BTreeMap::new(),
        };
        let entry = KeyringStorage::new(profile)
            .unwrap()
            .entry_for_field("cookie_key")
            .unwrap();
        save_keystore_to_entry(&entry, &broken).unwrap();

        assert!(encrypt(profile, b"{}").is_err());

        // Key 2 still decrypts from the cache, without another keychain read.
        assert_eq!(
            cache_lookup_specific(profile, 2),
            Some(Zeroizing::new([2u8; 32])),
            "the loaded keystore must be cached"
        );
    }

    /// A one-key store with key `[id; 32]`, too new to rotate.
    fn fresh_store(id: u8) -> CachedStore {
        let mut keys = BTreeMap::new();
        keys.insert(id, Zeroizing::new([id; 32]));
        let mut created_at = BTreeMap::new();
        created_at.insert(id, now_unix_secs());
        CachedStore {
            current: nz(id),
            keys,
            created_at,
        }
    }

    #[test]
    fn encrypt_loads_without_the_cache_lock_and_keeps_a_store_cached_meanwhile() {
        crate::storage::keyring::test_keychain::install();
        let profile = "cookie-load-unlocked";
        let cache_was_locked = std::cell::Cell::new(None);

        let data = encrypt_with_loader(profile, b"{}", |_| {
            // Stands in for a decrypt that caches the store while this
            // thread reads the keychain. That needs STORE_CACHE unlocked.
            match STORE_CACHE.try_lock() {
                Ok(mut guard) => {
                    guard
                        .get_or_insert_with(HashMap::new)
                        .insert(profile.to_string(), fresh_store(7));
                    cache_was_locked.set(Some(false));
                }
                Err(_) => cache_was_locked.set(Some(true)),
            }
            Ok(fresh_store(1))
        })
        .unwrap();

        assert_eq!(
            cache_was_locked.get(),
            Some(false),
            "STORE_CACHE must not be held while the keychain is read"
        );
        assert_eq!(data[0], 7, "the store cached meanwhile must be used");
        assert_eq!(cache_lookup(profile), Some((7, [7u8; 32])));
    }

    #[test]
    fn concurrent_encrypts_read_the_keychain_once() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{mpsc, Arc};
        use std::time::Duration;

        const PROFILE: &str = "cookie-concurrent-encrypts";
        // Detached threads and bounded waits: a regression that never reads
        // the keychain, or that blocks, fails the test instead of hanging it.
        const WAIT: Duration = Duration::from_secs(10);
        let loads = Arc::new(AtomicUsize::new(0));
        let (reading_tx, reading_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();

        let first_loads = Arc::clone(&loads);
        let first_done = done_tx.clone();
        std::thread::spawn(move || {
            let result = encrypt_with_loader(PROFILE, b"{}", |_| {
                first_loads.fetch_add(1, Ordering::SeqCst);
                let _ = reading_tx.send(());
                // A slow keychain read, such as one waiting on a prompt.
                std::thread::sleep(Duration::from_millis(200));
                Ok(fresh_store(1))
            });
            let _ = first_done.send(result);
        });
        reading_rx
            .recv_timeout(WAIT)
            .expect("the first encrypt never read the keychain");

        let second_loads = Arc::clone(&loads);
        std::thread::spawn(move || {
            let result = encrypt_with_loader(PROFILE, b"{}", |_| {
                second_loads.fetch_add(1, Ordering::SeqCst);
                Ok(fresh_store(2))
            });
            let _ = done_tx.send(result);
        });

        for _ in 0..2 {
            let data = done_rx
                .recv_timeout(WAIT)
                .expect("an encrypt did not finish")
                .unwrap();
            assert_eq!(data[0], 1, "both encrypts must use the first store");
        }
        assert_eq!(
            loads.load(Ordering::SeqCst),
            1,
            "the second encrypt must use the first one's store"
        );
    }

    #[test]
    fn decrypt_without_keystore_does_not_create_one() {
        crate::storage::keyring::test_keychain::install();
        let profile = "cookie-decrypt-no-keystore";
        let data = encrypt_with_key(1, &[7u8; 32], b"{}");

        assert!(decrypt(profile, &data).is_err());

        let entry = KeyringStorage::new(profile)
            .unwrap()
            .entry_for_field("cookie_key")
            .unwrap();
        assert!(
            matches!(entry.get_password(), Err(keyring::Error::NoEntry)),
            "a read must not create a cookie key"
        );
    }

    #[test]
    fn encrypt_creates_keystore_and_decrypt_reads_it() {
        crate::storage::keyring::test_keychain::install();
        let profile = "cookie-encrypt-creates-keystore";

        let data = encrypt(profile, b"{\"v\":1}").unwrap();
        let entry = KeyringStorage::new(profile)
            .unwrap()
            .entry_for_field("cookie_key")
            .unwrap();
        assert!(entry.get_password().is_ok(), "encrypt must create the key");

        // Read through the keychain, not the per-process cache.
        STORE_CACHE
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .remove(profile);
        assert_eq!(decrypt(profile, &data).unwrap().as_slice(), b"{\"v\":1}");
    }
}
