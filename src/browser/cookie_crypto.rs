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
use crate::storage::keyring::KeyringStorage;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::num::NonZeroU8;
use std::sync::Mutex;
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
struct CachedStore {
    current: NonZeroU8,
    keys: BTreeMap<u8, Zeroizing<[u8; 32]>>,
    created_at: BTreeMap<u8, i64>,
}

/// Per-process cache of keystores. Avoids repeated keyring reads (and on
/// macOS, repeated Keychain dialogs) within a single login flow.
static STORE_CACHE: Mutex<Option<HashMap<String, CachedStore>>> = Mutex::new(None);

fn now_unix_secs() -> i64 {
    chrono::Utc::now().timestamp()
}

fn generate_key() -> Result<[u8; 32]> {
    let mut key = [0u8; 32];
    getrandom::getrandom(&mut key)
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
    let serialized = serialize_keystore(store)?;
    let entry = keyring.entry_for_field("cookie_key")?;
    entry
        .set_password(&serialized)
        .map_err(|e| AwzarsError::Keyring(format!("Failed to store cookie keystore: {}", e)))?;
    Ok(())
}

fn load_or_init_store(profile: &str) -> Result<CachedStore> {
    let keyring = KeyringStorage::new(profile)?;
    let entry = keyring.entry_for_field("cookie_key")?;
    let now = now_unix_secs();

    match entry.get_password() {
        Ok(value) => {
            // The String returned by the OS keychain holds the base64-encoded
            // cookie keys. Wrap it so the heap buffer is wiped after we parse.
            let value: Zeroizing<String> = Zeroizing::new(value);
            let store = parse_keystore(&value, now)?;
            // If we read the legacy single-key format, persist the JSON
            // version so the next read takes the fast path.
            let is_legacy = serde_json::from_str::<KeyStoreJson>(&value).is_err();
            if is_legacy {
                save_keystore(&keyring, &store)?;
            }
            Ok(store)
        }
        Err(_) => {
            let key = generate_key()?;
            let mut keys = BTreeMap::new();
            keys.insert(1u8, Zeroizing::new(key));
            let mut created_at = BTreeMap::new();
            created_at.insert(1u8, now);
            let store = CachedStore {
                current: NonZeroU8::MIN,
                keys,
                created_at,
            };
            save_keystore(&keyring, &store)?;
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
                "Cookie key id space exhausted (255 rotations); run `awzars clear-cache` to reset"
                    .into(),
            )
        })?;

    let new_key = generate_key()?;
    store.keys.insert(new_id.get(), Zeroizing::new(new_key));
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

fn cache_lookup(profile: &str) -> Option<(u8, [u8; 32])> {
    let guard = STORE_CACHE.lock().ok()?;
    let map = guard.as_ref()?;
    let store = map.get(profile)?;
    let key = store.keys.get(&store.current.get())?;
    Some((store.current.get(), **key))
}

fn cache_lookup_specific(profile: &str, id: u8) -> Option<[u8; 32]> {
    let guard = STORE_CACHE.lock().ok()?;
    let map = guard.as_ref()?;
    let store = map.get(profile)?;
    store.keys.get(&id).map(|k| **k)
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
    let mut guard = match STORE_CACHE.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    // Dropping the HashMap drops every CachedStore, which drops every
    // Zeroizing<[u8; 32]>, which zeroes the bytes.
    *guard = None;
}

/// Encrypt a JSON payload for the given profile. Returns binary file contents.
///
/// Format: `[1 byte key_id][12 byte nonce][ciphertext + 16 byte tag]`.
pub fn encrypt(profile: &str, json: &[u8]) -> Result<Vec<u8>> {
    let keyring = KeyringStorage::new(profile)?;

    // Load (cache or keyring), rotate if stale, persist + cache the result.
    let (key_id, key_bytes) = {
        let mut store = match cache_lookup(profile) {
            Some(_) => {
                // Take a mutable copy out of the cache (we may rotate). If the
                // entry vanished between the lookup and the take, fall through
                // to a fresh keyring load.
                let mut guard = STORE_CACHE
                    .lock()
                    .map_err(|_| AwzarsError::Storage("Cookie keystore cache poisoned".into()))?;
                let map = guard.get_or_insert_with(HashMap::new);
                match map.remove(profile) {
                    Some(s) => s,
                    None => load_or_init_store(profile)?,
                }
            }
            None => load_or_init_store(profile)?,
        };

        let rotated = rotate_if_needed(&mut store)?;
        if rotated {
            save_keystore(&keyring, &store)?;
        }

        let key = store.keys.get(&store.current.get()).ok_or_else(|| {
            AwzarsError::Storage("Current cookie key missing from keystore".into())
        })?;
        let id = store.current.get();
        let bytes: [u8; 32] = **key;
        cache_replace(profile, store);
        (id, bytes)
    };

    let cipher = ChaCha20Poly1305::new_from_slice(&key_bytes)
        .map_err(|e| AwzarsError::Storage(format!("Cipher init failed: {}", e)))?;

    let mut nonce_bytes = [0u8; 12];
    getrandom::getrandom(&mut nonce_bytes)
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
pub fn decrypt(profile: &str, data: &[u8]) -> Result<Vec<u8>> {
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
        let store = load_or_init_store(profile)?;
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
        let bytes: [u8; 32] = *key;
        cache_replace(profile, store);
        bytes
    };

    let cipher = ChaCha20Poly1305::new_from_slice(&key_bytes)
        .map_err(|e| AwzarsError::Storage(format!("Cipher init failed: {}", e)))?;

    let nonce = Nonce::from_slice(&data[1..13]);
    let ciphertext = &data[13..];

    cipher.decrypt(nonce, ciphertext).map_err(|e| {
        AwzarsError::Storage(format!(
            "Cookie decryption failed — keyring entry may have been deleted: {}",
            e
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Direct encrypt/decrypt with raw keys (no keyring) for testing the crypto layer.
    fn encrypt_with_key(key_id: u8, key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
        let cipher = ChaCha20Poly1305::new_from_slice(key).unwrap();
        let mut nonce_bytes = [0u8; 12];
        getrandom::getrandom(&mut nonce_bytes).unwrap();
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
}
