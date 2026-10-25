//! `clear-cache` must drop the stored STS credentials but keep the cookie
//! key, so the remembered browser session (`cookies.enc`) stays usable.
//!
//! The keyring mock keeps nothing between `Entry::new` calls, so this test
//! installs a small in-memory store shared by every entry. It lives in its
//! own test binary because the default credential builder is process-global.

use std::any::Any;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use awzars::storage::keyring::KeyringStorage;
use keyring::credential::{Credential, CredentialApi, CredentialBuilderApi};

type Store = Arc<Mutex<HashMap<(String, String), Vec<u8>>>>;

struct SharedCredential {
    store: Store,
    key: (String, String),
}

impl CredentialApi for SharedCredential {
    fn set_secret(&self, secret: &[u8]) -> keyring::Result<()> {
        self.store
            .lock()
            .unwrap()
            .insert(self.key.clone(), secret.to_vec());
        Ok(())
    }

    fn get_secret(&self) -> keyring::Result<Vec<u8>> {
        self.store
            .lock()
            .unwrap()
            .get(&self.key)
            .cloned()
            .ok_or(keyring::Error::NoEntry)
    }

    fn delete_credential(&self) -> keyring::Result<()> {
        self.store
            .lock()
            .unwrap()
            .remove(&self.key)
            .map(|_| ())
            .ok_or(keyring::Error::NoEntry)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

struct SharedBuilder {
    store: Store,
}

impl CredentialBuilderApi for SharedBuilder {
    fn build(
        &self,
        _target: Option<&str>,
        service: &str,
        user: &str,
    ) -> keyring::Result<Box<Credential>> {
        Ok(Box::new(SharedCredential {
            store: self.store.clone(),
            key: (service.to_string(), user.to_string()),
        }))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[test]
fn clear_cache_keeps_the_cookie_key() {
    keyring::set_default_credential_builder(Box::new(SharedBuilder {
        store: Store::default(),
    }));
    let profile = "clear-cache-test";
    let keyring = KeyringStorage::new(profile).unwrap();
    for field in ["credentials", "cookie_key"] {
        keyring
            .entry_for_field(field)
            .unwrap()
            .set_password("stored")
            .unwrap();
    }

    awzars::config::cleanup::clear_stored_credentials(profile).unwrap();

    let password = |field| keyring.entry_for_field(field).unwrap().get_password();
    assert!(matches!(
        password("credentials"),
        Err(keyring::Error::NoEntry)
    ));
    assert_eq!(password("cookie_key").unwrap(), "stored");
}
