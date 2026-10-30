//! Browser automation using chromiumoxide

use crate::config;
use crate::error::{AwzarsError, Result};
use chromiumoxide::browser::{Browser, BrowserConfig};
use chromiumoxide::cdp::browser_protocol::network::{
    Cookie, CookieParam, CookieSameSite, TimeSinceEpoch,
};
use chromiumoxide::page::Page;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use zeroize::Zeroizing;

/// Serialized cookie for persisting browser sessions across remote/local Chrome.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SavedCookie {
    name: String,
    value: String,
    domain: String,
    path: String,
    /// Seconds since UNIX epoch. -1 = session cookie.
    expires: f64,
    http_only: bool,
    secure: bool,
    same_site: Option<String>,
}

/// On-disk cookie store for transferring sessions from remote Chrome to local.
#[derive(Debug, Serialize, Deserialize)]
struct CookieStore {
    version: u32,
    saved_at: String,
    cookies: Vec<SavedCookie>,
}

/// Domains required for the Azure AD → AWS SAML federation flow. Cookies for
/// any other domain (banking, personal SaaS, etc.) must never be copied out of
/// a shared remote Chrome instance onto the awzars host.
const SAML_FEDERATION_DOMAINS: &[&str] = &[
    "login.microsoftonline.com",
    "login.windows.net",
    "login.microsoft.com",
    "login.live.com",
    "sts.windows.net",
    "aadcdn.msftauth.net",
    "aadcdn.msauth.net",
    "msauth.net",
    "msftauth.net",
    "signin.aws.amazon.com",
];

/// Whether a cookie's `domain` attribute is within the SAML federation allow-list.
///
/// Matches a cookie domain against the allow-list. Cookie domains conventionally
/// start with a leading `.`; both `foo.com` and `.foo.com` mean the cookie is
/// valid for `foo.com` and its subdomains. We accept:
///   * exact match (case-insensitive),
///   * suffix match on a dot boundary (e.g. cookie `.login.microsoftonline.com`
///     accepts the literal `login.microsoftonline.com`, and cookie
///     `login.microsoftonline.com` is accepted for subdomain hosts).
fn is_allowed_cookie_domain(cookie_domain: &str) -> bool {
    let d = cookie_domain.trim_start_matches('.').to_ascii_lowercase();
    if d.is_empty() {
        return false;
    }
    SAML_FEDERATION_DOMAINS.iter().any(|allowed| {
        let allowed = allowed.to_ascii_lowercase();
        d == allowed || d.ends_with(&format!(".{}", allowed))
    })
}

impl SavedCookie {
    /// Check if this cookie has expired.
    fn is_expired(&self) -> bool {
        if self.expires <= 0.0 {
            return false; // session cookie
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();
        self.expires <= now
    }

    /// Convert to a `CookieParam` for injection into a browser.
    fn to_cookie_param(&self) -> CookieParam {
        let mut param = CookieParam::new(&self.name, &self.value);
        param.domain = Some(self.domain.clone());
        param.path = Some(self.path.clone());
        param.secure = Some(self.secure);
        param.http_only = Some(self.http_only);
        param.same_site = self.same_site.as_ref().and_then(|s| match s.as_str() {
            "Strict" => Some(CookieSameSite::Strict),
            "Lax" => Some(CookieSameSite::Lax),
            "None" => Some(CookieSameSite::None),
            _ => None,
        });
        if self.expires > 0.0 {
            param.expires = Some(TimeSinceEpoch::new(self.expires));
        }
        param
    }
}

fn cookie_to_saved(c: &Cookie) -> SavedCookie {
    SavedCookie {
        name: c.name.clone(),
        value: c.value.clone(),
        domain: c.domain.clone(),
        path: c.path.clone(),
        expires: c.expires,
        http_only: c.http_only,
        secure: c.secure,
        same_site: c
            .same_site
            .as_ref()
            .map(|s: &CookieSameSite| s.as_ref().to_string()),
    }
}

/// Path to the cookie store file for a profile.
fn cookie_store_path(profile: &str) -> Result<std::path::PathBuf> {
    Ok(config::chromium_data_dir(profile)?.join("cookies.enc"))
}

/// Decrypt and parse a saved cookie store.
///
/// A store that cannot be decrypted is an error in headless mode: without
/// its cookies the sign-in can only time out. A visible browser carries on
/// without them, since the user can sign in and replace the store.
fn decode_cookie_store(
    profile: &str,
    contents: &[u8],
    headless: bool,
) -> Result<Option<CookieStore>> {
    let json = match super::cookie_crypto::decrypt(profile, contents) {
        Ok(j) => j,
        Err(e) if headless => {
            return Err(AwzarsError::Browser(format!(
                "The saved browser session for profile '{}' cannot be decrypted ({}). \
                 Run `awzars login --profile {} --remember-me` to sign in again.",
                profile, e, profile
            )));
        }
        Err(e) => {
            tracing::warn!(
                "Cookie store decryption failed for profile '{}': {}",
                profile,
                e
            );
            return Ok(None);
        }
    };

    let store: CookieStore = serde_json::from_slice(&json)
        .map_err(|e| AwzarsError::Browser(format!("Failed to parse cookie store: {}", e)))?;
    Ok(Some(store))
}

/// Decide whether a cookie-injection failure stops the sign-in.
///
/// Headless sign-in cannot succeed without the cookies, so it fails now
/// instead of waiting for the timeout. A visible browser carries on.
fn cookie_injection_outcome(injected: Result<bool>, headless: bool) -> Result<()> {
    match injected {
        Ok(_) => Ok(()),
        Err(e) if headless => Err(e),
        Err(e) => {
            tracing::debug!("Cookie injection skipped: {}", e);
            Ok(())
        }
    }
}

/// Path to the legacy plaintext cookie file (pre-encryption awzars).
fn legacy_cookie_path(profile: &str) -> Result<std::path::PathBuf> {
    Ok(config::chromium_data_dir(profile)?.join("cookies.json"))
}

/// Refuse to proceed if a legacy plaintext `cookies.json` is still present.
///
/// A pre-encryption awzars build wrote cookies in plaintext. Migration tries
/// to delete that file after writing the encrypted store, but if the delete
/// fails the plaintext jar persists on disk alongside the new encrypted one
/// — silently defeating the encryption for any attacker with read access.
///
/// Fail-closed: any operation that touches the cookie store must call this
/// first, so a stale plaintext file blocks further use of the profile until
/// the user removes it. Both the read path (`inject_cookies_from_store`) and
/// the write path (`save_cookies`) gate on this so a stale file cannot be
/// silently extended.
fn refuse_if_legacy_cookies_present(profile: &str) -> Result<()> {
    refuse_if_legacy_cookies_present_at(&legacy_cookie_path(profile)?)
}

/// Path-taking variant of [`refuse_if_legacy_cookies_present`] for unit
/// tests that don't want to thread a profile name through `chromium_data_dir`.
fn refuse_if_legacy_cookies_present_at(legacy: &std::path::Path) -> Result<()> {
    if legacy.exists() {
        return Err(AwzarsError::Browser(format!(
            "Legacy plaintext cookie file detected at {}. It contains session \
             cookies from a pre-encryption awzars version and must be deleted \
             before this profile can be used. Run: rm {}",
            legacy.display(),
            legacy.display()
        )));
    }
    Ok(())
}

/// Whether `shutdown` closes the whole browser. Only a Chrome that awzars
/// launched is closed; a remote Chrome belongs to the operator, so awzars
/// closes just its own page there and disconnects.
fn should_close_browser(is_remote: bool) -> bool {
    !is_remote
}

/// Azure AD login browser automation
pub struct AzureLoginBrowser {
    browser: Option<Browser>,
    page: Option<Page>,
    headless: bool,
    remember_me: bool,
    is_remote: bool,
    /// CDP event loop for a remote Chrome. Aborted on shutdown to drop the
    /// connection; it does not end on its own while the browser stays open.
    remote_handler: Option<tokio::task::JoinHandle<()>>,
    quiet: bool,
    profile: String,
    /// Ephemeral directory for non-remember-me sessions. Held so that it is
    /// cleaned up (deleted) when this struct is dropped after the browser exits.
    _ephemeral_dir: Option<tempfile::TempDir>,
}

impl AzureLoginBrowser {
    /// Create a new browser instance connecting to remote Chrome
    /// Set CHROME_REMOTE_URL environment variable to the WebSocket URL, e.g.:
    /// CHROME_REMOTE_URL=ws://remote-host:9222/devtools/browser/xxx
    ///
    /// `no_sandbox` disables the Chrome sandbox when launching a local browser.
    /// This is required when running as root but reduces the security boundary,
    /// so it must be opted into explicitly.
    pub async fn new(
        headless: bool,
        no_sandbox: bool,
        remember_me: bool,
        profile: &str,
        allow_insecure_remote_chrome: bool,
    ) -> Result<Self> {
        // Check for remote Chrome URL.
        //
        // SECURITY: When CHROME_REMOTE_URL is explicitly set, the user has chosen
        // to route the authentication flow through a remote Chrome (often for
        // network isolation or to keep the flow off the awzars host). Do NOT
        // silently fall back to local Chrome on connection failure — that would
        // defeat the operator's intent and may leak that awzars touched the
        // local host at all. Fail loudly instead.
        if let Ok(remote_url) = std::env::var("CHROME_REMOTE_URL") {
            return Self::connect_remote(
                &remote_url,
                headless,
                allow_insecure_remote_chrome,
                remember_me,
                profile,
            )
            .await;
        }

        // Local Chrome launch (no CHROME_REMOTE_URL set)
        Self::launch_local(headless, no_sandbox, remember_me, profile).await
    }

    /// Connect to a remote Chrome instance via WebSocket
    async fn connect_remote(
        ws_url: &str,
        headless: bool,
        allow_insecure: bool,
        remember_me: bool,
        profile: &str,
    ) -> Result<Self> {
        let parsed = validate_ws_url(ws_url, allow_insecure)?;

        tracing::warn!(
            "Connecting to remote Chrome at {}. The authentication flow, including credentials, traverses this connection; only use a trusted Chrome instance.",
            redact_ws_url(&parsed)
        );
        if parsed.scheme() == "ws" {
            tracing::warn!("Connection is UNENCRYPTED (ws://). Use wss:// for TLS.");
        }
        // Separate cue for the network-crossing case. The general warning
        // above is the same regardless of host; an SSH-tunnelled loopback
        // connection is meaningfully lower-risk than a WAN host, and
        // operators routinely skim past warnings they've seen 100 times.
        // A dedicated line for non-loopback makes the WAN case visible.
        if !is_loopback_url(&parsed) {
            tracing::warn!("Host is non-loopback — credentials will traverse the network.");
        }

        tracing::info!("Connecting to remote Chrome at {}", redact_ws_url(&parsed));

        let (browser, mut handler) = Browser::connect(ws_url)
            .await
            .map_err(|e| AwzarsError::Browser(format!("Failed to connect to remote Chrome: {}. Verify CHROME_REMOTE_URL points to a running Chrome DevTools endpoint.", e)))?;

        // Spawn handler task
        let remote_handler = tokio::spawn(async move {
            while let Some(event) = handler.next().await {
                if event.is_err() {
                    tracing::trace!("Browser handler event: {:?}", event);
                }
            }
        });

        Ok(Self {
            browser: Some(browser),
            page: None,
            headless,
            remember_me,
            is_remote: true,
            remote_handler: Some(remote_handler),
            quiet: false,
            profile: profile.to_string(),
            _ephemeral_dir: None,
        })
    }

    /// Launch a local Chrome instance
    async fn launch_local(
        headless: bool,
        no_sandbox: bool,
        remember_me: bool,
        profile: &str,
    ) -> Result<Self> {
        let mut config_builder = BrowserConfig::builder().request_timeout(Duration::from_secs(120));

        if let Some(exe) = find_chrome_executable() {
            config_builder = config_builder.chrome_executable(exe);
        }

        let mut ephemeral_dir = None;

        if remember_me {
            // Persist session cookies for auto re-authentication
            let data_dir = config::chromium_data_dir(profile)?;
            std::fs::create_dir_all(&data_dir).map_err(|e| {
                AwzarsError::Browser(format!("Failed to create chromium data dir: {}", e))
            })?;
            // Enforce restricted permissions on the chromium data directory.
            // Symlink-safe so a planted symlink at the leaf cannot redirect
            // the chmod onto a directory outside the chromium tree.
            crate::util::enforce_perms_no_symlink(&data_dir, 0o700).map_err(|e| {
                AwzarsError::Browser(format!(
                    "Failed to set permissions on chromium data dir {}: {}",
                    data_dir.display(),
                    e
                ))
            })?;
            config_builder = config_builder.user_data_dir(data_dir);
            tracing::info!("Using persistent browser session for profile: {}", profile);
        } else {
            // Use an ephemeral temp directory that is auto-cleaned on drop,
            // preventing cookies/localStorage/IndexedDB from surviving.
            let tmp = tempfile::TempDir::new().map_err(|e| {
                AwzarsError::Browser(format!("Failed to create ephemeral browser dir: {}", e))
            })?;
            config_builder = config_builder
                .user_data_dir(tmp.path())
                .arg("--incognito")
                .arg("--disk-cache-size=0")
                .arg("--media-cache-size=0");
            ephemeral_dir = Some(tmp);
        }

        if !headless {
            config_builder = config_builder.with_head();
        }

        if no_sandbox {
            tracing::warn!("Chrome sandbox disabled (--no-sandbox) — security boundary reduced");
            config_builder = config_builder.no_sandbox();
        }

        let config = config_builder
            .build()
            .map_err(|e| AwzarsError::Browser(format!("Failed to create browser config: {}", e)))?;

        let (browser, mut handler) = Browser::launch(config)
            .await
            .map_err(|e| {
                let err_str = format!("{}", e);
                if err_str.contains("SingletonLock") || err_str.contains("SingletonSocket") || err_str.contains("SingletonCookie") {
                    AwzarsError::Browser(format!(
                        "Chrome profile lock error for '{}': another Chrome instance is using the session data. \
                         Close the other Chrome windows that use this profile and try again.",
                        profile
                    ))
                } else if err_str.contains("Permission denied") {
                    let chrome_hint = std::env::var("CHROME")
                        .ok()
                        .filter(|v| v.ends_with(".app"))
                        .map(|v| format!(
                            " CHROME is set to a .app bundle; point it to the binary instead, e.g. \
                             CHROME=\"{}/Contents/MacOS/...\".",
                            v
                        ))
                        .unwrap_or_default();
                    let data_directory = config::chromium_data_dir(profile)
                        .map(|path| path.display().to_string())
                        .unwrap_or_else(|_| "the configured Chromium data directory".into());
                    AwzarsError::Browser(format!(
                        "Permission denied launching Chrome for profile '{}'.{} \
                         If you previously ran awzars with sudo, check ownership \
                         and permissions of {}.",
                        profile, chrome_hint, data_directory
                    ))
                } else {
                    AwzarsError::Browser(format!(
                        "Failed to launch browser: {}. Install Chrome/Chromium, set CHROME=/path/to/chrome to point to your installation, or set CHROME_REMOTE_URL to connect to a remote Chrome instance.",
                        e
                    ))
                }
            })?;

        // Spawn handler task
        tokio::spawn(async move {
            while let Some(event) = handler.next().await {
                if event.is_err() {
                    tracing::trace!("Browser handler event: {:?}", event);
                }
            }
        });

        Ok(Self {
            browser: Some(browser),
            page: None,
            headless,
            remember_me,
            is_remote: false,
            remote_handler: None,
            quiet: false,
            profile: profile.to_string(),
            _ephemeral_dir: ephemeral_dir,
        })
    }

    /// Login to Azure AD and retrieve SAML assertion.
    ///
    /// The returned assertion is wrapped in `Zeroizing<String>` so the heap
    /// holding the base64-encoded assertion is wiped when the caller drops
    /// the value. Plumb the wrapper through (or borrow as `&str`) — do not
    /// `.to_string()` it back into a plain `String`.
    pub async fn login_and_get_saml(
        &mut self,
        tenant_id: &str,
        app_id_uri: &str,
    ) -> Result<Zeroizing<String>> {
        let browser = self
            .browser
            .as_ref()
            .ok_or_else(|| AwzarsError::Browser("Browser not initialized".to_string()))?;

        // Create new page
        let page = browser
            .new_page("about:blank")
            .await
            .map_err(|e| AwzarsError::Browser(format!("Failed to create page: {}", e)))?;

        self.page = Some(page.clone());

        // Headed and headless local sessions both reuse the encrypted cookie
        // store, including when it replaces a persistent user-data directory.
        if !self.is_remote {
            let injected = self.inject_cookies_from_store(browser).await;
            cookie_injection_outcome(injected, self.headless)?;
        }

        // Build Azure AD login URL (validates tenant_id is a UUID)
        let login_url = build_azure_login_url(tenant_id, app_id_uri)?;

        let timeout = self.authentication_timeout()?;
        super::saml_capture::capture(&page, &login_url, timeout).await
    }

    /// Gracefully close the browser process, or for a remote Chrome close
    /// only the page awzars opened and disconnect, leaving the browser open.
    ///
    /// Must be called before `AzureLoginBrowser` is dropped to suppress
    /// chromiumoxide's "Browser was not closed manually" WARN. Takes the
    /// `Browser` out of the `Option` so it cannot be used after shutdown.
    pub async fn shutdown(&mut self) {
        let page = self.page.take();
        let Some(mut browser) = self.browser.take() else {
            return;
        };
        if should_close_browser(self.is_remote) {
            if let Err(e) = browser.close().await {
                tracing::debug!("Browser close returned error: {}", e);
            }
            return;
        }
        if let Some(page) = page {
            if let Err(e) = page.close().await {
                tracing::debug!("Closing the remote page returned error: {}", e);
            }
        }
        if let Some(handler) = self.remote_handler.take() {
            handler.abort();
        }
    }

    /// Whether this browser is connected to a remote Chrome instance.
    pub fn is_remote(&self) -> bool {
        self.is_remote
    }

    pub fn set_quiet(&mut self, quiet: bool) {
        self.quiet = quiet;
    }

    /// Extract all cookies from the current browser session and save them to
    /// the local cookie store. Called after successful remembered auth to
    /// enable subsequent local headless re-authentication.
    pub async fn save_cookies(&self) -> Result<()> {
        // Fail-closed if a legacy plaintext cookies.json is still on disk.
        // The post-write cleanup block below would otherwise have written a
        // fresh `cookies.enc` first and only then tried to remove the
        // plaintext sibling; if that remove failed, both files would coexist
        // until the user noticed the warning. Refusing here means the new
        // encrypted file is never written until the legacy one is gone.
        refuse_if_legacy_cookies_present(&self.profile)?;

        let browser = self
            .browser
            .as_ref()
            .ok_or_else(|| AwzarsError::Browser("Browser not initialized".to_string()))?;

        let cookies = browser
            .get_cookies()
            .await
            .map_err(|e| AwzarsError::Browser(format!("Failed to extract cookies: {}", e)))?;

        let dir = config::chromium_data_dir(&self.profile)?;
        std::fs::create_dir_all(&dir).map_err(|e| {
            AwzarsError::Browser(format!("Failed to create cookie store dir: {}", e))
        })?;

        // Enforce restricted permissions on the cookie store directory.
        // Symlink-safe: a planted symlink at the leaf is rejected.
        crate::util::enforce_perms_no_symlink(&dir, 0o700).map_err(|e| {
            AwzarsError::Browser(format!(
                "Failed to set permissions on cookie store dir {}: {}",
                dir.display(),
                e
            ))
        })?;

        let path = dir.join("cookies.enc");
        let total = cookies.len();
        let filtered: Vec<SavedCookie> = cookies
            .iter()
            .filter(|c| is_allowed_cookie_domain(&c.domain))
            .map(cookie_to_saved)
            .collect();
        let dropped = total - filtered.len();
        if dropped > 0 {
            tracing::info!(
                "Dropping {} cookies outside SAML federation allow-list (kept {})",
                dropped,
                filtered.len()
            );
        }
        let store = CookieStore {
            version: 1,
            saved_at: chrono::Utc::now().to_rfc3339(),
            cookies: filtered,
        };
        let json = serde_json::to_vec(&store)?;

        // Encrypt the cookie payload
        let encrypted = super::cookie_crypto::encrypt(&self.profile, &json)?;

        crate::util::atomic_write(&path, &encrypted, 0o600)?;

        // Clean up old unencrypted cookie file if present. If removal fails,
        // warn via the tracing log — the plaintext cookie
        // jar would otherwise persist on disk alongside the new encrypted
        // store, defeating the encryption. Subsequent calls into the cookie
        // store will fail-closed via `refuse_if_legacy_cookies_present` until
        // the user clears the file.
        let old_path = dir.join("cookies.json");
        if old_path.exists() {
            if let Err(e) = std::fs::remove_file(&old_path) {
                let msg = format!(
                    "Failed to remove legacy unencrypted cookie file {}: {}. \
                     This file contains session cookies from a previous awzars \
                     version and MUST be deleted manually before the next \
                     login. Subsequent operations on this profile will refuse \
                     to run until it is gone.",
                    old_path.display(),
                    e
                );
                tracing::warn!("{}", msg);
            }
        }

        tracing::info!(
            "Saved {} cookies to local store for profile: {}",
            store.cookies.len(),
            self.profile
        );
        Ok(())
    }

    /// Load cookies from the local cookie store and inject them into the browser.
    /// Returns Ok(true) if cookies were injected, Ok(false) if no valid cookies found.
    async fn inject_cookies_from_store(&self, browser: &Browser) -> Result<bool> {
        // Fail-closed if a stale plaintext cookie file is still on disk:
        // a previous migration tried to delete it and failed, and we must not
        // proceed silently while the unencrypted secrets remain.
        refuse_if_legacy_cookies_present(&self.profile)?;

        let path = cookie_store_path(&self.profile)?;
        if !path.exists() {
            return Ok(false);
        }

        let contents = std::fs::read(&path)
            .map_err(|e| AwzarsError::Browser(format!("Failed to read cookie store: {}", e)))?;

        let Some(store) = decode_cookie_store(&self.profile, &contents, self.headless)? else {
            return Ok(false);
        };

        let valid_cookies: Vec<CookieParam> = store
            .cookies
            .into_iter()
            .filter(|c| !c.is_expired() && is_allowed_cookie_domain(&c.domain))
            .map(|c| c.to_cookie_param())
            .collect();

        if valid_cookies.is_empty() {
            tracing::info!("No valid cookies in store for profile: {}", self.profile);
            return Ok(false);
        }

        tracing::info!(
            "Injecting {} cookies for local headless re-auth",
            valid_cookies.len()
        );
        browser
            .set_cookies(valid_cookies)
            .await
            .map_err(|e| AwzarsError::Browser(format!("Failed to inject cookies: {}", e)))?;

        Ok(true)
    }

    /// Check if a cookie store exists for the given profile.
    pub fn has_cookie_store(profile: &str) -> bool {
        cookie_store_path(profile)
            .map(|p| p.exists())
            .unwrap_or(false)
    }

    fn authentication_timeout(&self) -> Result<Duration> {
        if !self.headless {
            if !self.quiet {
                eprintln!("Please complete the login in the browser window...");
                eprintln!("Waiting for authentication...");
            }
            Ok(Duration::from_secs(300))
        } else if self.remember_me || Self::has_cookie_store(&self.profile) {
            tracing::info!("Headless mode: attempting cookie-based re-authentication");
            Ok(Duration::from_secs(30))
        } else {
            Err(AwzarsError::Browser(
                "Headless mode requires a saved session. Run `awzars login --remember-me` \
                 without --headless first to establish a browser session."
                    .into(),
            ))
        }
    }
}

/// Validate a Chrome DevTools WebSocket URL.
///
/// Requires `wss://` by default (or `ws://` only if `allow_insecure` is true),
/// a non-empty host, and no embedded userinfo (username/password).
/// Returns the parsed URL on success.
fn validate_ws_url(raw: &str, allow_insecure: bool) -> Result<url::Url> {
    let parsed = url::Url::parse(raw)
        .map_err(|e| AwzarsError::Browser(format!("Invalid CHROME_REMOTE_URL: {}", e)))?;

    match parsed.scheme() {
        "wss" => {}
        "ws" if allow_insecure => {}
        "ws" => {
            return Err(AwzarsError::Browser(
                "CHROME_REMOTE_URL uses ws:// (unencrypted). \
                 This exposes credentials to network attackers. \
                 Use wss:// or pass --allow-insecure-remote-chrome."
                    .to_string(),
            ));
        }
        other => {
            return Err(AwzarsError::Browser(format!(
                "CHROME_REMOTE_URL must use ws:// or wss:// (got {})",
                other
            )));
        }
    }

    if parsed.host_str().map(str::is_empty).unwrap_or(true) {
        return Err(AwzarsError::Browser(
            "CHROME_REMOTE_URL is missing a host".to_string(),
        ));
    }

    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(AwzarsError::Browser(
            "CHROME_REMOTE_URL must not contain userinfo (username/password)".to_string(),
        ));
    }

    Ok(parsed)
}

/// Whether the URL's host is a loopback address. `localhost` (case-
/// insensitive), the IPv4 `127.0.0.0/8` block, and IPv6 `::1` all count.
///
/// Note: hostnames are NOT resolved here. A name like `mybox.local` that
/// happens to map to `127.0.0.1` in `/etc/hosts` will be treated as
/// non-loopback. Conservative-by-default: a false "not loopback" only
/// produces an extra warning line, never a connection refusal.
fn is_loopback_url(u: &url::Url) -> bool {
    match u.host() {
        Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

/// Render a WebSocket URL with the path stripped, so that browser session
/// IDs (which appear in the path) do not leak into log output.
fn redact_ws_url(u: &url::Url) -> String {
    let scheme = u.scheme();
    let host = u.host_str().unwrap_or("?");
    match u.port() {
        Some(p) => format!("{}://{}:{}", scheme, host, p),
        None => format!("{}://{}", scheme, host),
    }
}

use crate::auth::azure::protocol::build_azure_login_url;

/// Resolve the Chrome executable to use, bypassing chromiumoxide's built-in detection
/// which can find broken PATH wrappers (e.g. Homebrew Cask installs whose .app was
/// never moved to /Applications) before checking the real app locations.
///
/// Also handles CHROME env var pointing to a .app bundle instead of the binary inside.
fn find_chrome_executable() -> Option<std::path::PathBuf> {
    // Handle CHROME env var ourselves before chromiumoxide reads it.
    // If it points to a .app bundle, resolve to the binary inside the bundle.
    if let Ok(val) = std::env::var("CHROME") {
        let p = std::path::PathBuf::from(&val);
        if p.extension().and_then(|e| e.to_str()) == Some("app") {
            // .app bundle: derive binary path as <bundle>/Contents/MacOS/<AppName>
            if let Some(stem) = p.file_stem() {
                let bin = p.join("Contents/MacOS").join(stem);
                if bin.exists() {
                    tracing::debug!("CHROME .app bundle resolved to {}", bin.display());
                    return Some(bin);
                }
            }
            // Bundle exists but binary not inside — fall through to system detection
            // so the user still gets a browser if one is installed normally.
            tracing::warn!(
                "CHROME={} is a .app bundle but the binary was not found inside; \
                 set CHROME to the binary path, e.g. \"{}/Contents/MacOS/...\"",
                val,
                val
            );
        } else if p.exists() {
            return Some(p);
        }
    }

    #[cfg(target_os = "macos")]
    {
        // Check /Applications and ~/Applications explicitly. This runs before
        // chromiumoxide's `which chromium` so that a broken Homebrew Cask wrapper
        // (which points to /Applications/Chromium.app when that path is missing)
        // is never used when a working browser is installed at the standard location.
        let system_candidates = [
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Chromium.app/Contents/MacOS/Chromium",
            "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
        ];
        for path in &system_candidates {
            let p = std::path::Path::new(path);
            if p.exists() {
                return Some(p.to_path_buf());
            }
        }

        if let Some(home) = std::env::var_os("HOME") {
            let user_candidates = [
                "Google Chrome.app/Contents/MacOS/Google Chrome",
                "Chromium.app/Contents/MacOS/Chromium",
                "Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
            ];
            for rel in &user_candidates {
                let path = std::path::Path::new(&home).join("Applications").join(rel);
                if path.exists() {
                    return Some(path);
                }
            }
        }

        // Homebrew Cask: the .app may still be in the Caskroom staging directory
        // if it was never moved to /Applications (e.g. user cancelled the prompt).
        let cask_apps: &[(&str, &str)] = &[
            (
                "/opt/homebrew/Caskroom/google-chrome",
                "Google Chrome.app/Contents/MacOS/Google Chrome",
            ),
            (
                "/opt/homebrew/Caskroom/chromium",
                "Chromium.app/Contents/MacOS/Chromium",
            ),
        ];
        for (cask_dir, app_rel) in cask_apps {
            if let Ok(entries) = std::fs::read_dir(cask_dir) {
                for entry in entries.flatten() {
                    let candidate = entry.path().join(app_rel);
                    if candidate.exists() {
                        return Some(candidate);
                    }
                }
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_ws_url_accepts_wss() {
        assert!(validate_ws_url("wss://host:9222/devtools/browser/abc", false).is_ok());
    }

    #[test]
    fn test_validate_ws_url_rejects_ws_by_default() {
        assert!(validate_ws_url("ws://host:9222/devtools/browser/abc", false).is_err());
    }

    #[test]
    fn test_validate_ws_url_accepts_ws_with_insecure_flag() {
        assert!(validate_ws_url("ws://host:9222/devtools/browser/abc", true).is_ok());
    }

    #[test]
    fn test_validate_ws_url_rejects_http() {
        assert!(validate_ws_url("http://host:9222/", false).is_err());
    }

    #[test]
    fn test_validate_ws_url_rejects_userinfo() {
        assert!(validate_ws_url("ws://user:pass@host:9222/", true).is_err());
    }

    #[test]
    fn test_validate_ws_url_rejects_garbage() {
        assert!(validate_ws_url("not a url", false).is_err());
    }

    #[test]
    fn test_refuse_if_legacy_cookies_returns_ok_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let legacy = dir.path().join("cookies.json");
        // File does not exist — must succeed.
        assert!(refuse_if_legacy_cookies_present_at(&legacy).is_ok());
    }

    #[test]
    fn test_refuse_if_legacy_cookies_errs_when_present() {
        let dir = tempfile::tempdir().unwrap();
        let legacy = dir.path().join("cookies.json");
        std::fs::write(&legacy, b"{\"cookies\":[]}").unwrap();

        let err = refuse_if_legacy_cookies_present_at(&legacy).unwrap_err();
        match err {
            AwzarsError::Browser(msg) => {
                // Error must name the offending path so the user can act on it.
                assert!(
                    msg.contains(legacy.to_str().unwrap()),
                    "error must include path; got: {}",
                    msg
                );
                assert!(
                    msg.contains("rm"),
                    "error should suggest the rm command; got: {}",
                    msg
                );
            }
            other => panic!("expected Browser error, got {:?}", other),
        }
    }

    #[test]
    fn test_is_loopback_url_accepts_loopback_forms() {
        assert!(is_loopback_url(
            &url::Url::parse("wss://localhost:9222/x").unwrap()
        ));
        assert!(is_loopback_url(
            &url::Url::parse("wss://LOCALHOST:9222/x").unwrap()
        ));
        assert!(is_loopback_url(
            &url::Url::parse("ws://127.0.0.1:9222/x").unwrap()
        ));
        // Whole 127/8 block is loopback per RFC.
        assert!(is_loopback_url(
            &url::Url::parse("ws://127.5.6.7:9222/x").unwrap()
        ));
        assert!(is_loopback_url(
            &url::Url::parse("wss://[::1]:9222/x").unwrap()
        ));
    }

    #[test]
    fn test_is_loopback_url_rejects_non_loopback() {
        assert!(!is_loopback_url(
            &url::Url::parse("wss://chrome.example.com:9222/x").unwrap()
        ));
        // Private LAN address is not loopback even though it's RFC1918.
        assert!(!is_loopback_url(
            &url::Url::parse("ws://10.0.0.42:9222/x").unwrap()
        ));
        assert!(!is_loopback_url(
            &url::Url::parse("ws://192.168.1.1:9222/x").unwrap()
        ));
        // Public IPv6.
        assert!(!is_loopback_url(
            &url::Url::parse("wss://[2001:db8::1]:9222/x").unwrap()
        ));
        // Hostnames that *resolve* to loopback are not detected — by design.
        assert!(!is_loopback_url(
            &url::Url::parse("wss://mybox.local:9222/x").unwrap()
        ));
    }

    #[test]
    fn test_redact_ws_url_strips_path() {
        let u = url::Url::parse("ws://host:9222/devtools/browser/secret-id").unwrap();
        assert_eq!(redact_ws_url(&u), "ws://host:9222");
    }

    #[test]
    fn test_redact_ws_url_no_port() {
        let u = url::Url::parse("wss://host/devtools/browser/secret").unwrap();
        assert_eq!(redact_ws_url(&u), "wss://host");
    }

    #[test]
    fn test_saved_cookie_session_not_expired() {
        let cookie = SavedCookie {
            name: "session".into(),
            value: "abc".into(),
            domain: ".example.com".into(),
            path: "/".into(),
            expires: -1.0,
            http_only: true,
            secure: true,
            same_site: None,
        };
        assert!(!cookie.is_expired());
    }

    #[test]
    fn test_saved_cookie_future_not_expired() {
        let future = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64()
            + 3600.0;
        let cookie = SavedCookie {
            name: "session".into(),
            value: "abc".into(),
            domain: ".example.com".into(),
            path: "/".into(),
            expires: future,
            http_only: true,
            secure: true,
            same_site: None,
        };
        assert!(!cookie.is_expired());
    }

    #[test]
    fn test_saved_cookie_past_expired() {
        let past = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64()
            - 3600.0;
        let cookie = SavedCookie {
            name: "session".into(),
            value: "abc".into(),
            domain: ".example.com".into(),
            path: "/".into(),
            expires: past,
            http_only: true,
            secure: true,
            same_site: None,
        };
        assert!(cookie.is_expired());
    }

    #[test]
    fn test_allowed_cookie_domain_accepts_federation_hosts() {
        assert!(is_allowed_cookie_domain("login.microsoftonline.com"));
        assert!(is_allowed_cookie_domain(".login.microsoftonline.com"));
        assert!(is_allowed_cookie_domain(".sts.windows.net"));
        assert!(is_allowed_cookie_domain("signin.aws.amazon.com"));
        assert!(is_allowed_cookie_domain(".aadcdn.msftauth.net"));
        // Subdomains of allow-listed hosts are accepted
        assert!(is_allowed_cookie_domain("foo.login.microsoftonline.com"));
    }

    #[test]
    fn test_allowed_cookie_domain_rejects_unrelated() {
        assert!(!is_allowed_cookie_domain("bank.example.com"));
        assert!(!is_allowed_cookie_domain("gmail.com"));
        assert!(!is_allowed_cookie_domain(""));
        assert!(!is_allowed_cookie_domain("."));
        // Lookalikes must be rejected (substring but not a true suffix).
        assert!(!is_allowed_cookie_domain(
            "login.microsoftonline.com.attacker.com"
        ));
        assert!(!is_allowed_cookie_domain("evillogin.microsoftonline.com"));
        assert!(!is_allowed_cookie_domain(
            "signin.aws.amazon.com.attacker.com"
        ));
    }

    #[test]
    fn undecryptable_cookie_store_fails_fast_only_when_headless() {
        // The test keychain starts empty: the cookie keystore is created
        // fresh, so a store written under another key cannot be decrypted.
        let profile = "cookie-store-errors-test";
        let mut contents = vec![0u8; 64];
        contents[0] = 1; // key id 1

        let err = decode_cookie_store(profile, &contents, true).unwrap_err();
        match err {
            AwzarsError::Browser(msg) => assert!(
                msg.contains("awzars login --profile cookie-store-errors-test --remember-me"),
                "error should tell the user how to sign in again; got: {}",
                msg
            ),
            other => panic!("expected Browser error, got {:?}", other),
        }
        // A person can still sign in in a visible browser, which replaces
        // the store, so headed logins carry on without the cookies.
        assert!(decode_cookie_store(profile, &contents, false)
            .unwrap()
            .is_none());
    }

    #[test]
    fn cookie_injection_failure_stops_only_headless_sign_in() {
        let failure = || Err(AwzarsError::Browser("injection failed".into()));
        for headless in [true, false] {
            assert!(cookie_injection_outcome(Ok(true), headless).is_ok());
            assert!(cookie_injection_outcome(Ok(false), headless).is_ok());
        }
        match cookie_injection_outcome(failure(), true) {
            Err(AwzarsError::Browser(msg)) => assert_eq!(msg, "injection failed"),
            other => panic!("expected the injection error, got {:?}", other),
        }
        assert!(cookie_injection_outcome(failure(), false).is_ok());
    }

    #[test]
    fn test_cookie_store_roundtrip() {
        let store = CookieStore {
            version: 1,
            saved_at: "2026-04-14T18:00:00Z".into(),
            cookies: vec![SavedCookie {
                name: "ESTSAUTH".into(),
                value: "secret_value".into(),
                domain: ".login.microsoftonline.com".into(),
                path: "/".into(),
                expires: 9999999999.0,
                http_only: true,
                secure: true,
                same_site: Some("Lax".into()),
            }],
        };
        let json = serde_json::to_string(&store).unwrap();
        let parsed: CookieStore = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.cookies.len(), 1);
        assert_eq!(parsed.cookies[0].name, "ESTSAUTH");
        assert_eq!(parsed.cookies[0].same_site, Some("Lax".into()));
    }

    #[test]
    fn test_shutdown_closes_only_a_browser_awzars_launched() {
        assert!(should_close_browser(false));
        assert!(!should_close_browser(true));
    }

    /// Start a throwaway headless Chrome with a temporary profile and remote
    /// debugging on a free port. Returns the child, the profile dir and the
    /// `ws://` browser endpoint read from `DevToolsActivePort`.
    fn launch_throwaway_chrome() -> (std::process::Child, tempfile::TempDir, u16, String) {
        let exe = find_chrome_executable().expect("no Chrome/Chromium found");
        let dir = tempfile::TempDir::new().unwrap();
        let mut child = std::process::Command::new(exe)
            .arg("--headless=new")
            .arg("--remote-debugging-port=0")
            .arg(format!("--user-data-dir={}", dir.path().display()))
            .arg("--no-first-run")
            .arg("--no-default-browser-check")
            .arg("about:blank")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let port_file = dir.path().join("DevToolsActivePort");
        for _ in 0..200 {
            if let Ok(text) = std::fs::read_to_string(&port_file) {
                let mut lines = text.lines();
                if let (Some(port), Some(path)) = (lines.next(), lines.next()) {
                    let port: u16 = port.parse().unwrap();
                    let ws = format!("ws://127.0.0.1:{}{}", port, path);
                    return (child, dir, port, ws);
                }
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = child.kill();
        let _ = child.wait();
        panic!("Chrome did not write DevToolsActivePort");
    }

    #[tokio::test]
    #[ignore = "launches a local headless Chrome; run with `cargo test -- --ignored`"]
    async fn test_remote_shutdown_keeps_remote_chrome_running() {
        let (mut chrome, _profile, port, ws_url) = launch_throwaway_chrome();

        let mut awz = AzureLoginBrowser::connect_remote(&ws_url, true, true, false, "test")
            .await
            .unwrap();
        let page = awz
            .browser
            .as_ref()
            .unwrap()
            .new_page("about:blank")
            .await
            .unwrap();
        let own_target = page.target_id().inner().clone();
        awz.page = Some(page);

        awz.shutdown().await;
        tokio::time::sleep(Duration::from_millis(500)).await;

        let still_running = chrome.try_wait().unwrap().is_none();
        let targets: Vec<serde_json::Value> = if still_running {
            reqwest::get(format!("http://127.0.0.1:{}/json/list", port))
                .await
                .unwrap()
                .json()
                .await
                .unwrap()
        } else {
            Vec::new()
        };
        let _ = chrome.kill();
        let _ = chrome.wait();

        assert!(still_running, "shutdown closed the remote Chrome");
        assert!(
            !targets.iter().any(|t| t["id"] == own_target.as_str()),
            "the page awzars opened is still open"
        );
        assert!(
            targets.iter().any(|t| t["type"] == "page"),
            "the operator's own tab was closed"
        );
    }
}
