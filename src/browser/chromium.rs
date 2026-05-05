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

/// Azure AD login browser automation
pub struct AzureLoginBrowser {
    browser: Option<Browser>,
    page: Option<Page>,
    headless: bool,
    remember_me: bool,
    is_remote: bool,
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

        // Prominent security warning
        eprintln!(
            "\x1b[1;31mWARNING\x1b[0m: Connecting to remote Chrome at {}",
            redact_ws_url(&parsed)
        );
        eprintln!("  The entire authentication flow (including credentials) will traverse this connection.");
        eprintln!("  Only use this with Chrome instances you fully trust.");
        if parsed.scheme() == "ws" {
            eprintln!("  Connection is \x1b[1;31mUNENCRYPTED\x1b[0m (ws://). Use wss:// for TLS.");
        }
        // Separate cue for the network-crossing case. The general warning
        // above is the same regardless of host; an SSH-tunnelled loopback
        // connection is meaningfully lower-risk than a WAN host, and
        // operators routinely skim past warnings they've seen 100 times.
        // A dedicated line for non-loopback makes the WAN case visible.
        if !is_loopback_url(&parsed) {
            eprintln!("  Host is non-loopback — credentials will traverse the network.");
        }

        tracing::info!("Connecting to remote Chrome at {}", redact_ws_url(&parsed));

        let (browser, mut handler) = Browser::connect(ws_url)
            .await
            .map_err(|e| AwzarsError::Browser(format!("Failed to connect to remote Chrome: {}. Verify CHROME_REMOTE_URL points to a running Chrome DevTools endpoint.", e)))?;

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
            is_remote: true,
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
                         Close other Chrome windows using this profile, or run `awzars clear-cache --profile {}` \
                         and re-run `awzars login --remember-me` to reset the session.",
                        profile, profile
                    ))
                } else if err_str.contains("Permission denied") {
                    AwzarsError::Browser(format!(
                        "Permission denied accessing Chrome data directory for profile '{}'. \
                         Check permissions on the chromium data directory or re-run `awzars login --remember-me` to reinitialize.",
                        profile
                    ))
                } else {
                    AwzarsError::Browser(format!(
                        "Failed to launch browser: {}. Install Chrome/Chromium or set CHROME_REMOTE_URL to connect to a remote Chrome instance.",
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

        // Inject saved cookies for local headless re-auth (from remote Chrome sessions).
        // This enables credential-process to silently re-authenticate without needing
        // a persistent Chrome user-data-dir (avoids SingletonLock conflicts).
        if !self.is_remote && self.headless {
            if let Err(e) = self.inject_cookies_from_store(browser).await {
                tracing::debug!("Cookie injection skipped: {}", e);
            }
        }

        // Build Azure AD login URL (validates tenant_id is a UUID)
        let login_url = build_azure_login_url(tenant_id, app_id_uri)?;

        tracing::info!("Navigating to Azure AD login");
        page.goto(&login_url)
            .await
            .map_err(|e| AwzarsError::Browser(format!("Failed to navigate: {}", e)))?;

        // Handle the login flow
        self.handle_login_flow(&page).await?;

        // Wait for redirect and extract SAML response
        let saml_response = self.extract_saml_response(&page).await?;

        Ok(saml_response)
    }

    /// Gracefully close the browser process (or CDP session for remote Chrome).
    ///
    /// Must be called before `AzureLoginBrowser` is dropped to suppress
    /// chromiumoxide's "Browser was not closed manually" WARN. Takes the
    /// `Browser` out of the `Option` so it cannot be used after shutdown.
    pub async fn shutdown(&mut self) {
        if let Some(mut browser) = self.browser.take() {
            if let Err(e) = browser.close().await {
                tracing::debug!("Browser close returned error (expected for remote): {}", e);
            }
        }
    }

    /// Whether this browser is connected to a remote Chrome instance.
    pub fn is_remote(&self) -> bool {
        self.is_remote
    }

    /// Extract all cookies from the current browser session and save them to
    /// the local cookie store. Called after successful remote Chrome auth to
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
        // warn loudly on BOTH stderr and the tracing log — the plaintext cookie
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
                eprintln!("\x1b[1;31mWARNING\x1b[0m: {}", msg);
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

        let json = match super::cookie_crypto::decrypt(&self.profile, &contents) {
            Ok(j) => j,
            Err(e) => {
                tracing::warn!(
                    "Cookie store decryption failed for profile '{}': {}",
                    self.profile,
                    e
                );
                return Ok(false);
            }
        };

        let store: CookieStore = serde_json::from_slice(&json)
            .map_err(|e| AwzarsError::Browser(format!("Failed to parse cookie store: {}", e)))?;

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

    /// Handle the Azure AD login flow
    async fn handle_login_flow(&self, page: &Page) -> Result<()> {
        if !self.headless {
            // Headed mode: wait for user to complete login
            eprintln!("Please complete the login in the browser window...");
            eprintln!("Waiting for authentication...");
            self.wait_for_authentication(page, Duration::from_secs(300))
                .await?;
        } else if self.remember_me || self.has_injected_cookies() {
            // Headless mode with persistent session or injected cookies: rely on cookies for auto-redirect
            tracing::info!("Headless mode: attempting cookie-based re-authentication");
            self.wait_for_authentication(page, Duration::from_secs(30))
                .await
                .map_err(|_| {
                    AwzarsError::Browser(
                        "Headless re-authentication failed: session cookies may be expired. \
                     Run `awzars login` (without --headless) to re-authenticate interactively."
                            .to_string(),
                    )
                })?;
        } else {
            return Err(AwzarsError::Browser(
                "Headless mode requires --remember-me with a previous headed login to establish \
                 a browser session. Run `awzars login --remember-me` first to create a session, \
                 then use --headless for subsequent re-authentications."
                    .to_string(),
            ));
        }

        Ok(())
    }

    /// Check if a cookie store file exists for this profile (injected cookies available).
    fn has_injected_cookies(&self) -> bool {
        Self::has_cookie_store(&self.profile)
    }

    /// Wait for user to complete authentication
    async fn wait_for_authentication(&self, page: &Page, timeout: Duration) -> Result<()> {
        let start = std::time::Instant::now();

        loop {
            if start.elapsed() > timeout {
                return Err(AwzarsError::Browser("Authentication timed out".to_string()));
            }

            // Check if we've been redirected to AWS
            if let Ok(Some(url)) = page.url().await {
                if is_aws_redirect_url(&url) {
                    tracing::info!("Authentication successful, redirect detected");
                    return Ok(());
                }
            }

            // SECURITY: Only check for SAML response on verified AWS pages.
            // A non-AWS page must never cause us to believe auth is complete.
            if let Ok(Some(url)) = page.url().await {
                if is_aws_redirect_url(&url) {
                    if let Ok(content) = page.content().await {
                        // Page HTML embeds the SAMLResponse value; wrap so
                        // the heap is wiped when this iteration ends.
                        let content = Zeroizing::new(content);
                        if content.contains("SAMLResponse") {
                            tracing::info!("SAML response detected in page");
                            return Ok(());
                        }
                    }
                }
            }

            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    /// Extract SAML response from the page.
    ///
    /// SECURITY: SAML data is ONLY extracted when the page URL is a verified
    /// AWS sign-in / console redirect. This prevents attacker-controlled pages
    /// from injecting fake SAML responses.
    ///
    /// Returns `Zeroizing<String>` so the heap-allocated assertion is wiped
    /// on drop rather than left in freed memory.
    async fn extract_saml_response(&self, page: &Page) -> Result<Zeroizing<String>> {
        tracing::info!("Extracting SAML response");

        let timeout = Duration::from_secs(60);
        let start = std::time::Instant::now();

        loop {
            if start.elapsed() > timeout {
                return Err(AwzarsError::Browser(
                    "Timeout waiting for SAML response".to_string(),
                ));
            }

            // SECURITY: Only extract from a verified AWS page. Any other page --
            // including attacker-controlled content -- must never be a source.
            let url = page.url().await.ok().flatten();
            let on_aws_page = url.as_deref().map(is_aws_redirect_url).unwrap_or(false);

            if on_aws_page {
                // Path 1: CSS selector on form input
                if let Ok(element) = page.find_element("input[name='SAMLResponse']").await {
                    if let Ok(Some(value)) = element.attribute("value").await {
                        tracing::info!("SAML response received from form");
                        return Ok(Zeroizing::new(value));
                    }
                }

                // Path 2: HTML content fallback. Wrap the page HTML so the
                // SAMLResponse-bearing buffer is wiped after extraction.
                if let Ok(content) = page.content().await {
                    let content = Zeroizing::new(content);
                    if let Some(saml) = extract_saml_from_html(&content) {
                        tracing::info!("SAML response extracted from HTML");
                        return Ok(Zeroizing::new(saml));
                    }
                }
            }

            tokio::time::sleep(Duration::from_millis(500)).await;
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

use crate::auth::azure::protocol::{
    build_azure_login_url, extract_saml_from_html, is_aws_redirect_url,
};

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
}
