//! Google OAuth loopback login flow for Antigravity.
//!
//! Port of upstream `AntigravityLoginRunner` (`AntigravityLoginFlow.swift`):
//! opens Google's OAuth consent screen in the default browser, waits for the
//! loopback `/callback` redirect, exchanges the authorization code for tokens,
//! and persists `OAuthCredentials` to `~/.codexbar/antigravity/oauth_creds.json`
//! protected via `crate::secure_file`.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use uuid::Uuid;

use super::remote::{
    OAuthClient, OAuthCredentials, TOKEN_URL, credential_email, credentials_path, default_home,
    non_empty, resolve_client_from_environment, resolve_stored_credentials, save_credentials,
};

const AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const USERINFO_URL: &str = "https://www.googleapis.com/oauth2/v2/userinfo";
const SCOPES: &str =
    "https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/userinfo.email";
const LOGIN_TIMEOUT: Duration = Duration::from_secs(120);
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);
const USERINFO_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_CALLBACK_BYTES: usize = 64 * 1024;

static LOGIN_GENERATION: AtomicU64 = AtomicU64::new(0);
static LOGIN_CANCELLED: AtomicBool = AtomicBool::new(false);
static LOGIN_CANCEL_NOTIFY: Notify = Notify::const_new();

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AntigravityOAuthStatus {
    pub signed_in: bool,
    pub email: Option<String>,
    pub credentials_path: String,
    pub client_available: bool,
    pub missing_client_message: Option<String>,
}

/// Inspect stored Antigravity Google OAuth status without logging secrets.
pub fn status() -> AntigravityOAuthStatus {
    let home = default_home();
    let path = credentials_path(&home);
    let stored = resolve_stored_credentials(&home).ok().flatten();
    let signed_in = stored
        .as_ref()
        .is_some_and(|creds| non_empty(creds.access_token.as_deref()).is_some());
    let email = if signed_in {
        stored.as_ref().and_then(credential_email)
    } else {
        None
    };

    let has_stored_client = stored.as_ref().is_some_and(|creds| {
        non_empty(creds.client_id.as_deref()).is_some()
            && non_empty(creds.client_secret.as_deref()).is_some()
    });
    let (client_available, missing_client_message) = if has_stored_client {
        (true, None)
    } else {
        match resolve_client_from_environment() {
            Ok(_) => (true, None),
            Err(err) => (false, Some(err.into_provider_error().to_string())),
        }
    };

    AntigravityOAuthStatus {
        signed_in,
        email,
        credentials_path: path.display().to_string(),
        client_available,
        missing_client_message,
    }
}

/// Remove any saved Antigravity Google OAuth credentials file.
pub fn sign_out() -> Result<(), String> {
    let path = credentials_path(&default_home());
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(format!("Could not remove Antigravity credentials: {err}")),
    }
}

/// Signal an active browser sign-in flow (if any) to cancel immediately.
pub fn cancel_login() {
    LOGIN_CANCELLED.store(true, Ordering::SeqCst);
    LOGIN_CANCEL_NOTIFY.notify_waiters();
}

/// Run interactive Google OAuth browser sign-in and save credentials.
pub async fn login_with_browser<F>(open_browser: F) -> Result<Option<String>, String>
where
    F: FnOnce(&str) -> Result<(), String>,
{
    let generation = LOGIN_GENERATION.fetch_add(1, Ordering::SeqCst) + 1;
    LOGIN_CANCELLED.store(false, Ordering::SeqCst);

    let oauth_client =
        resolve_client_from_environment().map_err(|err| err.into_provider_error().to_string())?;
    let state = Uuid::new_v4().simple().to_string();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|err| format!("Could not bind local OAuth callback listener: {err}"))?;
    let addr = listener
        .local_addr()
        .map_err(|err| format!("Could not inspect OAuth callback port: {err}"))?;
    let redirect_url = format!("http://127.0.0.1:{}/callback", addr.port());
    let auth_url = make_authorization_url(&redirect_url, &state, &oauth_client.client_id)?;

    open_browser(&auth_url)?;

    let (callback, mut callback_stream) = wait_for_callback(listener, &state, generation).await?;
    let result = complete_callback_login(&callback, &state, &redirect_url, &oauth_client).await;
    if let Some(stream) = callback_stream.as_mut() {
        write_response_and_close(stream, &callback_http_response(result.is_ok())).await;
    }
    result
}

async fn complete_callback_login(
    callback: &OAuthCallback,
    expected_state: &str,
    redirect_url: &str,
    oauth_client: &OAuthClient,
) -> Result<Option<String>, String> {
    if let Some(error) = callback
        .error
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if error == "access_denied" {
            return Err("Antigravity Google sign-in cancelled.".to_string());
        }
        return Err(format!("Google sign-in failed: {error}"));
    }

    if callback.returned_state.as_deref() != Some(expected_state) {
        return Err("Google login state mismatch.".to_string());
    }
    let Some(code) = callback
        .code
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    else {
        return Err("Google login did not return an authorization code.".to_string());
    };

    let http = crate::core::credentialed_http_client_builder()
        .timeout(HTTP_TIMEOUT)
        .build()
        .map_err(|err| format!("Could not initialize HTTP client: {err}"))?;
    let tokens = exchange_code_for_tokens(&http, code, redirect_url, oauth_client).await?;
    let email = fetch_user_email(&http, &tokens.access_token).await;

    let expiry_date = tokens
        .expires_in
        .map(|secs| (chrono::Utc::now().timestamp_millis() as f64) + (secs as f64) * 1000.0);
    let mut credentials = OAuthCredentials {
        access_token: Some(tokens.access_token),
        refresh_token: tokens.refresh_token,
        expiry_date,
        id_token: tokens.id_token,
        email: email.clone(),
        project_id: None,
        client_id: Some(oauth_client.client_id.clone()),
        client_secret: Some(oauth_client.client_secret.clone()),
    };
    let resolved_email = credential_email(&credentials).or(email);
    if credentials.email.is_none() {
        credentials.email = resolved_email.clone();
    }

    let path = credentials_path(&default_home());
    save_credentials(&path, &credentials)
        .map_err(|err| format!("Could not save Antigravity OAuth credentials: {err}"))?;
    Ok(resolved_email)
}

fn make_authorization_url(
    redirect_uri: &str,
    state: &str,
    client_id: &str,
) -> Result<String, String> {
    reqwest::Url::parse_with_params(
        AUTH_URL,
        [
            ("client_id", client_id),
            ("redirect_uri", redirect_uri),
            ("response_type", "code"),
            ("scope", SCOPES),
            ("access_type", "offline"),
            ("prompt", "select_account consent"),
            ("state", state),
        ],
    )
    .map(String::from)
    .map_err(|err| format!("Could not build Antigravity login URL: {err}"))
}

#[derive(Debug, PartialEq, Eq)]
struct OAuthCallback {
    code: Option<String>,
    returned_state: Option<String>,
    error: Option<String>,
}

enum ParsedRequest {
    Callback(OAuthCallback),
    IgnorePath,
    BadRequest(&'static str),
}

fn parse_callback_request(raw: &[u8], expected_state: &str) -> ParsedRequest {
    let Ok(text) = std::str::from_utf8(raw) else {
        return ParsedRequest::BadRequest("Invalid callback request.");
    };
    let Some(line) = text.lines().next() else {
        return ParsedRequest::BadRequest("Invalid callback request.");
    };
    let mut parts = line.split_whitespace();
    let _method = parts.next();
    let Some(target) = parts.next() else {
        return ParsedRequest::BadRequest("Invalid callback URL.");
    };
    let Ok(url) = reqwest::Url::parse(&format!("http://127.0.0.1{target}")) else {
        return ParsedRequest::BadRequest("Invalid callback URL.");
    };
    if url.path() != "/callback" {
        return ParsedRequest::IgnorePath;
    }

    let mut code = None;
    let mut returned_state = None;
    let mut error = None;
    for (k, v) in url.query_pairs() {
        match k.as_ref() {
            "code" => code = Some(v.into_owned()),
            "state" => returned_state = Some(v.into_owned()),
            "error" => error = Some(v.into_owned()),
            _ => {}
        }
    }

    if let Some(ref returned) = returned_state
        && returned != expected_state
    {
        return ParsedRequest::Callback(OAuthCallback {
            code: None,
            returned_state: Some(returned.clone()),
            error: Some("state_mismatch".to_string()),
        });
    }

    ParsedRequest::Callback(OAuthCallback {
        code,
        returned_state,
        error,
    })
}

fn callback_http_response(ok: bool) -> Vec<u8> {
    let (status, title, detail) = if ok {
        (
            "200 OK",
            "Login Successful",
            "You can close this window and return to CodexBar.",
        )
    } else {
        (
            "400 Bad Request",
            "Login Failed",
            "You can close this window and try again.",
        )
    };
    let body = format!(
        "<html><body style=\"font-family: -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif; padding: 32px; text-align: center;\"><h1>{title}</h1><p>{detail}</p></body></html>"
    );
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn not_found_http_response() -> &'static [u8] {
    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
}

async fn wait_for_callback(
    listener: TcpListener,
    expected_state: &str,
    generation: u64,
) -> Result<(OAuthCallback, Option<TcpStream>), String> {
    let deadline = tokio::time::sleep(LOGIN_TIMEOUT);
    tokio::pin!(deadline);

    loop {
        if LOGIN_CANCELLED.load(Ordering::SeqCst)
            || LOGIN_GENERATION.load(Ordering::SeqCst) != generation
        {
            return Err("Antigravity Google sign-in cancelled.".to_string());
        }

        tokio::select! {
            () = &mut deadline => {
                return Err("Antigravity Google sign-in timed out.".to_string());
            }
            () = LOGIN_CANCEL_NOTIFY.notified() => {
                return Err("Antigravity Google sign-in cancelled.".to_string());
            }
            accepted = listener.accept() => {
                let (stream, _) = accepted
                    .map_err(|err| format!("OAuth callback listener failed: {err}"))?;
                if let Some(pending) = handle_connection(stream, expected_state).await {
                    return Ok(pending);
                }
            }
        }
    }
}

async fn write_response_and_close(stream: &mut TcpStream, bytes: &[u8]) {
    let _write = stream.write_all(bytes).await;
    let _shutdown = stream.shutdown().await;
}

async fn handle_connection(
    mut stream: TcpStream,
    expected_state: &str,
) -> Option<(OAuthCallback, Option<TcpStream>)> {
    let mut buf = Vec::with_capacity(2048);
    let mut chunk = [0_u8; 1024];
    loop {
        match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut chunk)).await {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(n)) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() >= MAX_CALLBACK_BYTES {
                    break;
                }
            }
            Ok(Err(_)) => break,
        }
    }

    if buf.is_empty() {
        return None;
    }

    match parse_callback_request(&buf, expected_state) {
        ParsedRequest::IgnorePath => {
            write_response_and_close(&mut stream, not_found_http_response()).await;
            None
        }
        ParsedRequest::BadRequest(msg) => {
            write_response_and_close(&mut stream, &callback_http_response(false)).await;
            Some((
                OAuthCallback {
                    code: None,
                    returned_state: None,
                    error: Some(msg.to_string()),
                },
                None,
            ))
        }
        ParsedRequest::Callback(cb) => Some((cb, Some(stream))),
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: Option<String>,
    expires_in: Option<i64>,
    id_token: Option<String>,
}

async fn exchange_code_for_tokens(
    client: &reqwest::Client,
    code: &str,
    redirect_uri: &str,
    oauth_client: &OAuthClient,
) -> Result<TokenResponse, String> {
    let response = client
        .post(TOKEN_URL)
        .form(&[
            ("code", code),
            ("client_id", oauth_client.client_id.as_str()),
            ("client_secret", oauth_client.client_secret.as_str()),
            ("redirect_uri", redirect_uri),
            ("grant_type", "authorization_code"),
        ])
        .send()
        .await
        .map_err(|err| format!("Google token request failed: {err}"))?;

    let status = response.status();
    let bytes = response
        .bytes()
        .await
        .map_err(|err| format!("Failed to read Google token response: {err}"))?;
    if !status.is_success() {
        return Err(token_exchange_failure_message(&bytes, status.as_u16()));
    }
    serde_json::from_slice(&bytes)
        .map_err(|_| "Could not decode Google token response.".to_string())
}

fn token_exchange_failure_message(bytes: &[u8], status_code: u16) -> String {
    if let Ok(json) = serde_json::from_slice::<serde_json::Value>(bytes)
        && json.get("error").and_then(|v| v.as_str()) == Some("invalid_client")
    {
        return "Google rejected the Antigravity OAuth client (invalid_client). Update Antigravity, or set ANTIGRAVITY_OAUTH_CLIENT_ID and ANTIGRAVITY_OAUTH_CLIENT_SECRET before retrying.".to_string();
    }
    format!("Google token exchange failed (HTTP {status_code}).")
}

#[derive(Deserialize)]
struct UserInfoResponse {
    email: Option<String>,
}

async fn fetch_user_email(client: &reqwest::Client, access_token: &str) -> Option<String> {
    let response = client
        .get(USERINFO_URL)
        .bearer_auth(access_token)
        .timeout(USERINFO_TIMEOUT)
        .send()
        .await
        .ok()?;
    if !response.status().is_success() {
        return None;
    }
    let info: UserInfoResponse = response.json().await.ok()?;
    non_empty(info.email.as_deref()).map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorization_url_encodes_consumer_parameters() {
        let url = make_authorization_url(
            "http://127.0.0.1:43210/callback",
            "state-xyz",
            "123-client.apps.googleusercontent.com",
        )
        .unwrap();
        let parsed = reqwest::Url::parse(&url).unwrap();
        let pairs: std::collections::HashMap<String, String> = parsed
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        assert_eq!(
            pairs.get("client_id").map(String::as_str),
            Some("123-client.apps.googleusercontent.com")
        );
        assert_eq!(
            pairs.get("redirect_uri").map(String::as_str),
            Some("http://127.0.0.1:43210/callback")
        );
        assert_eq!(pairs.get("response_type").map(String::as_str), Some("code"));
        assert_eq!(
            pairs.get("access_type").map(String::as_str),
            Some("offline")
        );
        assert_eq!(
            pairs.get("prompt").map(String::as_str),
            Some("select_account consent")
        );
        assert_eq!(pairs.get("state").map(String::as_str), Some("state-xyz"));
        assert!(pairs.get("scope").unwrap().contains("cloud-platform"));
    }

    #[test]
    fn callback_parser_validates_path_state_code_and_error() {
        assert!(matches!(
            parse_callback_request(b"GET /favicon.ico HTTP/1.1\r\n\r\n", "s1"),
            ParsedRequest::IgnorePath
        ));
        match parse_callback_request(b"GET /callback?code=abc&state=s1 HTTP/1.1\r\n\r\n", "s1") {
            ParsedRequest::Callback(cb) => {
                assert_eq!(cb.code.as_deref(), Some("abc"));
                assert_eq!(cb.returned_state.as_deref(), Some("s1"));
                assert_eq!(cb.error, None);
            }
            _ => panic!("expected Callback"),
        }
        match parse_callback_request(b"GET /callback?code=abc&state=wrong HTTP/1.1\r\n\r\n", "s1") {
            ParsedRequest::Callback(cb) => {
                assert_eq!(cb.error.as_deref(), Some("state_mismatch"));
                assert!(cb.code.is_none());
            }
            _ => panic!("expected state mismatch"),
        }
    }

    #[test]
    fn token_exchange_maps_invalid_client_cleanly() {
        let msg = token_exchange_failure_message(br#"{"error":"invalid_client"}"#, 401);
        assert!(msg.contains("invalid_client"));
        assert!(msg.contains("ANTIGRAVITY_OAUTH_CLIENT_ID"));
        let generic = token_exchange_failure_message(br#"{"error":"secret_echo"}"#, 500);
        assert_eq!(generic, "Google token exchange failed (HTTP 500).");
        assert!(!generic.contains("secret_echo"));
    }

    #[tokio::test]
    async fn loopback_server_ignores_favicon_and_preconnect_and_defers_success_response() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let generation = LOGIN_GENERATION.load(Ordering::SeqCst);
        let server =
            tokio::spawn(
                async move { wait_for_callback(listener, "expected-state", generation).await },
            );

        // Speculative empty connection (e.g. browser preconnect) must be ignored.
        let mut preconnect = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        preconnect.shutdown().await.unwrap();

        let mut fav = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        fav.write_all(b"GET /favicon.ico HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut fav_resp = String::new();
        fav.read_to_string(&mut fav_resp).await.unwrap();
        assert!(fav_resp.starts_with("HTTP/1.1 404"));

        let mut cb = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        cb.write_all(b"GET /callback?code=auth-code-1&state=expected-state HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();

        let (received, mut stream) = server.await.unwrap().unwrap();
        assert_eq!(received.code.as_deref(), Some("auth-code-1"));
        assert_eq!(received.returned_state.as_deref(), Some("expected-state"));
        assert_eq!(received.error, None);

        let mut stream = stream.take().expect("callback response stream");
        write_response_and_close(&mut stream, &callback_http_response(true)).await;

        let mut cb_resp = String::new();
        cb.read_to_string(&mut cb_resp).await.unwrap();
        assert!(cb_resp.starts_with("HTTP/1.1 200 OK"));
        assert!(cb_resp.contains("Login Successful"));
    }

    #[tokio::test]
    async fn callback_error_response_reports_login_failed_instead_of_success() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let generation = LOGIN_GENERATION.load(Ordering::SeqCst);
        let server =
            tokio::spawn(
                async move { wait_for_callback(listener, "expected-state", generation).await },
            );

        let mut cb = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        cb.write_all(b"GET /callback?code=auth-code-2&state=expected-state HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();

        let (_received, mut stream) = server.await.unwrap().unwrap();
        let mut stream = stream.take().expect("callback response stream");
        write_response_and_close(&mut stream, &callback_http_response(false)).await;

        let mut cb_resp = String::new();
        cb.read_to_string(&mut cb_resp).await.unwrap();
        assert!(cb_resp.starts_with("HTTP/1.1 400 Bad Request"));
        assert!(cb_resp.contains("Login Failed"));
        assert!(!cb_resp.contains("Login Successful"));
    }
}
