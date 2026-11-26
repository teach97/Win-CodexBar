//! Google OAuth remote quota path.
//!
//! Port of upstream `AntigravityRemoteUsageFetcher` and
//! `AntigravityOAuthCredentialsStore` (CodexBar v0.71.0 #4102, v0.73.0
//! consumer-client recovery, v0.77.0 #4571 paid-tier plan labels, v0.79 #4632
//! daily-cloudcode-pa summary host) plus Windows PE64 RIP-relative client-pair
//! discovery for multi-client binaries such as `language_server.exe`.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::Duration;

use async_trait::async_trait;
use regex_lite::Regex;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::legacy_status::{self, RemoteModelQuota};
use super::offline_reason::{LiveFailure, RemoteFailureKind};
use super::quota_summary;
use crate::core::{ProviderError, RateWindow, UsageSnapshot};

pub(super) const CREDENTIALS_ENV: &str = "ANTIGRAVITY_OAUTH_CREDENTIALS_JSON";
const CLIENT_ID_ENV: &str = "ANTIGRAVITY_OAUTH_CLIENT_ID";
const CLIENT_SECRET_ENV: &str = "ANTIGRAVITY_OAUTH_CLIENT_SECRET";

/// Public consumer OAuth client id that `agy` and the Antigravity language
/// server use for personal Google account sign-in (`AntigravityOAuthConfig.consumerClientID`).
/// Bundles embed additional clients; Cloud Code treats non-consumer tokens as
/// unonboarded with placeholder 100% buckets.
pub(super) const CONSUMER_CLIENT_ID: &str =
    "1071006060591-tmhssin2h21lcre235vtolojh4g403ep.apps.googleusercontent.com";

pub(super) const NOT_LOGGED_IN_MESSAGE: &str = "Antigravity Google OAuth is not signed in. Sign in with Google in Settings > Providers > Antigravity, or set ANTIGRAVITY_OAUTH_CREDENTIALS_JSON.";
pub(super) const SESSION_EXPIRED_MESSAGE: &str =
    "Antigravity Google sign-in expired. Sign in to it again.";
pub(super) const REAUTHENTICATION_REQUIRED_MESSAGE: &str = "This Antigravity account was signed in with an OAuth client that cannot read its quota. Sign in to it again.";
const MISSING_CLIENT_MESSAGE: &str = "Could not discover a matching Antigravity OAuth client. Update or install Antigravity, or set ANTIGRAVITY_OAUTH_CLIENT_ID and ANTIGRAVITY_OAUTH_CLIENT_SECRET.";
const LIMITS_NOT_AVAILABLE: &str = "Limits not available";

pub(super) const BASE_URL: &str = "https://cloudcode-pa.googleapis.com";
/// Current quota lives on the daily host; the OAuth quota summary is read there
/// while every other Cloud Code call keeps `BASE_URL` (upstream #4632).
const DAILY_BASE_URL: &str = "https://daily-cloudcode-pa.googleapis.com";
pub(super) const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const SUMMARY_TIMEOUT_CAP: Duration = Duration::from_secs(2);
const REFRESH_SAFETY_WINDOW_MS: f64 = 60_000.0;
const ONBOARD_POLL_ATTEMPTS: usize = 5;
const ONBOARD_POLL_INTERVAL: Duration = Duration::from_secs(2);
/// Antigravity 2.x ships `language_server.exe` around 200 MiB; allow up to
/// 512 MiB when scanning installed artifacts for its OAuth client pair.
const MAX_CLIENT_ARTIFACT_BYTES: u64 = 512 * 1024 * 1024;
const TOS_NOT_SUPPORTED_BY_CLIENT: &str = "GOOGLE_TOS_NOT_SUPPORTED_BY_CLIENT";
const SESSION_WINDOW_MINUTES: u32 = 300;
const PE_PAIRING_LEA_WINDOW: usize = 160;

fn client_metadata() -> Value {
    json!({
        "ideType": "ANTIGRAVITY",
        "platform": "PLATFORM_UNSPECIFIED",
        "pluginType": "GEMINI",
    })
}

/// Cloud Code only grants quota access to the Antigravity Hub client family,
/// so every quota request carries a fixed Hub compatibility identity.
pub(super) fn user_agent() -> String {
    let architecture = if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        "amd64"
    };
    let platform = if cfg!(windows) {
        "windows"
    } else if cfg!(target_os = "macos") {
        "darwin"
    } else {
        "linux"
    };
    format!("antigravity/hub/2.9.1 {platform}/{architecture}")
}

// ── Credentials ─────────────────────────────────────────────────────

/// Serialized `AntigravityOAuthCredentials`. No `Debug`: every field but
/// `email` is a secret or identifies the grant.
#[derive(Clone, Default, PartialEq, Serialize, Deserialize)]
pub(super) struct OAuthCredentials {
    #[serde(alias = "accessToken", skip_serializing_if = "Option::is_none")]
    pub(super) access_token: Option<String>,
    #[serde(alias = "refreshToken", skip_serializing_if = "Option::is_none")]
    pub(super) refresh_token: Option<String>,
    /// Milliseconds since the Unix epoch.
    #[serde(alias = "expiresAt", skip_serializing_if = "Option::is_none")]
    pub(super) expiry_date: Option<f64>,
    #[serde(alias = "idToken", skip_serializing_if = "Option::is_none")]
    pub(super) id_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) email: Option<String>,
    #[serde(alias = "projectId", skip_serializing_if = "Option::is_none")]
    pub(super) project_id: Option<String>,
    #[serde(alias = "clientId", skip_serializing_if = "Option::is_none")]
    pub(super) client_id: Option<String>,
    #[serde(alias = "clientSecret", skip_serializing_if = "Option::is_none")]
    pub(super) client_secret: Option<String>,
}

#[derive(Clone, PartialEq, Eq)]
pub(super) struct OAuthClient {
    pub(super) client_id: String,
    pub(super) client_secret: String,
}

pub(super) fn default_home() -> PathBuf {
    dirs::home_dir().unwrap_or_else(|| PathBuf::from("."))
}

pub(super) fn credentials_path(home: &Path) -> PathBuf {
    home.join(".codexbar")
        .join("antigravity")
        .join("oauth_creds.json")
}

pub(super) fn non_empty(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

pub(super) fn credential_email(credentials: &OAuthCredentials) -> Option<String> {
    TokenClaims::from_credentials(credentials).email
}

struct TokenClaims {
    email: Option<String>,
    hosted_domain: Option<String>,
}

impl TokenClaims {
    fn from_credentials(credentials: &OAuthCredentials) -> Self {
        let claims = credentials.id_token.as_deref().and_then(jwt_payload);
        let claim = |name: &str| {
            claims
                .as_ref()
                .and_then(|claims| claims.get(name))
                .and_then(Value::as_str)
                .and_then(|value| non_empty(Some(value)))
                .map(str::to_owned)
        };
        Self {
            email: claim("email")
                .or_else(|| non_empty(credentials.email.as_deref()).map(str::to_owned)),
            hosted_domain: claim("hd"),
        }
    }
}

fn jwt_payload(token: &str) -> Option<Value> {
    use base64::Engine;
    let payload = token.split('.').nth(1)?;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload.trim_end_matches('='))
        .ok()?;
    serde_json::from_slice(&decoded).ok()
}

// ── Transport ───────────────────────────────────────────────────────

pub(super) enum RequestBody {
    Json(Value),
    Form(Vec<(&'static str, String)>),
}

/// One outbound POST. No `Debug`: it carries the bearer token and, for token
/// refresh, the refresh token and client secret.
pub(super) struct RemoteRequest {
    pub(super) url: String,
    pub(super) bearer: Option<String>,
    pub(super) user_agent: Option<String>,
    pub(super) body: RequestBody,
    pub(super) timeout: Duration,
}

pub(super) struct RemoteResponse {
    pub(super) status: u16,
    pub(super) body: Vec<u8>,
}

#[allow(
    clippy::double_must_use,
    reason = "async-trait marks its boxed futures #[must_use]"
)]
#[async_trait]
pub(super) trait RemoteTransport: Send + Sync {
    async fn post(&self, request: RemoteRequest) -> Result<RemoteResponse, ProviderError>;
}

pub(super) struct HttpRemoteTransport {
    client: reqwest::Client,
}

impl HttpRemoteTransport {
    fn new() -> Result<Self, ProviderError> {
        let client = crate::core::credentialed_http_client_builder()
            .build()
            .map_err(|error| ProviderError::Other(error.to_string()))?;
        Ok(Self { client })
    }
}

#[async_trait]
impl RemoteTransport for HttpRemoteTransport {
    async fn post(&self, request: RemoteRequest) -> Result<RemoteResponse, ProviderError> {
        let mut builder = self.client.post(&request.url).timeout(request.timeout);
        if let Some(bearer) = &request.bearer {
            builder = builder.bearer_auth(bearer);
        }
        if let Some(user_agent) = &request.user_agent {
            builder = builder.header(reqwest::header::USER_AGENT, user_agent);
        }
        builder = match &request.body {
            RequestBody::Json(body) => builder.json(body),
            RequestBody::Form(fields) => builder.form(fields),
        };
        let response = builder.send().await.map_err(map_transport_error)?;
        let status = response.status().as_u16();
        let body = response.bytes().await.map_err(map_transport_error)?;
        Ok(RemoteResponse {
            status,
            body: body.to_vec(),
        })
    }
}

fn map_transport_error(error: reqwest::Error) -> ProviderError {
    if error.is_timeout() {
        ProviderError::Timeout
    } else {
        ProviderError::Network(error)
    }
}

// ── Errors ──────────────────────────────────────────────────────────

#[derive(Debug)]
pub(super) enum RemoteError {
    NotLoggedIn,
    SessionExpired,
    ReauthenticationRequired,
    MissingOAuthClient,
    PermissionDenied,
    Api(u16),
    /// A retryable token-refresh failure (5xx, 429, ...): not a lost session.
    TransientApi(u16),
    Parse(String),
    Persist(String),
    Transport(ProviderError),
}

impl RemoteError {
    fn kind(&self) -> RemoteFailureKind {
        match self {
            Self::NotLoggedIn => RemoteFailureKind::NotLoggedIn,
            Self::SessionExpired => RemoteFailureKind::SessionExpired,
            Self::ReauthenticationRequired => RemoteFailureKind::ReauthenticationRequired,
            _ => RemoteFailureKind::RequestFailed,
        }
    }

    /// Response bodies are never copied into the error: Cloud Code error
    /// payloads can echo account or project details.
    pub(super) fn into_provider_error(self) -> ProviderError {
        match self {
            Self::NotLoggedIn => ProviderError::OAuth(NOT_LOGGED_IN_MESSAGE.to_string()),
            Self::SessionExpired => {
                ProviderError::OAuthExpired(SESSION_EXPIRED_MESSAGE.to_string())
            }
            Self::ReauthenticationRequired => {
                ProviderError::OAuth(REAUTHENTICATION_REQUIRED_MESSAGE.to_string())
            }
            Self::MissingOAuthClient => ProviderError::OAuth(MISSING_CLIENT_MESSAGE.to_string()),
            Self::PermissionDenied => ProviderError::Other(
                "Antigravity remote API permission denied (HTTP 403)".to_string(),
            ),
            Self::Api(status) => {
                ProviderError::Other(format!("Antigravity remote API error: HTTP {status}"))
            }
            Self::TransientApi(status) => ProviderError::OAuthTransient(format!(
                "Antigravity sign-in refresh failed (HTTP {status}). Try again later."
            )),
            Self::Parse(message) => ProviderError::Parse(format!(
                "Could not parse Antigravity remote usage: {message}"
            )),
            Self::Persist(message) => ProviderError::Other(format!(
                "Could not save Antigravity OAuth credentials: {message}"
            )),
            Self::Transport(error) => error,
        }
    }
}

impl From<RemoteError> for LiveFailure {
    fn from(error: RemoteError) -> Self {
        let kind = error.kind();
        LiveFailure::remote(error.into_provider_error(), kind)
    }
}

// ── Response models ─────────────────────────────────────────────────

#[derive(Deserialize)]
#[serde(untagged)]
enum ProjectReference {
    Id(String),
    Object {
        #[serde(alias = "projectId")]
        id: Option<String>,
    },
}

impl ProjectReference {
    fn value(&self) -> Option<String> {
        let raw = match self {
            Self::Id(id) => Some(id.as_str()),
            Self::Object { id } => id.as_deref(),
        };
        non_empty(raw).map(str::to_owned)
    }
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct CodeAssistResponse {
    plan_info: Option<CodeAssistPlanInfo>,
    current_tier: Option<TierInfo>,
    paid_tier: Option<TierInfo>,
    allowed_tiers: Option<Vec<AllowedTier>>,
    ineligible_tiers: Option<Vec<IneligibleTier>>,
    cloudaicompanion_project: Option<ProjectReference>,
}

impl CodeAssistResponse {
    fn project_id(&self) -> Option<String> {
        self.cloudaicompanion_project
            .as_ref()
            .and_then(ProjectReference::value)
    }

    /// Consumer accounts are unonboarded when the token's OAuth client is not
    /// the consumer sign-in client.
    fn rejects_client_for_consumer_tier(&self) -> bool {
        self.current_tier.is_none()
            && self.project_id().is_none()
            && self.ineligible_tiers.as_ref().is_some_and(|tiers| {
                tiers
                    .iter()
                    .any(|tier| tier.reason_code.as_deref() == Some(TOS_NOT_SUPPORTED_BY_CLIENT))
            })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CodeAssistPlanInfo {
    plan_type: Option<String>,
}

#[derive(Deserialize)]
struct TierInfo {
    id: Option<String>,
    name: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AllowedTier {
    id: Option<String>,
    is_default: Option<bool>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct IneligibleTier {
    reason_code: Option<String>,
}

#[derive(Deserialize)]
struct OnboardResponse {
    response: Option<OnboardInnerResponse>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OnboardInnerResponse {
    cloudaicompanion_project: Option<ProjectReference>,
}

#[derive(Deserialize)]
struct FetchAvailableModelsResponse {
    models: Option<BTreeMap<String, RemoteModel>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RemoteModel {
    display_name: Option<String>,
    label: Option<String>,
    quota_info: Option<RemoteQuotaInfo>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RemoteQuotaInfo {
    remaining_fraction: Option<f64>,
    reset_time: Option<String>,
}

#[derive(Deserialize)]
struct RetrieveUserQuotaResponse {
    buckets: Option<Vec<RetrieveUserQuotaBucket>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RetrieveUserQuotaBucket {
    model_id: Option<String>,
    remaining_fraction: Option<f64>,
    reset_time: Option<String>,
}

/// serde error text quotes string values from the payload, so a decode
/// failure reduces to a fixed category: response content must not reach
/// user-facing errors or logs.
const UNEXPECTED_RESPONSE_SHAPE: &str = "unexpected response shape";

fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, RemoteError> {
    serde_json::from_slice(bytes).map_err(|_| RemoteError::Parse(UNEXPECTED_RESPONSE_SHAPE.into()))
}

// ── Fetcher ─────────────────────────────────────────────────────────

enum CredentialSource {
    Injected(OAuthCredentials),
    Stored(PathBuf, OAuthCredentials),
}

pub(super) struct RemoteFetcher<T: RemoteTransport> {
    pub(super) transport: T,
    pub(super) home: PathBuf,
    /// Serialized credentials from `ANTIGRAVITY_OAUTH_CREDENTIALS_JSON`.
    pub(super) injected_credentials: Option<String>,
    /// `ANTIGRAVITY_OAUTH_CLIENT_ID` / `_SECRET` override.
    pub(super) configured_client: Option<OAuthClient>,
    /// Installed Antigravity files that may embed the OAuth client.
    pub(super) client_artifacts: Vec<PathBuf>,
    pub(super) timeout: Duration,
    pub(super) onboard_poll_interval: Duration,
}

fn configured_client_from_env() -> Option<OAuthClient> {
    let env = |key: &str| {
        std::env::var(key)
            .ok()
            .filter(|value| !value.trim().is_empty())
    };
    match (env(CLIENT_ID_ENV), env(CLIENT_SECRET_ENV)) {
        (Some(client_id), Some(client_secret)) => Some(OAuthClient {
            client_id: client_id.trim().to_string(),
            client_secret: client_secret.trim().to_string(),
        }),
        _ => None,
    }
}

/// Resolve the Antigravity OAuth client from explicit env vars or installed app binaries.
/// Caches discovered binary results keyed by `(path, len, mtime)` so Settings status
/// checks do not re-read large executables on every open.
pub(super) fn resolve_client_from_environment() -> Result<OAuthClient, RemoteError> {
    if let Some(client) = configured_client_from_env() {
        return Ok(client);
    }
    discover_client_cached(&default_client_artifacts()).ok_or(RemoteError::MissingOAuthClient)
}

#[derive(Clone, PartialEq, Eq)]
struct ArtifactFingerprint {
    path: PathBuf,
    len: u64,
    modified: Option<std::time::SystemTime>,
}

type DiscoveredClientCacheEntry = Option<(ArtifactFingerprint, Option<OAuthClient>)>;

static DISCOVERED_CLIENT_CACHE: LazyLock<std::sync::Mutex<DiscoveredClientCacheEntry>> =
    LazyLock::new(|| std::sync::Mutex::new(None));

fn discover_client_cached(paths: &[PathBuf]) -> Option<OAuthClient> {
    for path in paths {
        let Ok(metadata) = std::fs::metadata(path) else {
            continue;
        };
        if !metadata.is_file() || metadata.len() > MAX_CLIENT_ARTIFACT_BYTES {
            continue;
        }
        let fingerprint = ArtifactFingerprint {
            path: path.clone(),
            len: metadata.len(),
            modified: metadata.modified().ok(),
        };
        if let Ok(guard) = DISCOVERED_CLIENT_CACHE.lock()
            && let Some((cached_fp, cached_client)) = guard.as_ref()
            && *cached_fp == fingerprint
        {
            if let Some(client) = cached_client {
                return Some(client.clone());
            }
            continue;
        }
        let parsed = std::fs::read(path)
            .ok()
            .and_then(|bytes| parse_client_from_artifact(&bytes));
        if let Ok(mut guard) = DISCOVERED_CLIENT_CACHE.lock() {
            *guard = Some((fingerprint, parsed.clone()));
        }
        if parsed.is_some() {
            return parsed;
        }
    }
    None
}

impl RemoteFetcher<HttpRemoteTransport> {
    pub(super) fn from_environment() -> Result<Self, ProviderError> {
        let injected_credentials = std::env::var(CREDENTIALS_ENV)
            .ok()
            .filter(|value| !value.trim().is_empty());
        Ok(Self {
            transport: HttpRemoteTransport::new()?,
            home: default_home(),
            injected_credentials,
            configured_client: configured_client_from_env(),
            client_artifacts: default_client_artifacts(),
            timeout: REQUEST_TIMEOUT,
            onboard_poll_interval: ONBOARD_POLL_INTERVAL,
        })
    }
}

/// Windows install layout of the Antigravity desktop app.
fn default_client_artifacts() -> Vec<PathBuf> {
    let Some(local_app_data) = std::env::var_os("LOCALAPPDATA").map(PathBuf::from) else {
        return Vec::new();
    };
    let resources = local_app_data
        .join("Programs")
        .join("Antigravity")
        .join("resources");
    vec![
        resources.join("app").join("out").join("main.js"),
        resources
            .join("app")
            .join("extensions")
            .join("antigravity")
            .join("bin")
            .join("language_server_windows_x64.exe"),
        resources.join("bin").join("language_server.exe"),
    ]
}

pub(super) fn resolve_stored_credentials(
    home: &Path,
) -> Result<Option<OAuthCredentials>, RemoteError> {
    let path = credentials_path(home);
    if !path.is_file() {
        return Ok(None);
    }
    let contents = crate::secure_file::read_string(&path)
        .map_err(|error| RemoteError::Parse(format!("credentials file: {}", error.kind())))?;
    let credentials = serde_json::from_str::<OAuthCredentials>(&contents)
        .map_err(|_| RemoteError::Parse("Invalid Antigravity OAuth credentials file.".into()))?;
    Ok(Some(credentials))
}

impl<T: RemoteTransport> RemoteFetcher<T> {
    /// Whether Auto mode should try OAuth: injected credentials or the shared
    /// credentials file exist. Mirrors upstream's `hasSharedOAuthCredentials`.
    pub(super) fn has_credentials(&self) -> bool {
        // A blank injected value (for example an empty env var) is not a
        // credential; treating it as one would hide the real not-logged-in
        // error behind a decode failure.
        non_empty(self.injected_credentials.as_deref()).is_some()
            || credentials_path(&self.home).is_file()
    }

    fn resolve_credentials(&self) -> Result<Option<CredentialSource>, RemoteError> {
        if let Some(value) = non_empty(self.injected_credentials.as_deref()) {
            let credentials = serde_json::from_str::<OAuthCredentials>(value).map_err(|_| {
                RemoteError::Parse("Could not decode selected account credentials.".into())
            })?;
            return Ok(Some(CredentialSource::Injected(credentials)));
        }
        let path = credentials_path(&self.home);
        Ok(resolve_stored_credentials(&self.home)?
            .map(|credentials| CredentialSource::Stored(path, credentials)))
    }

    pub(super) async fn fetch(&self) -> Result<UsageSnapshot, RemoteError> {
        let (mut credentials, store) = match self.resolve_credentials()? {
            Some(CredentialSource::Injected(credentials)) => (credentials, None),
            Some(CredentialSource::Stored(path, credentials)) => (credentials, Some(path)),
            None => return Err(RemoteError::NotLoggedIn),
        };
        let Some(stored_access_token) = non_empty(credentials.access_token.as_deref()) else {
            return Err(RemoteError::NotLoggedIn);
        };
        let mut access_token = stored_access_token.to_string();

        let now_ms = chrono::Utc::now().timestamp_millis() as f64;
        if credentials
            .expiry_date
            .is_some_and(|expiry| expiry - now_ms <= REFRESH_SAFETY_WINDOW_MS)
        {
            let Some(refresh_token) = non_empty(credentials.refresh_token.as_deref()) else {
                return Err(RemoteError::NotLoggedIn);
            };
            let refresh_token = refresh_token.to_string();
            credentials = self
                .refresh_access_token(&credentials, &refresh_token, store.as_deref())
                .await?;
            access_token = credentials.access_token.clone().unwrap_or(access_token);
        }

        let claims = TokenClaims::from_credentials(&credentials);
        let code_assist = self.load_code_assist(&access_token).await?;
        let stored_project = non_empty(credentials.project_id.as_deref()).map(str::to_owned);
        if stored_project.is_none() && code_assist.rejects_client_for_consumer_tier() {
            // Quota endpoints would answer with a placeholder summary that
            // reports every bucket at 100%.
            return Err(RemoteError::ReauthenticationRequired);
        }
        let project_id = self
            .resolve_project_id(&access_token, stored_project.clone(), &code_assist)
            .await?;
        if let Some(project_id) = &project_id
            && stored_project.as_deref() != Some(project_id.as_str())
        {
            credentials.project_id = Some(project_id.clone());
            if let Some(path) = &store
                && let Err(error) = save_credentials(path, &credentials)
            {
                tracing::warn!(?error, "Could not persist Antigravity project ID");
            }
        }
        let plan = resolve_plan(&code_assist, claims.hosted_domain.as_deref());

        match self
            .post_cloud_code(
                format!("{DAILY_BASE_URL}/v1internal:retrieveUserQuotaSummary"),
                &access_token,
                project_id.as_deref(),
                self.timeout.min(SUMMARY_TIMEOUT_CAP),
            )
            .await
        {
            Ok(bytes) => match quota_summary::parse_usage_snapshot(&bytes) {
                Ok(summary) => {
                    // #4571: a measured five-hour quota contradicts a Free label.
                    let plan = if plan
                        .as_deref()
                        .is_some_and(|plan| plan.eq_ignore_ascii_case("free"))
                        && has_measured_session_window(&summary)
                    {
                        None
                    } else {
                        plan
                    };
                    return Ok(with_identity(summary, claims.email, plan));
                }
                Err(error) => {
                    tracing::debug!(%error, "Antigravity remote quota summary unusable");
                }
            },
            Err(error @ (RemoteError::NotLoggedIn | RemoteError::SessionExpired)) => {
                return Err(error);
            }
            Err(error) => {
                tracing::debug!(?error, "Antigravity remote quota summary unavailable");
            }
        }

        let models = self
            .fetch_model_quotas(&access_token, project_id.as_deref())
            .await?;
        let snapshot = if models.is_empty() {
            UsageSnapshot::new(RateWindow::informational(LIMITS_NOT_AVAILABLE))
        } else {
            legacy_status::snapshot_from_model_quotas(&models)
        };
        Ok(with_identity(snapshot, claims.email, plan))
    }

    async fn post(
        &self,
        url: String,
        access_token: &str,
        body: Value,
        timeout: Duration,
    ) -> Result<Vec<u8>, RemoteError> {
        let response = self
            .transport
            .post(RemoteRequest {
                url,
                bearer: Some(access_token.to_string()),
                user_agent: Some(user_agent()),
                body: RequestBody::Json(body),
                timeout,
            })
            .await
            .map_err(RemoteError::Transport)?;
        match response.status {
            200 => Ok(response.body),
            401 => Err(RemoteError::SessionExpired),
            403 => Err(RemoteError::PermissionDenied),
            status => Err(RemoteError::Api(status)),
        }
    }

    async fn post_cloud_code(
        &self,
        endpoint: String,
        access_token: &str,
        project_id: Option<&str>,
        timeout: Duration,
    ) -> Result<Vec<u8>, RemoteError> {
        let body = match non_empty(project_id) {
            Some(project) => json!({ "project": project }),
            None => json!({}),
        };
        self.post(endpoint, access_token, body, timeout).await
    }

    async fn load_code_assist(
        &self,
        access_token: &str,
    ) -> Result<CodeAssistResponse, RemoteError> {
        let bytes = self
            .post(
                format!("{BASE_URL}/v1internal:loadCodeAssist"),
                access_token,
                json!({ "metadata": client_metadata() }),
                self.timeout,
            )
            .await?;
        decode(&bytes)
    }

    async fn resolve_project_id(
        &self,
        access_token: &str,
        stored_project: Option<String>,
        initial: &CodeAssistResponse,
    ) -> Result<Option<String>, RemoteError> {
        if let Some(project) = stored_project.or_else(|| initial.project_id()) {
            return Ok(Some(project));
        }
        let Some(tier_id) = pick_onboard_tier(initial) else {
            return Ok(None);
        };

        let onboard = self
            .post(
                format!("{BASE_URL}/v1internal:onboardUser"),
                access_token,
                json!({ "tierId": tier_id, "metadata": client_metadata() }),
                self.timeout,
            )
            .await
            .and_then(|bytes| decode::<OnboardResponse>(&bytes));
        match onboard {
            Ok(response) => {
                if let Some(project) = response
                    .response
                    .and_then(|inner| inner.cloudaicompanion_project)
                    .and_then(|project| project.value())
                {
                    return Ok(Some(project));
                }
            }
            Err(error) => tracing::warn!(?error, "Antigravity onboarding request failed"),
        }

        for _ in 0..ONBOARD_POLL_ATTEMPTS {
            tokio::time::sleep(self.onboard_poll_interval).await;
            if let Some(project) = self.load_code_assist(access_token).await?.project_id() {
                return Ok(Some(project));
            }
        }
        Ok(None)
    }

    async fn fetch_model_quotas(
        &self,
        access_token: &str,
        project_id: Option<&str>,
    ) -> Result<Vec<RemoteModelQuota>, RemoteError> {
        let response = self
            .post_cloud_code(
                format!("{BASE_URL}/v1internal:fetchAvailableModels"),
                access_token,
                project_id,
                self.timeout,
            )
            .await
            .and_then(|bytes| decode::<FetchAvailableModelsResponse>(&bytes));
        match response {
            Ok(response) => {
                let model_quotas = parse_model_quotas(response);
                if !should_verify_full_quotas(&model_quotas) {
                    return Ok(model_quotas);
                }
                // An all-100% model list may only prove availability; keep it
                // only when the quota endpoint confirms real readings.
                match self
                    .fetch_quota_buckets_if_permitted(access_token, project_id)
                    .await?
                {
                    Some(verified)
                        if verified
                            .iter()
                            .any(|quota| quota.remaining_fraction.is_some()) =>
                    {
                        Ok(merge_verified_quotas(model_quotas, verified))
                    }
                    _ => Ok(Vec::new()),
                }
            }
            Err(RemoteError::PermissionDenied) => {
                tracing::info!("Falling back to retrieveUserQuota for Antigravity remote usage");
                Ok(self
                    .fetch_quota_buckets_if_permitted(access_token, project_id)
                    .await?
                    .unwrap_or_default())
            }
            Err(error) => Err(error),
        }
    }

    async fn fetch_quota_buckets_if_permitted(
        &self,
        access_token: &str,
        project_id: Option<&str>,
    ) -> Result<Option<Vec<RemoteModelQuota>>, RemoteError> {
        let response = self
            .post_cloud_code(
                format!("{BASE_URL}/v1internal:retrieveUserQuota"),
                access_token,
                project_id,
                self.timeout,
            )
            .await
            .and_then(|bytes| decode::<RetrieveUserQuotaResponse>(&bytes));
        match response {
            Ok(response) => parse_quota_buckets(response).map(Some),
            Err(RemoteError::PermissionDenied) => {
                tracing::info!(
                    "Antigravity remote quota endpoint is not permitted for this account"
                );
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    async fn refresh_access_token(
        &self,
        credentials: &OAuthCredentials,
        refresh_token: &str,
        store: Option<&Path>,
    ) -> Result<OAuthCredentials, RemoteError> {
        let client = self.refresh_client(credentials)?;
        let response = self
            .transport
            .post(RemoteRequest {
                url: TOKEN_URL.to_string(),
                bearer: None,
                user_agent: None,
                body: RequestBody::Form(vec![
                    ("client_id", client.client_id),
                    ("client_secret", client.client_secret),
                    ("refresh_token", refresh_token.to_string()),
                    ("grant_type", "refresh_token".to_string()),
                ]),
                timeout: self.timeout,
            })
            .await
            .map_err(RemoteError::Transport)?;
        match response.status {
            200 => {}
            // Only the invalid_grant family (400/401) means the session is
            // gone; a 5xx or 429 is transient and must not tell the user to
            // sign in again.
            400 | 401 => return Err(RemoteError::SessionExpired),
            status => return Err(RemoteError::TransientApi(status)),
        }
        let json: Value = serde_json::from_slice(&response.body)
            .map_err(|_| RemoteError::Parse("Could not parse refresh response".into()))?;
        let Some(access_token) = json.get("access_token").and_then(Value::as_str) else {
            return Err(RemoteError::Parse(
                "Could not parse refresh response".into(),
            ));
        };

        let mut updated = credentials.clone();
        updated.access_token = Some(access_token.to_string());
        if let Some(expires_in) = json.get("expires_in").and_then(Value::as_f64) {
            updated.expiry_date =
                Some(chrono::Utc::now().timestamp_millis() as f64 + expires_in * 1000.0);
        }
        if let Some(id_token) = json.get("id_token").and_then(Value::as_str) {
            updated.id_token = Some(id_token.to_string());
        }
        if let Some(path) = store {
            save_credentials(path, &updated)
                .map_err(|error| RemoteError::Persist(error.kind().to_string()))?;
        }
        tracing::debug!("Antigravity OAuth token refreshed");
        Ok(updated)
    }

    /// Refresh tokens stay bound to the client that issued them, so a client
    /// stored with the credentials always wins over discovery.
    fn refresh_client(&self, credentials: &OAuthCredentials) -> Result<OAuthClient, RemoteError> {
        if let (Some(client_id), Some(client_secret)) = (
            non_empty(credentials.client_id.as_deref()),
            non_empty(credentials.client_secret.as_deref()),
        ) {
            return Ok(OAuthClient {
                client_id: client_id.to_string(),
                client_secret: client_secret.to_string(),
            });
        }
        self.configured_client
            .clone()
            .or_else(|| discover_client(&self.client_artifacts))
            .ok_or(RemoteError::MissingOAuthClient)
    }
}

pub(super) fn save_credentials(path: &Path, credentials: &OAuthCredentials) -> std::io::Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)?;
    }
    let contents = serde_json::to_string_pretty(credentials).map_err(std::io::Error::other)?;
    crate::secure_file::write_string(path, &contents)
}

fn with_identity(
    mut snapshot: UsageSnapshot,
    email: Option<String>,
    plan: Option<String>,
) -> UsageSnapshot {
    if let Some(email) = email {
        snapshot = snapshot.with_email(email);
    }
    if let Some(plan) = plan {
        snapshot = snapshot.with_login_method(plan);
    }
    snapshot
}

fn has_measured_session_window(snapshot: &UsageSnapshot) -> bool {
    let measured = |window: &RateWindow| {
        !window.is_informational && window.window_minutes == Some(SESSION_WINDOW_MINUTES)
    };
    measured(&snapshot.primary)
        || snapshot
            .extra_rate_windows
            .iter()
            .any(|row| row.usage_known && measured(&row.window))
}

fn resolve_plan(response: &CodeAssistResponse, hosted_domain: Option<&str>) -> Option<String> {
    if let Some(tier) = &response.paid_tier {
        let name = non_empty(tier.name.as_deref());
        if name.is_some() || non_empty(tier.id.as_deref()).is_some() {
            return Some(name.unwrap_or("Paid").to_string());
        }
    }
    if let Some(plan_type) = response
        .plan_info
        .as_ref()
        .and_then(|info| non_empty(info.plan_type.as_deref()))
    {
        return Some(plan_type.to_string());
    }
    let current = response.current_tier.as_ref();
    match current.and_then(|tier| non_empty(tier.id.as_deref())) {
        Some("standard-tier") => Some("Paid".to_string()),
        Some("free-tier") => Some(
            if hosted_domain.is_none() {
                "Free"
            } else {
                "Workspace"
            }
            .to_string(),
        ),
        Some("legacy-tier") => Some("Legacy".to_string()),
        _ => current
            .and_then(|tier| non_empty(tier.name.as_deref()))
            .map(str::to_owned),
    }
}

fn pick_onboard_tier(response: &CodeAssistResponse) -> Option<String> {
    let allowed = response.allowed_tiers.as_deref().unwrap_or_default();
    allowed
        .iter()
        .filter(|tier| tier.is_default == Some(true))
        .chain(allowed.iter())
        .find_map(|tier| non_empty(tier.id.as_deref()))
        .or_else(|| {
            response
                .paid_tier
                .as_ref()
                .and_then(|tier| non_empty(tier.id.as_deref()))
        })
        .or_else(|| {
            response
                .current_tier
                .as_ref()
                .and_then(|tier| non_empty(tier.id.as_deref()))
        })
        .map(str::to_owned)
}

fn parse_model_quotas(response: FetchAvailableModelsResponse) -> Vec<RemoteModelQuota> {
    response
        .models
        .unwrap_or_default()
        .into_iter()
        .filter_map(|(model_id, model)| {
            let quota = model.quota_info?;
            let label = non_empty(model.display_name.as_deref())
                .or_else(|| non_empty(model.label.as_deref()))
                .unwrap_or(&model_id)
                .to_string();
            Some(RemoteModelQuota {
                label,
                model_id,
                remaining_fraction: quota.remaining_fraction,
                reset_time: quota.reset_time,
            })
        })
        .collect()
}

fn parse_quota_buckets(
    response: RetrieveUserQuotaResponse,
) -> Result<Vec<RemoteModelQuota>, RemoteError> {
    let buckets = response
        .buckets
        .ok_or_else(|| RemoteError::Parse("No quota buckets in response".into()))?;
    let mut by_model: BTreeMap<String, (Option<f64>, Option<String>)> = BTreeMap::new();
    for bucket in buckets {
        let Some(model_id) = non_empty(bucket.model_id.as_deref()).map(str::to_owned) else {
            continue;
        };
        if let Some((existing, _)) = by_model.get(&model_id)
            && existing.unwrap_or(f64::MAX) <= bucket.remaining_fraction.unwrap_or(f64::MAX)
        {
            continue;
        }
        by_model.insert(model_id, (bucket.remaining_fraction, bucket.reset_time));
    }
    Ok(by_model
        .into_iter()
        .map(
            |(model_id, (remaining_fraction, reset_time))| RemoteModelQuota {
                label: model_id.clone(),
                model_id,
                remaining_fraction,
                reset_time,
            },
        )
        .collect())
}

fn should_verify_full_quotas(quotas: &[RemoteModelQuota]) -> bool {
    !quotas.is_empty()
        && quotas
            .iter()
            .all(|quota| quota.remaining_fraction.unwrap_or(0.0) >= 0.999)
}

fn quota_key(model_id: &str) -> String {
    model_id.trim().to_lowercase()
}

fn merge_verified_quotas(
    model_quotas: Vec<RemoteModelQuota>,
    verified: Vec<RemoteModelQuota>,
) -> Vec<RemoteModelQuota> {
    let mut verified_by_id: HashMap<String, RemoteModelQuota> = verified
        .into_iter()
        .map(|quota| (quota_key(&quota.model_id), quota))
        .collect();
    let mut merged = model_quotas
        .into_iter()
        .filter_map(|model| {
            let verified = verified_by_id.remove(&quota_key(&model.model_id))?;
            Some(RemoteModelQuota {
                remaining_fraction: verified.remaining_fraction.or(model.remaining_fraction),
                reset_time: verified.reset_time.or(model.reset_time),
                label: model.label,
                model_id: model.model_id,
            })
        })
        .collect::<Vec<_>>();
    let mut unmatched = verified_by_id
        .into_values()
        .filter(|quota| quota.remaining_fraction.is_some())
        .collect::<Vec<_>>();
    unmatched.sort_by_key(|quota| quota.model_id.to_lowercase());
    merged.extend(unmatched);
    merged
}

// ── OAuth client discovery ──────────────────────────────────────────

const CLIENT_ID_MARKER: &[u8] = b".apps.googleusercontent.com";
const CLIENT_SECRET_MARKER: &[u8] = b"GOCSPX-";
const CLIENT_SECRET_SUFFIX_LEN: usize = 28;
const OAUTH_CLIENT_MODULE_MARKER: &[u8] = b"vs/platform/cloudCode/common/oauthClient.js";
const TEXT_ARTIFACT_WINDOW: usize = 4000;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;

static CLIENT_ID_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"[0-9]+-[A-Za-z0-9_-]+\.apps\.googleusercontent\.com$").expect("valid regex")
});
static CLIENT_SECRET_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^GOCSPX-[A-Za-z0-9_-]{28}$").expect("valid regex"));

fn discover_client(paths: &[PathBuf]) -> Option<OAuthClient> {
    paths.iter().find_map(|path| {
        let metadata = std::fs::metadata(path).ok()?;
        if !metadata.is_file() || metadata.len() > MAX_CLIENT_ARTIFACT_BYTES {
            return None;
        }
        parse_client_from_artifact(&std::fs::read(path).ok()?)
    })
}

/// Text artifacts are scanned only near the bundled OAuth client module (or
/// their start). Native PE64 executables pair `CONSUMER_CLIENT_ID` with its
/// secret via x64 RIP-relative `LEA` proximity when several clients coexist;
/// simpler binaries fall back to unambiguous single-client matching.
pub(super) fn parse_client_from_artifact(data: &[u8]) -> Option<OAuthClient> {
    if std::str::from_utf8(data).is_ok() {
        let start = find(data, OAUTH_CLIENT_MODULE_MARKER, 0).unwrap_or(0);
        let end = (start + TEXT_ARTIFACT_WINDOW).min(data.len());
        return unambiguous_client(&data[start..end]);
    }
    if let Some(paired) = parse_pe64_paired_client(data) {
        return Some(paired);
    }
    unambiguous_client(data)
}

#[derive(Clone, Copy)]
struct PeSection {
    is_executable: bool,
    virtual_address: u64,
    virtual_size: usize,
    raw_ptr: usize,
    raw_size: usize,
}

fn read_u16_le(data: &[u8], off: usize) -> Option<u16> {
    let bytes: [u8; 2] = data.get(off..off + 2)?.try_into().ok()?;
    Some(u16::from_le_bytes(bytes))
}

fn read_u32_le(data: &[u8], off: usize) -> Option<u32> {
    let bytes: [u8; 4] = data.get(off..off + 4)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

fn read_i32_le(data: &[u8], off: usize) -> Option<i32> {
    let bytes: [u8; 4] = data.get(off..off + 4)?.try_into().ok()?;
    Some(i32::from_le_bytes(bytes))
}

fn parse_pe64_sections(data: &[u8]) -> Option<Vec<PeSection>> {
    if data.get(0..2) != Some(b"MZ") {
        return None;
    }
    let e_lfanew = read_u32_le(data, 0x3c)? as usize;
    if data.get(e_lfanew..e_lfanew + 4) != Some(b"PE\0\0") {
        return None;
    }
    let coff = e_lfanew + 4;
    // AMD64 (0x8664) COFF machine
    if read_u16_le(data, coff)? != 0x8664 {
        return None;
    }
    let num_sections = read_u16_le(data, coff + 2)? as usize;
    let opt_size = read_u16_le(data, coff + 16)? as usize;
    let opt = coff + 20;
    // PE32+ optional header magic (0x020b)
    if read_u16_le(data, opt)? != 0x020b {
        return None;
    }
    let sec_table = opt.checked_add(opt_size)?;
    let table_end = sec_table.checked_add(num_sections.checked_mul(40)?)?;
    if table_end > data.len() {
        return None;
    }
    let mut sections = Vec::with_capacity(num_sections);
    for idx in 0..num_sections {
        let off = sec_table + idx * 40;
        let name = data.get(off..off + 8)?;
        let virtual_size = read_u32_le(data, off + 8)? as usize;
        let virtual_address = u64::from(read_u32_le(data, off + 12)?);
        let raw_size = read_u32_le(data, off + 16)? as usize;
        let raw_ptr = read_u32_le(data, off + 20)? as usize;
        let characteristics = read_u32_le(data, off + 36)?;
        let is_executable =
            (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0 || name.starts_with(b".text");
        sections.push(PeSection {
            is_executable,
            virtual_address,
            virtual_size,
            raw_ptr,
            raw_size,
        });
    }
    Some(sections)
}

fn file_offset_to_rva(sections: &[PeSection], offset: usize) -> Option<u64> {
    for section in sections {
        let span = section
            .raw_size
            .min(section.virtual_size.max(section.raw_size));
        if offset >= section.raw_ptr && offset < section.raw_ptr.saturating_add(span) {
            return Some(section.virtual_address + (offset - section.raw_ptr) as u64);
        }
    }
    None
}

fn decode_x64_rip_lea(code: &[u8], section_rva: u64, pos: usize) -> Option<u64> {
    let prefix = *code.get(pos)?;
    if prefix != 0x48 && prefix != 0x4C {
        return None;
    }
    if *code.get(pos + 1)? != 0x8D {
        return None;
    }
    let modrm = *code.get(pos + 2)?;
    if (modrm & 0xC7) != 0x05 {
        return None;
    }
    let disp = i64::from(read_i32_le(code, pos + 3)?);
    let inst_end_rva = i64::try_from(section_rva)
        .ok()?
        .checked_add(i64::try_from(pos + 7).ok()?)?;
    u64::try_from(inst_end_rva.checked_add(disp)?).ok()
}

/// Windows Antigravity builds embed multiple OAuth clients in `language_server.exe`.
/// Pair `CONSUMER_CLIENT_ID` with its matching `GOCSPX-` secret by finding x64
/// `LEA reg, [rip+disp32]` instructions referencing the consumer client id and a
/// secret string within the same local instruction window.
fn parse_pe64_paired_client(data: &[u8]) -> Option<OAuthClient> {
    let sections = parse_pe64_sections(data)?;

    let mut id_rvas = Vec::new();
    let mut from = 0;
    let id_bytes = CONSUMER_CLIENT_ID.as_bytes();
    while let Some(offset) = find(data, id_bytes, from) {
        from = offset + id_bytes.len();
        if let Some(rva) = file_offset_to_rva(&sections, offset)
            && !id_rvas.contains(&rva)
        {
            id_rvas.push(rva);
        }
    }
    if id_rvas.is_empty() {
        return None;
    }

    let mut secret_by_rva = HashMap::<u64, String>::new();
    let mut from = 0;
    while let Some(offset) = find(data, CLIENT_SECRET_MARKER, from) {
        from = offset + CLIENT_SECRET_MARKER.len();
        let end = offset + CLIENT_SECRET_MARKER.len() + CLIENT_SECRET_SUFFIX_LEN;
        let Some(Ok(secret)) = data.get(offset..end).map(std::str::from_utf8) else {
            continue;
        };
        if CLIENT_SECRET_RE.is_match(secret)
            && let Some(rva) = file_offset_to_rva(&sections, offset)
        {
            secret_by_rva.insert(rva, secret.to_string());
        }
    }
    if secret_by_rva.is_empty() {
        return None;
    }

    let mut matched_secrets = Vec::<String>::new();
    for section in sections.iter().filter(|section| section.is_executable) {
        let Some(end) = section.raw_ptr.checked_add(section.raw_size) else {
            continue;
        };
        let Some(code) = data.get(section.raw_ptr..end.min(data.len())) else {
            continue;
        };
        for pos in 0..code.len().saturating_sub(6) {
            let Some(target) = decode_x64_rip_lea(code, section.virtual_address, pos) else {
                continue;
            };
            if !id_rvas.contains(&target) {
                continue;
            }
            let win_start = pos.saturating_sub(PE_PAIRING_LEA_WINDOW);
            let win_end = (pos + 7 + PE_PAIRING_LEA_WINDOW).min(code.len().saturating_sub(6));
            for nearby in win_start..win_end {
                if nearby == pos {
                    continue;
                }
                if let Some(secret_rva) = decode_x64_rip_lea(code, section.virtual_address, nearby)
                    && let Some(secret) = secret_by_rva.get(&secret_rva)
                    && !matched_secrets.contains(secret)
                {
                    matched_secrets.push(secret.clone());
                }
            }
        }
    }

    (matched_secrets.len() == 1).then(|| OAuthClient {
        client_id: CONSUMER_CLIENT_ID.to_string(),
        client_secret: matched_secrets.remove(0),
    })
}

fn find(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    haystack
        .get(from..)?
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|offset| from + offset)
}

fn is_client_id_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'
}

fn unambiguous_client(data: &[u8]) -> Option<OAuthClient> {
    let mut ids = Vec::<String>::new();
    let mut from = 0;
    while let Some(index) = find(data, CLIENT_ID_MARKER, from) {
        from = index + CLIENT_ID_MARKER.len();
        let floor = index.saturating_sub(256);
        let mut start = index;
        while start > floor && is_client_id_byte(data[start - 1]) {
            start -= 1;
        }
        let Ok(text) = std::str::from_utf8(&data[start..from]) else {
            continue;
        };
        if let Some(found) = CLIENT_ID_RE.find(text) {
            let id = found.as_str().to_string();
            if !ids.contains(&id) {
                ids.push(id);
            }
        }
        if ids.len() > 1 {
            return None;
        }
    }

    let mut secrets = Vec::<String>::new();
    let mut from = 0;
    while let Some(index) = find(data, CLIENT_SECRET_MARKER, from) {
        from = index + CLIENT_SECRET_MARKER.len();
        let end = from + CLIENT_SECRET_SUFFIX_LEN;
        let Some(Ok(text)) = data.get(index..end).map(std::str::from_utf8) else {
            continue;
        };
        if CLIENT_SECRET_RE.is_match(text) && !secrets.iter().any(|secret| secret == text) {
            secrets.push(text.to_string());
        }
        if secrets.len() > 1 {
            return None;
        }
    }

    Some(OAuthClient {
        client_id: ids.pop()?,
        client_secret: secrets.pop()?,
    })
}

#[cfg(test)]
#[path = "remote_tests.rs"]
mod tests;
