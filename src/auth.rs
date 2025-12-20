use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use openidconnect::{
    core::{CoreClient, CoreProviderMetadata, CoreResponseType},
    reqwest::async_http_client,
    AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce,
    OAuth2TokenResponse, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, RefreshToken, Scope,
    TokenResponse,
};
use rocket::{
    http::{Cookie, CookieJar, SameSite, Status},
    response::Redirect,
    serde::json::Json,
    State,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// OIDC configuration loaded from Api.toml
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct OidcConfig {
    pub issuer_url: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    #[serde(default = "default_scopes")]
    pub scopes: Vec<String>,
    pub admin_group: String,
    pub session_secret: String,
    #[serde(default = "default_session_duration")]
    pub session_duration_hours: u64,
    #[serde(default = "default_post_login_redirect")]
    pub post_login_redirect: String,
    #[serde(default = "default_post_logout_redirect")]
    pub post_logout_redirect: String,
    /// Optional userinfo endpoint override. If not set, will be derived from issuer_url.
    pub userinfo_endpoint: Option<String>,
}

fn default_scopes() -> Vec<String> {
    vec![
        "openid".to_string(),
        "profile".to_string(),
        "email".to_string(),
        "groups".to_string(),
    ]
}

fn default_session_duration() -> u64 {
    24
}

fn default_post_login_redirect() -> String {
    "/".to_string()
}

fn default_post_logout_redirect() -> String {
    "/".to_string()
}

/// CORS configuration loaded from Api.toml
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct CorsConfig {
    pub allowed_origin: String,
}

/// Discovered OIDC provider client (managed state)
pub struct OidcClient {
    pub client: CoreClient,
    pub config: OidcConfig,
}

/// JWT claims for session cookie
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SessionClaims {
    pub sub: String,
    pub username: String,
    pub email: String,
    pub groups: Vec<String>,
    pub exp: usize,
    pub iat: usize,
    /// Encrypted refresh token (base64 encoded, XOR with session secret)
    pub refresh_token: String,
}

/// PKCE state stored in temporary cookie during auth flow
#[derive(Debug, Serialize, Deserialize)]
struct PkceState {
    verifier: String,
    csrf_state: String,
    nonce: String,
    redirect_after_login: Option<String>,
}

/// User info response for /auth/userinfo
#[derive(Debug, Serialize, Deserialize)]
pub struct UserInfo {
    pub username: String,
    pub email: String,
    pub groups: Vec<String>,
}

/// Error response
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthError {
    pub error: String,
    pub message: String,
}

const SESSION_COOKIE_NAME: &str = "session";
const PKCE_COOKIE_NAME: &str = "pkce_state";

/// Initialize OIDC client by discovering provider metadata
pub async fn init_oidc_client(config: OidcConfig) -> Result<OidcClient, String> {
    let issuer_url = IssuerUrl::new(config.issuer_url.clone())
        .map_err(|e| format!("Invalid issuer URL: {}", e))?;

    // Try standard discovery first
    let provider_metadata =
        match CoreProviderMetadata::discover_async(issuer_url.clone(), async_http_client).await {
            Ok(metadata) => metadata,
            Err(e) => {
                // If standard discovery fails, try manual discovery with more details
                eprintln!("Standard OIDC discovery failed: {:?}", e);
                eprintln!("Attempting manual discovery...");

                // Fetch the discovery document manually to get more error details
                let discovery_url = format!(
                    "{}/.well-known/openid-configuration",
                    config.issuer_url.trim_end_matches('/')
                );

                let http_client = reqwest::Client::new();
                let response = http_client
                    .get(&discovery_url)
                    .send()
                    .await
                    .map_err(|e| format!("Failed to fetch discovery document: {}", e))?;

                let status = response.status();
                let body = response
                    .text()
                    .await
                    .map_err(|e| format!("Failed to read discovery response body: {}", e))?;

                if !status.is_success() {
                    return Err(format!(
                        "Discovery endpoint returned status {}: {}",
                        status, body
                    ));
                }

                eprintln!("Discovery document fetched successfully, attempting to parse...");

                // Try to parse as JSON to see what fields are there
                let json: serde_json::Value = serde_json::from_str(&body)
                    .map_err(|e| format!("Discovery document is not valid JSON: {}", e))?;

                eprintln!(
                    "Discovery JSON keys: {:?}",
                    json.as_object().map(|o| o.keys().collect::<Vec<_>>())
                );

                // Try to deserialize into CoreProviderMetadata
                let metadata: CoreProviderMetadata = serde_json::from_str(&body).map_err(|e| {
                    format!(
                        "Failed to parse discovery document as OIDC metadata: {}. Raw JSON: {}",
                        e,
                        &body[..body.len().min(500)]
                    )
                })?;

                metadata
            }
        };

    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        ClientId::new(config.client_id.clone()),
        Some(ClientSecret::new(config.client_secret.clone())),
    )
    .set_redirect_uri(
        RedirectUrl::new(config.redirect_uri.clone())
            .map_err(|e| format!("Invalid redirect URI: {}", e))?,
    );

    Ok(OidcClient { client, config })
}

/// Simple XOR encryption for refresh token (not cryptographically secure, but obfuscates)
fn encrypt_refresh_token(token: &str, secret: &str) -> String {
    let key_bytes = secret.as_bytes();
    let encrypted: Vec<u8> = token
        .as_bytes()
        .iter()
        .enumerate()
        .map(|(i, b)| b ^ key_bytes[i % key_bytes.len()])
        .collect();
    BASE64.encode(&encrypted)
}

fn decrypt_refresh_token(encrypted: &str, secret: &str) -> Result<String, String> {
    let encrypted_bytes = BASE64
        .decode(encrypted)
        .map_err(|e| format!("Failed to decode refresh token: {}", e))?;
    let key_bytes = secret.as_bytes();
    let decrypted: Vec<u8> = encrypted_bytes
        .iter()
        .enumerate()
        .map(|(i, b)| b ^ key_bytes[i % key_bytes.len()])
        .collect();
    String::from_utf8(decrypted).map_err(|e| format!("Failed to decrypt refresh token: {}", e))
}

/// Create a session JWT from claims
fn create_session_jwt(claims: &SessionClaims, secret: &str) -> Result<String, String> {
    encode(
        &Header::default(),
        claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|e| format!("Failed to create session JWT: {}", e))
}

/// Validate and decode a session JWT
pub fn validate_session_jwt(token: &str, secret: &str) -> Result<SessionClaims, String> {
    let mut validation = Validation::default();
    validation.validate_exp = true;

    decode::<SessionClaims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .map(|data| data.claims)
    .map_err(|e| format!("Failed to validate session JWT: {}", e))
}

/// GET /auth/login - Initiates OIDC authentication flow
#[get("/login?<redirect>")]
pub fn login(
    oidc: &State<Arc<OidcClient>>,
    cookies: &CookieJar<'_>,
    redirect: Option<String>,
) -> Redirect {
    // Generate PKCE challenge
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    // Generate state and nonce
    let csrf_state = CsrfToken::new_random();
    let nonce = Nonce::new_random();

    // Clone values for the cookie before moving into closures
    let csrf_state_secret = csrf_state.secret().clone();
    let nonce_secret = nonce.secret().clone();

    // Build authorization URL
    let mut auth_request = oidc
        .client
        .authorize_url(
            AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            move || csrf_state,
            move || nonce,
        )
        .set_pkce_challenge(pkce_challenge);

    // Add configured scopes
    for scope in &oidc.config.scopes {
        auth_request = auth_request.add_scope(Scope::new(scope.clone()));
    }

    let (auth_url, _, _) = auth_request.url();

    // Store PKCE state in cookie
    let pkce_state = PkceState {
        verifier: pkce_verifier.secret().clone(),
        csrf_state: csrf_state_secret,
        nonce: nonce_secret,
        redirect_after_login: redirect,
    };

    let pkce_cookie = Cookie::build((
        PKCE_COOKIE_NAME,
        serde_json::to_string(&pkce_state).unwrap(),
    ))
    .path("/")
    .http_only(true)
    .same_site(SameSite::Lax)
    .max_age(rocket::time::Duration::minutes(5))
    .secure(!cfg!(debug_assertions));

    cookies.add(pkce_cookie);

    Redirect::to(auth_url.to_string())
}

/// GET /auth/callback - Handles OIDC callback after authentication
#[get("/callback?<code>&<state>")]
pub async fn callback(
    oidc: &State<Arc<OidcClient>>,
    cookies: &CookieJar<'_>,
    code: String,
    state: String,
) -> Result<Redirect, (Status, Json<AuthError>)> {
    // Retrieve and validate PKCE state
    let pkce_cookie = cookies.get(PKCE_COOKIE_NAME).ok_or_else(|| {
        (
            Status::BadRequest,
            Json(AuthError {
                error: "missing_state".to_string(),
                message: "PKCE state cookie not found. Please try logging in again.".to_string(),
            }),
        )
    })?;

    let pkce_state: PkceState = serde_json::from_str(pkce_cookie.value()).map_err(|_| {
        (
            Status::BadRequest,
            Json(AuthError {
                error: "invalid_state".to_string(),
                message: "Invalid PKCE state. Please try logging in again.".to_string(),
            }),
        )
    })?;

    // Validate CSRF state
    if state != pkce_state.csrf_state {
        return Err((
            Status::BadRequest,
            Json(AuthError {
                error: "csrf_mismatch".to_string(),
                message: "CSRF state mismatch. Please try logging in again.".to_string(),
            }),
        ));
    }

    // Exchange authorization code for tokens
    let token_response = oidc
        .client
        .exchange_code(AuthorizationCode::new(code))
        .set_pkce_verifier(PkceCodeVerifier::new(pkce_state.verifier))
        .request_async(async_http_client)
        .await
        .map_err(|e| {
            (
                Status::InternalServerError,
                Json(AuthError {
                    error: "token_exchange_failed".to_string(),
                    message: format!("Failed to exchange authorization code: {:?}", e),
                }),
            )
        })?;

    // Get ID token
    let id_token = token_response.id_token().ok_or_else(|| {
        (
            Status::InternalServerError,
            Json(AuthError {
                error: "missing_id_token".to_string(),
                message: "No ID token in response".to_string(),
            }),
        )
    })?;

    // Verify ID token
    let claims = id_token
        .claims(
            &oidc.client.id_token_verifier(),
            &Nonce::new(pkce_state.nonce),
        )
        .map_err(|e| {
            (
                Status::InternalServerError,
                Json(AuthError {
                    error: "id_token_verification_failed".to_string(),
                    message: format!("Failed to verify ID token: {}", e),
                }),
            )
        })?;

    // Extract user info from claims
    let subject = claims.subject().to_string();
    let email = claims.email().map(|e| e.to_string()).unwrap_or_default();
    let username = claims
        .preferred_username()
        .map(|u| u.to_string())
        .unwrap_or_else(|| subject.clone());

    // Extract groups - need to get from userinfo endpoint or access token
    // For Authentik, groups are in the access token or userinfo
    let userinfo_endpoint = oidc.config.userinfo_endpoint.clone().unwrap_or_else(|| {
        // Derive from issuer URL if not explicitly configured
        format!("{}/userinfo", oidc.config.issuer_url.trim_end_matches('/'))
    });
    let groups = fetch_user_groups(&userinfo_endpoint, token_response.access_token())
        .await
        .unwrap_or_default();

    eprintln!("Groups: {:?}", &groups);

    // Check if user has required admin group
    if !groups.contains(&oidc.config.admin_group) {
        return Err((
            Status::Forbidden,
            Json(AuthError {
                error: "forbidden".to_string(),
                message: format!(
                    "Access denied. You must be a member of the '{}' group.",
                    oidc.config.admin_group
                ),
            }),
        ));
    }

    // Get refresh token
    let refresh_token = token_response
        .refresh_token()
        .map(|t| t.secret().clone())
        .unwrap_or_default();

    // Encrypt refresh token
    let encrypted_refresh = encrypt_refresh_token(&refresh_token, &oidc.config.session_secret);

    // Create session claims
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize;

    let session_claims = SessionClaims {
        sub: subject,
        username,
        email,
        groups,
        iat: now,
        exp: now + (oidc.config.session_duration_hours as usize * 3600),
        refresh_token: encrypted_refresh,
    };

    // Create session JWT
    let session_jwt =
        create_session_jwt(&session_claims, &oidc.config.session_secret).map_err(|e| {
            (
                Status::InternalServerError,
                Json(AuthError {
                    error: "session_creation_failed".to_string(),
                    message: e,
                }),
            )
        })?;

    // Set session cookie
    let session_cookie = Cookie::build((SESSION_COOKIE_NAME, session_jwt))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .max_age(rocket::time::Duration::hours(
            oidc.config.session_duration_hours as i64,
        ))
        .secure(!cfg!(debug_assertions));

    cookies.add(session_cookie);

    // Remove PKCE cookie
    cookies.remove(Cookie::from(PKCE_COOKIE_NAME));

    // Redirect to post-login URL
    let redirect_url = pkce_state
        .redirect_after_login
        .unwrap_or_else(|| oidc.config.post_login_redirect.clone());

    Ok(Redirect::to(redirect_url))
}

/// Fetch user groups from userinfo endpoint using raw HTTP request
/// This allows us to extract custom claims like "groups" that aren't in the standard OIDC library
async fn fetch_user_groups(
    userinfo_endpoint: &str,
    access_token: &openidconnect::AccessToken,
) -> Result<Vec<String>, String> {
    // Make raw HTTP request to get all claims including custom ones
    let http_client = reqwest::Client::new();
    let response = http_client
        .get(userinfo_endpoint)
        .bearer_auth(access_token.secret())
        .send()
        .await
        .map_err(|e| format!("Failed to fetch userinfo: {}", e))?;

    if !response.status().is_success() {
        return Err(format!(
            "Userinfo request failed with status: {}",
            response.status()
        ));
    }

    let json: serde_json::Value = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse userinfo JSON: {}", e))?;

    eprintln!("JSON response: {:?}", &json);

    // Extract groups from the JSON response
    // Authentik typically returns groups as an array of strings
    if let Some(groups) = json.get("groups") {
        if let Some(groups_array) = groups.as_array() {
            return Ok(groups_array
                .iter()
                .filter_map(|g| g.as_str().map(String::from))
                .collect());
        }
    }

    Ok(vec![])
}

/// POST /auth/logout - Clears session cookie
#[post("/logout")]
pub fn logout(oidc: &State<Arc<OidcClient>>, cookies: &CookieJar<'_>) -> Redirect {
    // Remove session cookie
    cookies.remove(Cookie::from(SESSION_COOKIE_NAME));

    Redirect::to(oidc.config.post_logout_redirect.clone())
}

/// POST /auth/refresh - Refresh session using OIDC refresh token
#[post("/refresh")]
pub async fn refresh(
    oidc: &State<Arc<OidcClient>>,
    cookies: &CookieJar<'_>,
) -> Result<Status, (Status, Json<AuthError>)> {
    // Get current session
    let session_cookie = cookies.get(SESSION_COOKIE_NAME).ok_or_else(|| {
        (
            Status::Unauthorized,
            Json(AuthError {
                error: "no_session".to_string(),
                message: "No session cookie found".to_string(),
            }),
        )
    })?;

    // Validate current session (allow expired for refresh)
    let mut validation = Validation::default();
    validation.validate_exp = false; // Allow expired tokens for refresh

    let claims = decode::<SessionClaims>(
        session_cookie.value(),
        &DecodingKey::from_secret(oidc.config.session_secret.as_bytes()),
        &validation,
    )
    .map_err(|e| {
        (
            Status::Unauthorized,
            Json(AuthError {
                error: "invalid_session".to_string(),
                message: format!("Invalid session: {}", e),
            }),
        )
    })?
    .claims;

    // Decrypt refresh token
    let refresh_token = decrypt_refresh_token(&claims.refresh_token, &oidc.config.session_secret)
        .map_err(|e| {
        (
            Status::Unauthorized,
            Json(AuthError {
                error: "invalid_refresh_token".to_string(),
                message: e,
            }),
        )
    })?;

    if refresh_token.is_empty() {
        return Err((
            Status::Unauthorized,
            Json(AuthError {
                error: "no_refresh_token".to_string(),
                message: "No refresh token available".to_string(),
            }),
        ));
    }

    // Exchange refresh token for new tokens
    let token_response = oidc
        .client
        .exchange_refresh_token(&RefreshToken::new(refresh_token))
        .request_async(async_http_client)
        .await
        .map_err(|e| {
            (
                Status::Unauthorized,
                Json(AuthError {
                    error: "refresh_failed".to_string(),
                    message: format!("Failed to refresh token: {}", e),
                }),
            )
        })?;

    // Get new refresh token (or keep old one)
    let new_refresh_token = token_response
        .refresh_token()
        .map(|t| t.secret().clone())
        .unwrap_or_else(|| {
            decrypt_refresh_token(&claims.refresh_token, &oidc.config.session_secret)
                .unwrap_or_default()
        });

    // Encrypt new refresh token
    let encrypted_refresh = encrypt_refresh_token(&new_refresh_token, &oidc.config.session_secret);

    // Create new session claims
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize;

    let new_claims = SessionClaims {
        sub: claims.sub,
        username: claims.username,
        email: claims.email,
        groups: claims.groups,
        iat: now,
        exp: now + (oidc.config.session_duration_hours as usize * 3600),
        refresh_token: encrypted_refresh,
    };

    // Create new session JWT
    let session_jwt =
        create_session_jwt(&new_claims, &oidc.config.session_secret).map_err(|e| {
            (
                Status::InternalServerError,
                Json(AuthError {
                    error: "session_creation_failed".to_string(),
                    message: e,
                }),
            )
        })?;

    // Set new session cookie
    let session_cookie = Cookie::build((SESSION_COOKIE_NAME, session_jwt))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .max_age(rocket::time::Duration::hours(
            oidc.config.session_duration_hours as i64,
        ))
        .secure(!cfg!(debug_assertions));

    cookies.add(session_cookie);

    Ok(Status::Ok)
}

/// GET /auth/userinfo - Returns current user info from session
#[get("/userinfo")]
pub fn userinfo(
    oidc: &State<Arc<OidcClient>>,
    cookies: &CookieJar<'_>,
) -> Result<Json<UserInfo>, (Status, Json<AuthError>)> {
    // Debug mode: return fake user
    if cfg!(debug_assertions) {
        return Ok(Json(UserInfo {
            username: "AdminBot".to_string(),
            email: "admin@debug.local".to_string(),
            groups: vec!["admin".to_string()],
        }));
    }

    // Get session cookie
    let session_cookie = cookies.get(SESSION_COOKIE_NAME).ok_or_else(|| {
        (
            Status::Unauthorized,
            Json(AuthError {
                error: "no_session".to_string(),
                message: "No session cookie found".to_string(),
            }),
        )
    })?;

    // Validate session JWT
    let claims = validate_session_jwt(session_cookie.value(), &oidc.config.session_secret)
        .map_err(|e| {
            (
                Status::Unauthorized,
                Json(AuthError {
                    error: "invalid_session".to_string(),
                    message: e,
                }),
            )
        })?;

    Ok(Json(UserInfo {
        username: claims.username,
        email: claims.email,
        groups: claims.groups,
    }))
}
