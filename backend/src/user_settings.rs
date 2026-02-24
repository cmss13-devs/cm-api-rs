//! User settings management for sessions, consents, and MFA devices

use rocket::{http::Status, serde::json::Json, State};
use serde::{Deserialize, Serialize};

use crate::{
    admin::{AuthenticatedUser, Player},
    authentik::{get_user_by_uuid, AuthentikConfig, AuthentikError, AuthentikSuccess},
    Config,
};

// ============================================================================
// Types for Authentik API responses
// ============================================================================

/// User session from Authentik
#[derive(Debug, Deserialize, Clone)]
pub struct AuthentikSession {
    pub uuid: String,
    pub current: bool,
    pub user_agent: UserAgentInfo,
    pub last_ip: String,
    pub last_used: String,
    pub expires: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct UserAgentInfo {
    pub device: DeviceInfo,
    pub os: OsInfo,
    /// Browser info - named "user_agent" in Authentik's nested response
    #[serde(rename = "user_agent")]
    pub browser: BrowserInfo,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DeviceInfo {
    #[allow(dead_code)]
    pub brand: Option<String>,
    pub family: String,
    #[allow(dead_code)]
    pub model: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct OsInfo {
    pub family: String,
    /// OS version is split into major/minor/patch in Authentik
    pub major: Option<String>,
    #[allow(dead_code)]
    pub minor: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct BrowserInfo {
    pub family: String,
    /// Browser version is split into major/minor/patch in Authentik
    pub major: Option<String>,
    #[allow(dead_code)]
    pub minor: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AuthentikSessionsResponse {
    pub results: Vec<AuthentikSession>,
}

/// Session info for frontend
#[derive(Debug, Serialize)]
#[serde(crate = "rocket::serde", rename_all = "camelCase")]
pub struct SessionInfo {
    pub uuid: String,
    pub current: bool,
    pub device: String,
    pub browser: String,
    pub os: String,
    pub last_ip: String,
    pub last_used: String,
    pub expires: Option<String>,
}

/// Application consent from Authentik
#[derive(Debug, Deserialize, Clone)]
pub struct AuthentikConsent {
    pub pk: i64,
    pub expires: Option<String>,
    pub application: ConsentApplication,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ConsentApplication {
    #[allow(dead_code)]
    pub pk: String,
    pub name: String,
    pub slug: String,
    pub meta_launch_url: Option<String>,
    pub meta_icon: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AuthentikConsentsResponse {
    pub results: Vec<AuthentikConsent>,
}

/// Consent info for frontend
#[derive(Debug, Serialize)]
#[serde(crate = "rocket::serde", rename_all = "camelCase")]
pub struct ConsentInfo {
    pub pk: i64,
    pub application_name: String,
    pub application_slug: String,
    pub application_icon: Option<String>,
    pub application_url: Option<String>,
    pub expires: Option<String>,
}

/// MFA device types
#[derive(Debug, Deserialize, Clone)]
pub struct TotpDevice {
    pub pk: i64,
    pub name: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct WebAuthnDevice {
    pub pk: i64,
    pub name: String,
    pub created_on: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct StaticDevice {
    pub pk: i64,
    pub name: String,
    pub token_count: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct TotpDevicesResponse {
    pub results: Vec<TotpDevice>,
}

#[derive(Debug, Deserialize)]
struct WebAuthnDevicesResponse {
    pub results: Vec<WebAuthnDevice>,
}

#[derive(Debug, Deserialize)]
struct StaticDevicesResponse {
    pub results: Vec<StaticDevice>,
}

/// MFA device info for frontend
#[derive(Debug, Serialize)]
#[serde(crate = "rocket::serde", rename_all = "camelCase")]
pub struct MfaDeviceInfo {
    pub pk: i64,
    pub name: String,
    pub device_type: String,
    pub created_on: Option<String>,
    pub token_count: Option<i64>,
}

/// Full user settings response
#[derive(Debug, Serialize)]
#[serde(crate = "rocket::serde", rename_all = "camelCase")]
pub struct UserSettingsResponse {
    pub sessions: Vec<SessionInfo>,
    pub consents: Vec<ConsentInfo>,
    pub mfa_devices: Vec<MfaDeviceInfo>,
}

// ============================================================================
// Helper functions for Authentik API
// ============================================================================

/// Get user sessions from Authentik
async fn get_user_sessions(
    client: &reqwest::Client,
    config: &AuthentikConfig,
    user_pk: i64,
) -> Result<Vec<AuthentikSession>, String> {
    let url = format!(
        "{}/api/v3/core/authenticated_sessions/?user={}",
        config.base_url.trim_end_matches('/'),
        user_pk
    );

    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", config.token))
        .send()
        .await
        .map_err(|e| format!("Failed to query Authentik API: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("Authentik API returned error {}: {}", status, body));
    }

    let sessions_response: AuthentikSessionsResponse = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse Authentik response: {}", e))?;

    Ok(sessions_response.results)
}

/// Delete a user session
async fn delete_session(
    client: &reqwest::Client,
    config: &AuthentikConfig,
    session_uuid: &str,
) -> Result<(), String> {
    let url = format!(
        "{}/api/v3/core/authenticated_sessions/{}/",
        config.base_url.trim_end_matches('/'),
        session_uuid
    );

    let response = client
        .delete(&url)
        .header("Authorization", format!("Bearer {}", config.token))
        .send()
        .await
        .map_err(|e| format!("Failed to delete session: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!(
            "Failed to delete session (status {}): {}",
            status, body
        ));
    }

    Ok(())
}

/// Get user consents from Authentik
async fn get_user_consents(
    client: &reqwest::Client,
    config: &AuthentikConfig,
    user_pk: i64,
) -> Result<Vec<AuthentikConsent>, String> {
    let url = format!(
        "{}/api/v3/core/user_consent/?user={}",
        config.base_url.trim_end_matches('/'),
        user_pk
    );

    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", config.token))
        .send()
        .await
        .map_err(|e| format!("Failed to query Authentik API: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("Authentik API returned error {}: {}", status, body));
    }

    let consents_response: AuthentikConsentsResponse = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse Authentik response: {}", e))?;

    Ok(consents_response.results)
}

/// Revoke a user consent
async fn revoke_consent(
    client: &reqwest::Client,
    config: &AuthentikConfig,
    consent_pk: i64,
) -> Result<(), String> {
    let url = format!(
        "{}/api/v3/core/user_consent/{}/",
        config.base_url.trim_end_matches('/'),
        consent_pk
    );

    let response = client
        .delete(&url)
        .header("Authorization", format!("Bearer {}", config.token))
        .send()
        .await
        .map_err(|e| format!("Failed to revoke consent: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!(
            "Failed to revoke consent (status {}): {}",
            status, body
        ));
    }

    Ok(())
}

/// Get user MFA devices from Authentik (TOTP, WebAuthn, Static)
async fn get_user_mfa_devices(
    client: &reqwest::Client,
    config: &AuthentikConfig,
    user_pk: i64,
) -> Result<Vec<MfaDeviceInfo>, String> {
    let base_url = config.base_url.trim_end_matches('/');
    let auth_header = format!("Bearer {}", config.token);

    // Fetch all device types in parallel
    let (totp_result, webauthn_result, static_result) = tokio::join!(
        client
            .get(format!(
                "{}/api/v3/authenticators/totp/?user={}",
                base_url, user_pk
            ))
            .header("Authorization", &auth_header)
            .send(),
        client
            .get(format!(
                "{}/api/v3/authenticators/webauthn/?user={}",
                base_url, user_pk
            ))
            .header("Authorization", &auth_header)
            .send(),
        client
            .get(format!(
                "{}/api/v3/authenticators/static/?user={}",
                base_url, user_pk
            ))
            .header("Authorization", &auth_header)
            .send()
    );

    let mut devices = Vec::new();

    // Parse TOTP devices
    if let Ok(response) = totp_result {
        if response.status().is_success() {
            if let Ok(totp_response) = response.json::<TotpDevicesResponse>().await {
                for device in totp_response.results {
                    devices.push(MfaDeviceInfo {
                        pk: device.pk,
                        name: device.name,
                        device_type: "totp".to_string(),
                        created_on: None,
                        token_count: None,
                    });
                }
            }
        }
    }

    // Parse WebAuthn devices
    if let Ok(response) = webauthn_result {
        if response.status().is_success() {
            if let Ok(webauthn_response) = response.json::<WebAuthnDevicesResponse>().await {
                for device in webauthn_response.results {
                    devices.push(MfaDeviceInfo {
                        pk: device.pk,
                        name: device.name,
                        device_type: "webauthn".to_string(),
                        created_on: Some(device.created_on),
                        token_count: None,
                    });
                }
            }
        }
    }

    // Parse Static (backup codes) devices
    if let Ok(response) = static_result {
        if response.status().is_success() {
            if let Ok(static_response) = response.json::<StaticDevicesResponse>().await {
                for device in static_response.results {
                    devices.push(MfaDeviceInfo {
                        pk: device.pk,
                        name: device.name,
                        device_type: "static".to_string(),
                        created_on: None,
                        token_count: device.token_count,
                    });
                }
            }
        }
    }

    Ok(devices)
}

/// Delete an MFA device
async fn delete_mfa_device(
    client: &reqwest::Client,
    config: &AuthentikConfig,
    device_type: &str,
    device_pk: i64,
) -> Result<(), String> {
    let endpoint = match device_type {
        "totp" => "authenticators/totp",
        "webauthn" => "authenticators/webauthn",
        "static" => "authenticators/static",
        _ => return Err(format!("Unknown device type: {}", device_type)),
    };

    let url = format!(
        "{}/api/v3/{}/{}/",
        config.base_url.trim_end_matches('/'),
        endpoint,
        device_pk
    );

    let response = client
        .delete(&url)
        .header("Authorization", format!("Bearer {}", config.token))
        .send()
        .await
        .map_err(|e| format!("Failed to delete MFA device: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!(
            "Failed to delete MFA device (status {}): {}",
            status, body
        ));
    }

    Ok(())
}

// ============================================================================
// Endpoint handlers
// ============================================================================

/// GET /Authentik/MySettings - get user sessions, consents, and MFA devices
#[get("/MySettings")]
pub async fn get_my_settings(
    user: AuthenticatedUser<Player>,
    config: &State<Config>,
) -> Result<Json<UserSettingsResponse>, (Status, Json<AuthentikError>)> {
    let authentik_config = config.authentik.as_ref().ok_or_else(|| {
        (
            Status::InternalServerError,
            Json(AuthentikError {
                error: "not_configured".to_string(),
                message: "Authentik is not configured".to_string(),
            }),
        )
    })?;

    let http_client = reqwest::Client::new();

    let authentik_user = get_user_by_uuid(&http_client, authentik_config, &user.sub)
        .await
        .map_err(|e| {
            (
                Status::NotFound,
                Json(AuthentikError {
                    error: "user_not_found".to_string(),
                    message: e,
                }),
            )
        })?;

    // Fetch sessions, consents, and MFA devices in parallel
    let (sessions_result, consents_result, mfa_result) = tokio::join!(
        get_user_sessions(&http_client, authentik_config, authentik_user.pk),
        get_user_consents(&http_client, authentik_config, authentik_user.pk),
        get_user_mfa_devices(&http_client, authentik_config, authentik_user.pk)
    );

    let sessions = sessions_result
        .map_err(|e| {
            (
                Status::InternalServerError,
                Json(AuthentikError {
                    error: "fetch_sessions_failed".to_string(),
                    message: e,
                }),
            )
        })?
        .into_iter()
        .map(|s| SessionInfo {
            uuid: s.uuid,
            current: s.current,
            device: s.user_agent.device.family,
            browser: format!(
                "{} {}",
                s.user_agent.browser.family,
                s.user_agent.browser.major.as_deref().unwrap_or_default()
            ),
            os: format!(
                "{} {}",
                s.user_agent.os.family,
                s.user_agent.os.major.as_deref().unwrap_or_default()
            ),
            last_ip: s.last_ip,
            last_used: s.last_used,
            expires: s.expires,
        })
        .collect();

    let consents = consents_result
        .map_err(|e| {
            (
                Status::InternalServerError,
                Json(AuthentikError {
                    error: "fetch_consents_failed".to_string(),
                    message: e,
                }),
            )
        })?
        .into_iter()
        .map(|c| ConsentInfo {
            pk: c.pk,
            application_name: c.application.name,
            application_slug: c.application.slug,
            application_icon: c.application.meta_icon,
            application_url: c.application.meta_launch_url,
            expires: c.expires,
        })
        .collect();

    let mfa_devices = mfa_result.map_err(|e| {
        (
            Status::InternalServerError,
            Json(AuthentikError {
                error: "fetch_mfa_failed".to_string(),
                message: e,
            }),
        )
    })?;

    Ok(Json(UserSettingsResponse {
        sessions,
        consents,
        mfa_devices,
    }))
}

/// DELETE /Authentik/MySettings/Session/<uuid> - delete a session
#[delete("/MySettings/Session/<session_uuid>")]
pub async fn delete_my_session(
    user: AuthenticatedUser<Player>,
    config: &State<Config>,
    session_uuid: String,
) -> Result<Json<AuthentikSuccess>, (Status, Json<AuthentikError>)> {
    let authentik_config = config.authentik.as_ref().ok_or_else(|| {
        (
            Status::InternalServerError,
            Json(AuthentikError {
                error: "not_configured".to_string(),
                message: "Authentik is not configured".to_string(),
            }),
        )
    })?;

    let http_client = reqwest::Client::new();

    // Verify the session belongs to this user
    let authentik_user = get_user_by_uuid(&http_client, authentik_config, &user.sub)
        .await
        .map_err(|e| {
            (
                Status::NotFound,
                Json(AuthentikError {
                    error: "user_not_found".to_string(),
                    message: e,
                }),
            )
        })?;

    let sessions = get_user_sessions(&http_client, authentik_config, authentik_user.pk)
        .await
        .map_err(|e| {
            (
                Status::InternalServerError,
                Json(AuthentikError {
                    error: "fetch_sessions_failed".to_string(),
                    message: e,
                }),
            )
        })?;

    if !sessions.iter().any(|s| s.uuid == session_uuid) {
        return Err((
            Status::Forbidden,
            Json(AuthentikError {
                error: "not_your_session".to_string(),
                message: "This session does not belong to you".to_string(),
            }),
        ));
    }

    delete_session(&http_client, authentik_config, &session_uuid)
        .await
        .map_err(|e| {
            (
                Status::InternalServerError,
                Json(AuthentikError {
                    error: "delete_failed".to_string(),
                    message: e,
                }),
            )
        })?;

    Ok(Json(AuthentikSuccess {
        message: "Session deleted".to_string(),
    }))
}

/// DELETE /Authentik/MySettings/Consent/<pk> - revoke an application consent
#[delete("/MySettings/Consent/<consent_pk>")]
pub async fn revoke_my_consent(
    user: AuthenticatedUser<Player>,
    config: &State<Config>,
    consent_pk: i64,
) -> Result<Json<AuthentikSuccess>, (Status, Json<AuthentikError>)> {
    let authentik_config = config.authentik.as_ref().ok_or_else(|| {
        (
            Status::InternalServerError,
            Json(AuthentikError {
                error: "not_configured".to_string(),
                message: "Authentik is not configured".to_string(),
            }),
        )
    })?;

    let http_client = reqwest::Client::new();

    // Verify the consent belongs to this user
    let authentik_user = get_user_by_uuid(&http_client, authentik_config, &user.sub)
        .await
        .map_err(|e| {
            (
                Status::NotFound,
                Json(AuthentikError {
                    error: "user_not_found".to_string(),
                    message: e,
                }),
            )
        })?;

    let consents = get_user_consents(&http_client, authentik_config, authentik_user.pk)
        .await
        .map_err(|e| {
            (
                Status::InternalServerError,
                Json(AuthentikError {
                    error: "fetch_consents_failed".to_string(),
                    message: e,
                }),
            )
        })?;

    let consent = consents.iter().find(|c| c.pk == consent_pk).ok_or_else(|| {
        (
            Status::Forbidden,
            Json(AuthentikError {
                error: "not_your_consent".to_string(),
                message: "This consent does not belong to you".to_string(),
            }),
        )
    })?;

    let app_name = consent.application.name.clone();

    revoke_consent(&http_client, authentik_config, consent_pk)
        .await
        .map_err(|e| {
            (
                Status::InternalServerError,
                Json(AuthentikError {
                    error: "revoke_failed".to_string(),
                    message: e,
                }),
            )
        })?;

    Ok(Json(AuthentikSuccess {
        message: format!("Revoked consent for {}", app_name),
    }))
}

/// DELETE /Authentik/MySettings/MfaDevice/<type>/<pk> - delete an MFA device
#[delete("/MySettings/MfaDevice/<device_type>/<device_pk>")]
pub async fn delete_my_mfa_device(
    user: AuthenticatedUser<Player>,
    config: &State<Config>,
    device_type: String,
    device_pk: i64,
) -> Result<Json<AuthentikSuccess>, (Status, Json<AuthentikError>)> {
    let authentik_config = config.authentik.as_ref().ok_or_else(|| {
        (
            Status::InternalServerError,
            Json(AuthentikError {
                error: "not_configured".to_string(),
                message: "Authentik is not configured".to_string(),
            }),
        )
    })?;

    let http_client = reqwest::Client::new();

    // Verify the device belongs to this user
    let authentik_user = get_user_by_uuid(&http_client, authentik_config, &user.sub)
        .await
        .map_err(|e| {
            (
                Status::NotFound,
                Json(AuthentikError {
                    error: "user_not_found".to_string(),
                    message: e,
                }),
            )
        })?;

    let devices = get_user_mfa_devices(&http_client, authentik_config, authentik_user.pk)
        .await
        .map_err(|e| {
            (
                Status::InternalServerError,
                Json(AuthentikError {
                    error: "fetch_devices_failed".to_string(),
                    message: e,
                }),
            )
        })?;

    let device = devices
        .iter()
        .find(|d| d.pk == device_pk && d.device_type == device_type)
        .ok_or_else(|| {
            (
                Status::Forbidden,
                Json(AuthentikError {
                    error: "not_your_device".to_string(),
                    message: "This device does not belong to you".to_string(),
                }),
            )
        })?;

    let device_name = device.name.clone();

    delete_mfa_device(&http_client, authentik_config, &device_type, device_pk)
        .await
        .map_err(|e| {
            (
                Status::InternalServerError,
                Json(AuthentikError {
                    error: "delete_failed".to_string(),
                    message: e,
                }),
            )
        })?;

    Ok(Json(AuthentikSuccess {
        message: format!("Deleted MFA device: {}", device_name),
    }))
}
