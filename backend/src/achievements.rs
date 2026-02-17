use std::collections::HashMap;

use rocket::{State, http::Status, serde::json::Json};
use serde::{Deserialize, Serialize};

use crate::{
    Config,
    authentik::{AuthentikConfig, AuthentikError, get_user_by_attribute},
    player::{AuthorizationHeader, validate_auth_header},
    steam::SteamConfig,
    utils::normalize_uuid,
};

#[derive(Debug, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct AchievementsResponse {
    pub achievements: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct SetAchievementRequest {
    pub ckey: String,
    pub achievement: String,
    /// Steam app instance to use (e.g., "default", "playtest"). Defaults to "default".
    #[serde(default = "default_instance")]
    pub instance: String,
}

fn default_instance() -> String {
    "default".to_string()
}

#[derive(Debug, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct SetAchievementResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SteamAchievementsResponse {
    playerstats: SteamPlayerStats,
}

#[derive(Debug, Deserialize)]
struct SteamPlayerStats {
    #[serde(rename = "steamID")]
    #[allow(dead_code)]
    steam_id: String,
    #[serde(rename = "gameName")]
    #[allow(dead_code)]
    game_name: Option<String>,
    #[serde(default)]
    achievements: HashMap<String, SteamAchievement>,
    #[serde(default)]
    result: Option<i32>,
    #[serde(default)]
    #[allow(dead_code)]
    success: bool,
    #[serde(default)]
    error: Option<String>,
}

impl SteamPlayerStats {
    fn is_success(&self) -> bool {
        if self.error.is_some() {
            return false;
        }
        if let Some(result) = self.result {
            return result == 1;
        }
        true
    }
}

#[derive(Debug, Deserialize)]
struct SteamAchievement {
    achieved: i32,
}

#[derive(Debug, Deserialize)]
struct SteamSetAchievementResponse {
    response: SteamSetAchievementInner,
}

#[derive(Debug, Deserialize)]
struct SteamSetAchievementInner {
    result: i32,
    #[serde(default)]
    error: Option<SteamSetAchievementError>,
}

#[derive(Debug, Deserialize)]
struct SteamSetAchievementError {
    #[serde(rename = "errorcode")]
    #[allow(dead_code)]
    error_code: i32,
    #[serde(rename = "errordesc")]
    error_desc: String,
}

/// Fetches achievements from Steam Partner API for a given steam_id
/// Uses the Publisher API which works regardless of user privacy settings
async fn get_steam_achievements(
    client: &reqwest::Client,
    config: &SteamConfig,
    steam_id: &str,
    instance: &str,
) -> Result<HashMap<String, SteamAchievement>, String> {
    let app_id = config
        .app_id
        .get(instance)
        .or_else(|| config.app_id.values().next())
        .ok_or_else(|| "No app_id configured for Steam".to_string())?;

    let url = format!(
        "https://partner.steam-api.com/ISteamUserStats/GetUserStatsForGame/v1/?key={}&steamid={}&appid={}",
        config.web_api_key, steam_id, app_id
    );

    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("Failed to contact Steam Partner API: {}", e))?;

    let status = response.status();
    let body = response.text().await.unwrap_or_default();

    if !status.is_success() {
        return Err(format!(
            "Steam Partner API returned error {}: {}",
            status, body
        ));
    }

    let achievements_response: SteamAchievementsResponse = serde_json::from_str(&body)
        .map_err(|e| format!("Failed to parse Steam Partner API response: {} - Body: {}", e, body))?;

    if !achievements_response.playerstats.is_success() {
        if let Some(error) = achievements_response.playerstats.error {
            return Err(format!("Steam Partner API error: {}", error));
        }
        return Err("Steam Partner API returned unsuccessful response".to_string());
    }

    Ok(achievements_response.playerstats.achievements)
}

/// Sets an achievement on Steam using the Publisher Web API
async fn set_steam_achievement(
    client: &reqwest::Client,
    config: &SteamConfig,
    steam_id: &str,
    achievement_name: &str,
    instance: &str,
) -> Result<(), String> {
    let app_id = config
        .app_id
        .get(instance)
        .or_else(|| config.app_id.values().next())
        .ok_or_else(|| "No app_id configured for Steam".to_string())?;

    // Use the SetUserStatsForGame endpoint (Publisher API)
    let url = "https://partner.steam-api.com/ISteamUserStats/SetUserStatsForGame/v1/";

    let params = [
        ("key", config.web_api_key.as_str()),
        ("steamid", steam_id),
        ("appid", &app_id.to_string()),
        ("count", "1"),
        ("name[0]", achievement_name),
        ("value[0]", "1"),
    ];

    let response = client
        .post(url)
        .form(&params)
        .send()
        .await
        .map_err(|e| format!("Failed to contact Steam Partner API: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!(
            "Steam Partner API returned error {}: {}",
            status, body
        ));
    }

    let set_response: SteamSetAchievementResponse = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse Steam Partner API response: {}", e))?;

    if set_response.response.result != 1 {
        if let Some(error) = set_response.response.error {
            return Err(format!("Steam Partner API error: {}", error.error_desc));
        }
        return Err(format!(
            "Steam Partner API returned result code: {}",
            set_response.response.result
        ));
    }

    Ok(())
}

/// Looks up steam_id from Authentik for a given ckey.
/// Tries to find user by ckey attribute first, then falls back to uuid field.
async fn get_steam_id_for_ckey(
    client: &reqwest::Client,
    authentik_config: &AuthentikConfig,
    ckey: &str,
) -> Result<Option<String>, String> {
    // First try to find by ckey attribute
    let user = match get_user_by_attribute(client, authentik_config, "ckey", ckey).await {
        Ok(user) => Some(user),
        Err(_) => {
            // Fall back to searching by uuid
            get_user_by_uuid(client, authentik_config, ckey).await.ok()
        }
    };

    let Some(user) = user else {
        return Ok(None);
    };

    // Extract steam_id from user attributes
    let steam_id = user
        .attributes
        .get("steam_id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    Ok(steam_id)
}

/// Finds an Authentik user by their uuid field
async fn get_user_by_uuid(
    client: &reqwest::Client,
    config: &AuthentikConfig,
    uuid: &str,
) -> Result<crate::authentik::AuthentikUser, String> {
    let uuid = normalize_uuid(uuid).ok_or_else(|| format!("Invalid UUID format: '{}'", uuid))?;
    let url = format!(
        "{}/api/v3/core/users/?uuid={}",
        config.base_url.trim_end_matches('/'),
        uuid
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

    let search_response: crate::authentik::AuthentikUserSearchResponse = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse Authentik response: {}", e))?;

    if search_response.results.is_empty() {
        return Err(format!("No user found with uuid '{}'", uuid));
    }

    Ok(search_response.results.into_iter().next().unwrap())
}

/// GET /Achievements?ckey=<ckey>&instance=<instance> - Get uncompleted achievements for a player
///
/// Returns list of uncompleted achievement keys.
/// Requires Bearer token authorization.
/// `instance` parameter selects which Steam app to query (e.g., "default", "playtest"). Defaults to "default".
#[get("/?<ckey>&<instance>")]
pub async fn get_achievements(
    auth_header: AuthorizationHeader,
    config: &State<Config>,
    ckey: &str,
    instance: Option<&str>,
) -> Result<Json<AchievementsResponse>, (Status, Json<AuthentikError>)> {
    let instance = instance.unwrap_or("default");
    // Validate auth token
    if !validate_auth_header(Some(&auth_header.0), config) {
        return Err((
            Status::Unauthorized,
            Json(AuthentikError {
                error: "unauthorized".to_string(),
                message: "Invalid or missing authorization token".to_string(),
            }),
        ));
    }

    let authentik_config = config.authentik.as_ref().ok_or_else(|| {
        (
            Status::InternalServerError,
            Json(AuthentikError {
                error: "not_configured".to_string(),
                message: "Authentik is not configured".to_string(),
            }),
        )
    })?;

    let steam_config = config.steam.as_ref().ok_or_else(|| {
        (
            Status::InternalServerError,
            Json(AuthentikError {
                error: "not_configured".to_string(),
                message: "Steam is not configured".to_string(),
            }),
        )
    })?;

    let http_client = reqwest::Client::new();

    // Look up steam_id from Authentik
    let steam_id = get_steam_id_for_ckey(&http_client, authentik_config, ckey)
        .await
        .map_err(|e| {
            (
                Status::InternalServerError,
                Json(AuthentikError {
                    error: "lookup_failed".to_string(),
                    message: e,
                }),
            )
        })?;

    let Some(steam_id) = steam_id else {
        // No steam_id linked, return empty list
        return Ok(Json(AchievementsResponse {
            achievements: Vec::new(),
        }));
    };

    // Get achievements from Steam
    let achievements = get_steam_achievements(&http_client, steam_config, &steam_id, instance)
        .await
        .map_err(|e| {
            (
                Status::FailedDependency,
                Json(AuthentikError {
                    error: "steam_api_error".to_string(),
                    message: e,
                }),
            )
        })?;

    // Return earned achievements
    let earned: Vec<String> = achievements
        .into_iter()
        .filter(|(_, a)| a.achieved == 1)
        .map(|(name, _)| name)
        .collect();

    Ok(Json(AchievementsResponse {
        achievements: earned,
    }))
}

/// POST /Achievements - Mark an achievement as completed for a player
///
/// Expects JSON body with ckey and achievement key.
/// Requires Bearer token authorization.
#[post("/", format = "json", data = "<request>")]
pub async fn set_achievement(
    auth_header: AuthorizationHeader,
    config: &State<Config>,
    request: Json<SetAchievementRequest>,
) -> Result<Json<SetAchievementResponse>, (Status, Json<AuthentikError>)> {
    // Validate auth token
    if !validate_auth_header(Some(&auth_header.0), config) {
        return Err((
            Status::Unauthorized,
            Json(AuthentikError {
                error: "unauthorized".to_string(),
                message: "Invalid or missing authorization token".to_string(),
            }),
        ));
    }

    let authentik_config = config.authentik.as_ref().ok_or_else(|| {
        (
            Status::InternalServerError,
            Json(AuthentikError {
                error: "not_configured".to_string(),
                message: "Authentik is not configured".to_string(),
            }),
        )
    })?;

    let steam_config = config.steam.as_ref().ok_or_else(|| {
        (
            Status::InternalServerError,
            Json(AuthentikError {
                error: "not_configured".to_string(),
                message: "Steam is not configured".to_string(),
            }),
        )
    })?;

    let http_client = reqwest::Client::new();

    // Look up steam_id from Authentik
    let steam_id = get_steam_id_for_ckey(&http_client, authentik_config, &request.ckey)
        .await
        .map_err(|e| {
            (
                Status::InternalServerError,
                Json(AuthentikError {
                    error: "lookup_failed".to_string(),
                    message: e,
                }),
            )
        })?;

    let Some(steam_id) = steam_id else {
        // No steam_id linked, can't set achievement
        return Ok(Json(SetAchievementResponse {
            success: false,
            error: Some("No Steam account linked to this ckey".to_string()),
        }));
    };

    // Set achievement on Steam
    if let Err(e) = set_steam_achievement(
        &http_client,
        steam_config,
        &steam_id,
        &request.achievement,
        &request.instance,
    )
    .await
    {
        return Ok(Json(SetAchievementResponse {
            success: false,
            error: Some(e),
        }));
    }

    Ok(Json(SetAchievementResponse {
        success: true,
        error: None,
    }))
}
