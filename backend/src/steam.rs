use std::collections::HashMap;

use rocket::{State, http::Status, serde::json::Json};
use rocket_db_pools::Connection;
use serde::{Deserialize, Serialize};

use crate::{
    Cmapi, Config,
    admin::{AuthenticatedUser, Player},
    authentik::{
        AuthentikError, create_user_with_steam_id, get_user_by_attribute, get_user_by_uuid,
        get_user_oauth_sources, parse_steam_id,
    },
    token::create_token,
};

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SteamConfig {
    pub web_api_key: String,
    pub app_id: HashMap<String, u32>,
    pub linking_url: String,
}

#[derive(Debug, Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct SteamAuthRequest {
    pub ticket: String,
    pub steam_id: String,
    pub display_name: String,
    #[serde(default)]
    pub create_account_if_missing: bool,
    pub instance: String,
}

#[derive(Debug, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct SteamAuthResponse {
    pub success: bool,
    pub user_exists: bool,
    pub access_token: Option<String>,
    pub requires_linking: bool,
    pub linking_url: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SteamTicketResponse {
    response: SteamTicketResponseInner,
}

#[derive(Debug, Deserialize)]
struct SteamTicketResponseInner {
    params: Option<SteamTicketParams>,
    error: Option<SteamTicketError>,
}

#[derive(Debug, Deserialize)]
struct SteamTicketParams {
    result: String,
    #[serde(rename = "steamid")]
    steam_id: String,
    #[serde(rename = "ownersteamid")]
    #[allow(dead_code)]
    owner_steam_id: String,
    #[serde(rename = "vacbanned")]
    vac_banned: bool,
    #[serde(rename = "publisherbanned")]
    publisher_banned: bool,
}

#[derive(Debug, Deserialize)]
struct SteamTicketError {
    #[serde(rename = "errorcode")]
    error_code: i32,
    #[serde(rename = "errordesc")]
    error_desc: String,
}

/// Validates a Steam session ticket via the Steam Web API
async fn validate_steam_ticket(
    client: &reqwest::Client,
    config: &SteamConfig,
    app_to_use: &str,
    ticket: &str,
    expected_steam_id: &str,
) -> Result<SteamTicketParams, String> {
    let Some(id_to_use) = config.app_id.get(app_to_use) else {
        return Err("Incorrect App ID request.".to_string());
    };

    let url = format!(
        "https://api.steampowered.com/ISteamUserAuth/AuthenticateUserTicket/v1/?key={}&appid={}&ticket={}",
        config.web_api_key, id_to_use, ticket
    );

    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("Failed to contact Steam API: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("Steam API returned error {}: {}", status, body));
    }

    let ticket_response: SteamTicketResponse = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse Steam API response: {}", e))?;

    if let Some(error) = ticket_response.response.error {
        return Err(format!(
            "Steam ticket validation failed ({}): {}",
            error.error_code, error.error_desc
        ));
    }

    let params = ticket_response
        .response
        .params
        .ok_or_else(|| "Steam API returned no params".to_string())?;

    if params.result != "OK" {
        return Err(format!("Steam ticket validation failed: {}", params.result));
    }

    // Verify the Steam ID matches what the client claimed
    if params.steam_id != expected_steam_id {
        return Err(format!(
            "Steam ID mismatch: expected {}, got {}",
            expected_steam_id, params.steam_id
        ));
    }

    // Check for bans
    if params.vac_banned {
        return Err("User is VAC banned".to_string());
    }

    if params.publisher_banned {
        return Err("User is publisher banned".to_string());
    }

    Ok(params)
}

/// POST /Steam/Authenticate - Authenticate a user via Steam
#[post("/Authenticate", format = "json", data = "<request>")]
pub async fn authenticate(
    config: &State<Config>,
    mut db: Connection<Cmapi>,
    request: Json<SteamAuthRequest>,
) -> Result<Json<SteamAuthResponse>, (Status, Json<AuthentikError>)> {
    let steam_config = config.steam.as_ref().ok_or_else(|| {
        (
            Status::InternalServerError,
            Json(AuthentikError {
                error: "not_configured".to_string(),
                message: "Steam authentication is not configured".to_string(),
            }),
        )
    })?;

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

    // Validate the Steam ticket
    let _ticket_params = validate_steam_ticket(
        &http_client,
        steam_config,
        &request.instance,
        &request.ticket,
        &request.steam_id,
    )
    .await
    .map_err(|e| {
        (
            Status::Unauthorized,
            Json(AuthentikError {
                error: "ticket_validation_failed".to_string(),
                message: e,
            }),
        )
    })?;

    // Look up user by steam_id attribute in Authentik
    let user_result = get_user_by_attribute(
        &http_client,
        authentik_config,
        "steam_id",
        &request.steam_id,
    )
    .await;

    match user_result {
        Ok(_user) => {
            // User exists, generate access token using cm-api database
            let token = create_token(&mut db, &request.steam_id)
                .await
                .map_err(|e| {
                    (
                        Status::InternalServerError,
                        Json(AuthentikError {
                            error: "token_generation_failed".to_string(),
                            message: e,
                        }),
                    )
                })?;

            Ok(Json(SteamAuthResponse {
                success: true,
                user_exists: true,
                access_token: Some(token),
                requires_linking: false,
                linking_url: None,
                error: None,
            }))
        }
        Err(_) => {
            // User not found
            if request.create_account_if_missing {
                // Create new user with Steam persona name as username
                let _user = create_user_with_steam_id(
                    &http_client,
                    authentik_config,
                    &request.display_name,
                    &request.steam_id,
                )
                .await
                .map_err(|e| {
                    (
                        Status::InternalServerError,
                        Json(AuthentikError {
                            error: "user_creation_failed".to_string(),
                            message: e,
                        }),
                    )
                })?;

                // Generate token for new user using cm-api database
                let token = create_token(&mut db, &request.steam_id)
                    .await
                    .map_err(|e| {
                        (
                            Status::InternalServerError,
                            Json(AuthentikError {
                                error: "token_generation_failed".to_string(),
                                message: e,
                            }),
                        )
                    })?;

                Ok(Json(SteamAuthResponse {
                    success: true,
                    user_exists: true,
                    access_token: Some(token),
                    requires_linking: false,
                    linking_url: None,
                    error: None,
                }))
            } else {
                // User needs to link or create account
                Ok(Json(SteamAuthResponse {
                    success: false,
                    user_exists: false,
                    access_token: None,
                    requires_linking: true,
                    linking_url: Some(steam_config.linking_url.clone()),
                    error: None,
                }))
            }
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(crate = "rocket::serde", rename_all = "camelCase")]
pub struct SteamPersonaResponse {
    pub persona_name: String,
    pub steam_id: String,
}

#[derive(Debug, Deserialize)]
struct GetPlayerSummariesResponse {
    response: GetPlayerSummariesInner,
}

#[derive(Debug, Deserialize)]
struct GetPlayerSummariesInner {
    players: Vec<SteamPlayer>,
}

#[derive(Debug, Deserialize)]
struct SteamPlayer {
    #[serde(rename = "steamid")]
    steam_id: String,
    #[serde(rename = "personaname")]
    persona_name: String,
}

/// GET /Steam/MyPersona - get the current user's Steam persona name
#[get("/MyPersona")]
pub async fn get_my_persona(
    user: AuthenticatedUser<Player>,
    config: &State<Config>,
) -> Result<Json<SteamPersonaResponse>, (Status, Json<AuthentikError>)> {
    let steam_config = config.steam.as_ref().ok_or_else(|| {
        (
            Status::InternalServerError,
            Json(AuthentikError {
                error: "not_configured".to_string(),
                message: "Steam is not configured".to_string(),
            }),
        )
    })?;

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

    let user_sources = get_user_oauth_sources(&http_client, authentik_config, authentik_user.pk)
        .await
        .map_err(|e| {
            (
                Status::InternalServerError,
                Json(AuthentikError {
                    error: "fetch_sources_failed".to_string(),
                    message: e,
                }),
            )
        })?;

    let steam_source = user_sources
        .iter()
        .find(|s| s.source.slug == "steam")
        .ok_or_else(|| {
            (
                Status::NotFound,
                Json(AuthentikError {
                    error: "steam_not_linked".to_string(),
                    message: "No Steam account linked".to_string(),
                }),
            )
        })?;

    let steam_id = parse_steam_id(&steam_source.identifier).ok_or_else(|| {
        (
            Status::InternalServerError,
            Json(AuthentikError {
                error: "invalid_steam_id".to_string(),
                message: "Could not parse Steam ID".to_string(),
            }),
        )
    })?;

    let url = format!(
        "https://partner.steam-api.com/ISteamUser/GetPlayerSummaries/v2/?key={}&steamids={}",
        steam_config.web_api_key, steam_id
    );

    let response = http_client.get(&url).send().await.map_err(|e| {
        (
            Status::InternalServerError,
            Json(AuthentikError {
                error: "steam_api_error".to_string(),
                message: format!("Failed to contact Steam API: {}", e),
            }),
        )
    })?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err((
            Status::InternalServerError,
            Json(AuthentikError {
                error: "steam_api_error".to_string(),
                message: format!("Steam API returned error {}: {}", status, body),
            }),
        ));
    }

    let summaries: GetPlayerSummariesResponse = response.json().await.map_err(|e| {
        (
            Status::InternalServerError,
            Json(AuthentikError {
                error: "steam_api_error".to_string(),
                message: format!("Failed to parse Steam API response: {}", e),
            }),
        )
    })?;

    let player = summaries
        .response
        .players
        .into_iter()
        .next()
        .ok_or_else(|| {
            (
                Status::NotFound,
                Json(AuthentikError {
                    error: "player_not_found".to_string(),
                    message: "Steam player not found".to_string(),
                }),
            )
        })?;

    Ok(Json(SteamPersonaResponse {
        persona_name: player.persona_name,
        steam_id: player.steam_id,
    }))
}
