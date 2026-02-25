use rocket::{State, http::Status, serde::json::Json};
use rocket_db_pools::Connection;
use serde::{Deserialize, Serialize};
use sqlx::{Row, query};

use crate::{
    Cmdb, Config, ServerRoleConfig,
    admin::{AuthenticatedUser, Player},
    authentik::{
        check_verification_eligibility, get_user_by_attribute, get_user_by_uuid,
        get_user_oauth_sources,
    },
    player::{AuthorizationHeader, validate_auth_header},
};

#[derive(Debug, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct DiscordError {
    pub error: String,
    pub message: String,
}

#[derive(Debug, Serialize)]
#[serde(crate = "rocket::serde", rename_all = "camelCase")]
pub struct DiscordUserResponse {
    pub source: String,
    pub ckey: String,
    pub discord_id: String,
    pub authentik_username: Option<String>,
}

/// Response for the Verified endpoint, includes role changes based on verification status
#[derive(Debug, Serialize)]
#[serde(crate = "rocket::serde", rename_all = "camelCase")]
pub struct VerifiedUserResponse {
    pub source: String,
    pub ckey: String,
    pub discord_id: String,
    pub authentik_username: Option<String>,
    /// Role IDs that should be added to the user
    pub roles_to_add: Vec<String>,
    /// Role IDs that should be removed from the user
    pub roles_to_remove: Vec<String>,
}

async fn get_ckey_by_discord_id_from_db(
    db: &mut Connection<Cmdb>,
    discord_id: &str,
) -> Result<String, String> {
    let player_id: i64 = match query("SELECT player_id FROM discord_links WHERE discord_id = ?")
        .bind(discord_id)
        .fetch_one(&mut ***db)
        .await
    {
        Ok(row) => row.get("player_id"),
        Err(_) => {
            return Err(format!(
                "No discord link found for discord_id '{}'",
                discord_id
            ));
        }
    };

    let ckey: String = match query("SELECT ckey FROM players WHERE id = ?")
        .bind(player_id)
        .fetch_one(&mut ***db)
        .await
    {
        Ok(row) => row.get("ckey"),
        Err(_) => return Err(format!("No player found with id '{}'", player_id)),
    };

    Ok(ckey)
}

pub async fn get_whitelist_status_by_ckey(db: &mut Connection<Cmdb>, ckey: &str) -> Option<String> {
    match query("SELECT whitelist_status FROM players WHERE ckey = ?")
        .bind(ckey)
        .fetch_one(&mut ***db)
        .await
    {
        Ok(row) => row.get::<Option<String>, _>("whitelist_status"),
        Err(_) => None,
    }
}

pub struct RoleChanges {
    pub roles_to_add: Vec<String>,
    pub roles_to_remove: Vec<String>,
}

pub fn resolve_role_changes(
    whitelist_status: Option<&str>,
    role_config: &ServerRoleConfig,
    is_linked: bool,
) -> RoleChanges {
    let (mut roles_to_add, mut roles_to_remove) = if is_linked {
        (
            role_config.roles_to_add.clone(),
            role_config.roles_to_remove.clone(),
        )
    } else {
        (
            role_config.roles_to_remove.clone(),
            role_config.roles_to_add.clone(),
        )
    };

    let all_whitelist_roles: Vec<String> = role_config
        .whitelist_roles
        .values()
        .flatten()
        .cloned()
        .collect();

    let earned_whitelist_roles: Vec<String> = if let Some(status) = whitelist_status {
        if !status.is_empty() {
            let player_whitelists: Vec<&str> = status.split('|').map(|s| s.trim()).collect();

            role_config
                .whitelist_roles
                .iter()
                .filter(|(whitelist_name, _role_ids)| {
                    player_whitelists.contains(&whitelist_name.as_str())
                })
                .flat_map(|(_whitelist_name, role_ids)| role_ids.clone())
                .collect()
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    roles_to_add.extend(earned_whitelist_roles.clone());

    let unearned_whitelist_roles: Vec<String> = all_whitelist_roles
        .into_iter()
        .filter(|role| !earned_whitelist_roles.contains(role))
        .collect();
    roles_to_remove.extend(unearned_whitelist_roles);

    roles_to_add.sort();
    roles_to_add.dedup();
    roles_to_remove.sort();
    roles_to_remove.dedup();

    roles_to_remove.retain(|role| !roles_to_add.contains(role));

    RoleChanges {
        roles_to_add,
        roles_to_remove,
    }
}

pub fn resolve_whitelist_roles(
    whitelist_status: Option<&str>,
    role_config: &ServerRoleConfig,
) -> Vec<String> {
    let Some(status) = whitelist_status else {
        return Vec::new();
    };

    if status.is_empty() {
        return Vec::new();
    }

    let player_whitelists: Vec<&str> = status.split('|').map(|s| s.trim()).collect();

    role_config
        .whitelist_roles
        .iter()
        .filter(|(whitelist_name, _role_ids)| player_whitelists.contains(&whitelist_name.as_str()))
        .flat_map(|(_whitelist_name, role_ids)| role_ids.clone())
        .collect()
}

#[get("/User/<discord_id>")]
pub async fn get_user_by_discord(
    auth_header: AuthorizationHeader,
    mut db: Connection<Cmdb>,
    config: &State<Config>,
    discord_id: String,
) -> Result<Json<DiscordUserResponse>, (Status, Json<DiscordError>)> {
    if !validate_auth_header(Some(auth_header.0.as_str()), config) {
        return Err((
            Status::Unauthorized,
            Json(DiscordError {
                error: "unauthorized".to_string(),
                message: "Not authorized to access this resource.".to_string(),
            }),
        ));
    }

    if let Some(authentik_config) = config.authentik.as_ref() {
        let http_client = reqwest::Client::new();

        if let Ok(authentik_user) =
            get_user_by_attribute(&http_client, authentik_config, "discord_id", &discord_id).await
        {
            // Extract ckey from attributes
            let ckey = authentik_user
                .attributes
                .get("ckey")
                .and_then(|v| v.as_str())
                .map(String::from);

            if let Some(ckey) = ckey {
                return Ok(Json(DiscordUserResponse {
                    source: "authentik".to_string(),
                    ckey,
                    discord_id,
                    authentik_username: Some(authentik_user.username),
                }));
            }
        }
    }

    match get_ckey_by_discord_id_from_db(&mut db, &discord_id).await {
        Ok(ckey) => Ok(Json(DiscordUserResponse {
            source: "database".to_string(),
            ckey,
            discord_id,
            authentik_username: None,
        })),
        Err(e) => Err((
            Status::NotFound,
            Json(DiscordError {
                error: "user_not_found".to_string(),
                message: e,
            }),
        )),
    }
}

#[get("/Verified/<discord_id>/<guild_id>")]
pub async fn check_verified(
    auth_header: AuthorizationHeader,
    mut db: Connection<Cmdb>,
    config: &State<Config>,
    discord_id: String,
    guild_id: String,
) -> Result<Json<VerifiedUserResponse>, (Status, Json<DiscordError>)> {
    if !validate_auth_header(Some(auth_header.0.as_str()), config) {
        return Err((
            Status::Unauthorized,
            Json(DiscordError {
                error: "unauthorized".to_string(),
                message: "Not authorized to access this resource.".to_string(),
            }),
        ));
    }

    let discord_config = config.discord_bot.as_ref().ok_or_else(|| {
        (
            Status::InternalServerError,
            Json(DiscordError {
                error: "not_configured".to_string(),
                message: "Discord bot is not configured".to_string(),
            }),
        )
    })?;

    if !discord_config.link_role_changes.contains_key(&guild_id) {
        return Err((
            Status::BadRequest,
            Json(DiscordError {
                error: "invalid_guild".to_string(),
                message: format!("Guild '{}' is not configured for verification", guild_id),
            }),
        ));
    }

    if let Some(authentik_config) = config.authentik.as_ref() {
        let http_client = reqwest::Client::new();

        if let Ok(authentik_user) =
            get_user_by_attribute(&http_client, authentik_config, "discord_id", &discord_id).await
        {
            let ckey = authentik_user
                .attributes
                .get("ckey")
                .and_then(|v| v.as_str())
                .map(String::from);

            if let Ok(oauth_sources) =
                get_user_oauth_sources(&http_client, authentik_config, authentik_user.pk).await
            {
                let linked_sources: Vec<String> = oauth_sources
                    .iter()
                    .map(|s| s.source.slug.clone())
                    .collect();

                let eligibility = check_verification_eligibility(
                    &mut db,
                    &linked_sources,
                    ckey.as_deref(),
                    authentik_user.uuid.as_deref(),
                    Some(&discord_id),
                    discord_config,
                )
                .await;

                match eligibility.server_eligibility.get(&guild_id) {
                    Some(true) => {
                        let ckey_str = eligibility.ckey.clone().unwrap_or_default();
                        let whitelist_status =
                            get_whitelist_status_by_ckey(&mut db, &ckey_str).await;
                        let role_config = discord_config.link_role_changes.get(&guild_id).unwrap();
                        let role_changes =
                            resolve_role_changes(whitelist_status.as_deref(), role_config, true);

                        return Ok(Json(VerifiedUserResponse {
                            source: "authentik".to_string(),
                            ckey: ckey_str,
                            discord_id,
                            authentik_username: Some(authentik_user.username),
                            roles_to_add: role_changes.roles_to_add,
                            roles_to_remove: role_changes.roles_to_remove,
                        }));
                    }
                    Some(false) | None => {
                        let reason = eligibility.reason.unwrap_or_else(|| {
                            format!(
                                "User does not meet verification requirements for guild '{}'",
                                guild_id
                            )
                        });
                        return Err((
                            Status::Forbidden,
                            Json(DiscordError {
                                error: "not_eligible".to_string(),
                                message: reason,
                            }),
                        ));
                    }
                }
            }
        }
    }

    match get_ckey_by_discord_id_from_db(&mut db, &discord_id).await {
        Ok(ckey) => {
            let whitelist_status = get_whitelist_status_by_ckey(&mut db, &ckey).await;
            let role_config = discord_config.link_role_changes.get(&guild_id).unwrap();
            let role_changes = resolve_role_changes(whitelist_status.as_deref(), role_config, true);

            Ok(Json(VerifiedUserResponse {
                source: "database".to_string(),
                ckey,
                discord_id,
                authentik_username: None,
                roles_to_add: role_changes.roles_to_add,
                roles_to_remove: role_changes.roles_to_remove,
            }))
        }
        Err(_) => {
            // User not found - return role changes as if they had unlinked
            let role_config = discord_config.link_role_changes.get(&guild_id).unwrap();
            let role_changes = resolve_role_changes(None, role_config, false);

            Ok(Json(VerifiedUserResponse {
                source: "not_found".to_string(),
                ckey: String::new(),
                discord_id,
                authentik_username: None,
                roles_to_add: role_changes.roles_to_add,
                roles_to_remove: role_changes.roles_to_remove,
            }))
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(crate = "rocket::serde", rename_all = "camelCase")]
pub struct DiscordProfileResponse {
    pub username: String,
    pub discord_id: String,
    pub global_name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DiscordApiUser {
    id: String,
    username: String,
    global_name: Option<String>,
}

/// GET /Discord/MyProfile - get the current user's Discord profile
#[get("/MyProfile")]
pub async fn get_my_profile(
    user: AuthenticatedUser<Player>,
    config: &State<Config>,
) -> Result<Json<DiscordProfileResponse>, (Status, Json<DiscordError>)> {
    let discord_config = config.discord_bot.as_ref().ok_or_else(|| {
        (
            Status::InternalServerError,
            Json(DiscordError {
                error: "not_configured".to_string(),
                message: "Discord is not configured".to_string(),
            }),
        )
    })?;

    let authentik_config = config.authentik.as_ref().ok_or_else(|| {
        (
            Status::InternalServerError,
            Json(DiscordError {
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
                Json(DiscordError {
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
                Json(DiscordError {
                    error: "fetch_sources_failed".to_string(),
                    message: e,
                }),
            )
        })?;

    let discord_source = user_sources
        .iter()
        .find(|s| s.source.slug == "discord")
        .ok_or_else(|| {
            (
                Status::NotFound,
                Json(DiscordError {
                    error: "discord_not_linked".to_string(),
                    message: "No Discord account linked".to_string(),
                }),
            )
        })?;

    let discord_id = &discord_source.identifier;

    let url = format!("https://discord.com/api/v10/users/{}", discord_id);

    let response = http_client
        .get(&url)
        .header("Authorization", format!("Bot {}", discord_config.token))
        .send()
        .await
        .map_err(|e| {
            (
                Status::InternalServerError,
                Json(DiscordError {
                    error: "discord_api_error".to_string(),
                    message: format!("Failed to contact Discord API: {}", e),
                }),
            )
        })?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err((
            Status::InternalServerError,
            Json(DiscordError {
                error: "discord_api_error".to_string(),
                message: format!("Discord API returned error {}: {}", status, body),
            }),
        ));
    }

    let discord_user: DiscordApiUser = response.json().await.map_err(|e| {
        (
            Status::InternalServerError,
            Json(DiscordError {
                error: "discord_api_error".to_string(),
                message: format!("Failed to parse Discord API response: {}", e),
            }),
        )
    })?;

    Ok(Json(DiscordProfileResponse {
        username: discord_user.username,
        discord_id: discord_user.id,
        global_name: discord_user.global_name,
    }))
}
