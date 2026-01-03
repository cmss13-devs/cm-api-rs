use rocket::{State, http::Status, serde::json::Json};
use rocket_db_pools::Connection;
use serde::Serialize;
use sqlx::{Row, query};

use crate::{
    Cmdb, Config, ServerRoleConfig,
    authentik::{check_verification_eligibility, get_user_by_attribute, get_user_oauth_sources},
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
    /// Role IDs that should be added based on the player's whitelist status
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub whitelist_roles: Vec<String>,
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
        .filter(|(whitelist_name, _role_id)| player_whitelists.contains(&whitelist_name.as_str()))
        .map(|(_whitelist_name, role_id)| role_id.clone())
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
                    whitelist_roles: Vec::new(),
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
            whitelist_roles: Vec::new(),
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

    let discord_config = config.discord_bot.as_ref().ok_or_else(|| {
        (
            Status::InternalServerError,
            Json(DiscordError {
                error: "not_configured".to_string(),
                message: "Discord bot is not configured".to_string(),
            }),
        )
    })?;

    if !discord_config.unlink_role_changes.contains_key(&guild_id) {
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
                    Some(&discord_id),
                    discord_config,
                )
                .await;

                match eligibility.server_eligibility.get(&guild_id) {
                    Some(true) => {
                        let ckey_str = eligibility.ckey.clone().unwrap_or_default();
                        let whitelist_status =
                            get_whitelist_status_by_ckey(&mut db, &ckey_str).await;
                        let role_config =
                            discord_config.unlink_role_changes.get(&guild_id).unwrap();
                        let whitelist_roles =
                            resolve_whitelist_roles(whitelist_status.as_deref(), role_config);

                        return Ok(Json(DiscordUserResponse {
                            source: "authentik".to_string(),
                            ckey: ckey_str,
                            discord_id,
                            authentik_username: Some(authentik_user.username),
                            whitelist_roles,
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
            let role_config = discord_config.unlink_role_changes.get(&guild_id).unwrap();
            let whitelist_roles = resolve_whitelist_roles(whitelist_status.as_deref(), role_config);

            Ok(Json(DiscordUserResponse {
                source: "database".to_string(),
                ckey,
                discord_id,
                authentik_username: None,
                whitelist_roles,
            }))
        }
        Err(e) => Err((
            Status::NotFound,
            Json(DiscordError {
                error: "user_not_found".to_string(),
                message: e,
            }),
        )),
    }
}
