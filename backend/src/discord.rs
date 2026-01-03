use rocket::{State, http::Status, serde::json::Json};
use rocket_db_pools::Connection;
use serde::Serialize;
use sqlx::{Row, query};

use crate::{
    Cmdb, Config,
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
            // Extract ckey from attributes
            let ckey = authentik_user
                .attributes
                .get("ckey")
                .and_then(|v| v.as_str())
                .map(String::from);

            if let Ok(oauth_sources) =
                get_user_oauth_sources(&http_client, authentik_config, authentik_user.pk).await
            {
                // Convert OAuth sources to linked source slugs
                let linked_sources: Vec<String> = oauth_sources
                    .iter()
                    .map(|s| s.source.slug.clone())
                    .collect();

                // Check eligibility using the shared function
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
                        return Ok(Json(DiscordUserResponse {
                            source: "authentik".to_string(),
                            ckey: eligibility.ckey.unwrap_or_default(),
                            discord_id,
                            authentik_username: Some(authentik_user.username),
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
