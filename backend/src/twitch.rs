use rocket::{State, http::Status, serde::json::Json};
use serde::Serialize;

use crate::{
    Config,
    authentik::{AuthentikError, get_user_by_ckey, get_user_oauth_sources},
    player::{AuthorizationHeader, validate_auth_header},
};

#[derive(Serialize)]
pub struct TwitchIdResponse {
    pub twitch_id: String,
}

#[get("/?<ckey>")]
pub async fn get_twitch_id_by_ckey(
    auth_header: AuthorizationHeader,
    ckey: String,
    config: &State<Config>,
) -> Result<Json<TwitchIdResponse>, String> {
    if !validate_auth_header(Some(&auth_header.0), &config) {
        return Err("unauthorized".to_string());
    };

    let http_client = reqwest::Client::new();

    let authentik_config = config
        .authentik
        .as_ref()
        .ok_or_else(|| "authentik is not configured".to_string())?;

    let user = get_user_by_ckey(&http_client, authentik_config, &ckey).await?;
    let oauth_sources = get_user_oauth_sources(&http_client, authentik_config, user.pk).await?;

    let Some(twitch_source) = oauth_sources.iter().find(|s| s.source.slug == "twitch") else {
        return Err("twitch not linked".to_string());
    };

    Ok(Json(TwitchIdResponse {
        twitch_id: twitch_source.identifier.clone(),
    }))
}
