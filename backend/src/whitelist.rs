use rocket::serde::json::Json;
use rocket_db_pools::Connection;
use serde::Serialize;
use sqlx::{prelude::FromRow, query_as};
use utoipa::ToSchema;

use crate::{
    Cmdb,
    admin::{AuthenticatedUser, Staff},
};

#[derive(Serialize, FromRow, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WhitelistPlayer {
    id: i64,
    ckey: Option<String>,
    whitelist_status: Option<String>,
}

/// Get all players with whitelists
#[utoipa::path(
    get,
    path = "/api/Whitelist",
    tag = "whitelist",
    security(("session_cookie" = [])),
    responses(
        (status = 200, description = "List of whitelisted players", body = Vec<WhitelistPlayer>),
        (status = 401, description = "Not authorized")
    )
)]
#[get("/")]
pub async fn get_all_whitelistees(
    mut db: Connection<Cmdb>,
    _admin: AuthenticatedUser<Staff>,
) -> Json<Vec<WhitelistPlayer>> {
    match query_as(
        "SELECT id, ckey, whitelist_status FROM players WHERE (whitelist_status is not null AND LENGTH(whitelist_status) > 0)",
    )
    .fetch_all(&mut **db)
    .await
    {
        Ok(result) => Json(result),
        Err(_) => Json(Vec::new()),
    }
}
