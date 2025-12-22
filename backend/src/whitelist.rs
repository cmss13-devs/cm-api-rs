use rocket::serde::json::Json;
use rocket_db_pools::Connection;
use serde::Serialize;
use sqlx::{prelude::FromRow, query_as};

use crate::{
    Cmdb,
    admin::{Admin, AuthenticatedUser},
};

#[derive(Serialize, FromRow)]
#[serde(rename_all = "camelCase")]
pub struct WhitelistPlayer {
    id: i64,
    ckey: Option<String>,
    whitelist_status: Option<String>,
}

#[get("/")]
pub async fn get_all_whitelistees(
    mut db: Connection<Cmdb>,
    _admin: AuthenticatedUser<Admin>,
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
