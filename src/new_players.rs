use rocket::serde::json::Json;
use rocket_db_pools::Connection;
use sqlx::query_as;

use crate::{player::Player, Cmdb};

#[get("/<minutes>")]
pub async fn get_new_players(mut db: Connection<Cmdb>, minutes: i64) -> Json<Vec<Player>> {
    let time_ago = format!(
        "{}",
        (chrono::Utc::now() - chrono::Duration::minutes(minutes)).format("%Y-%m-%d %H:%M:%S")
    );

    match query_as("SELECT * FROM players WHERE first_join_date <> \"UNKNOWN\" AND first_join_date > ? ORDER BY first_join_date ASC")
        .bind(time_ago)
        .fetch_all(&mut **db)
        .await
    {
        Ok(result) => Json(result),
        Err(_) => {
            Json(Vec::new())
        }
    }
}
