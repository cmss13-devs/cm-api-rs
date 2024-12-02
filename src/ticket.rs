use chrono::Utc;
use rocket::futures::Stream;
use rocket::{futures::TryStreamExt, serde::json::Json};
use rocket_db_pools::Connection;
use serde::Serialize;
use sqlx::Row;
use sqlx::{prelude::FromRow, query, query_as};

use crate::Cmdb;

#[derive(FromRow, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Ticket {
    id: i64,
    ticket: i32,
    action: String,
    message: String,
    recipient: Option<String>,
    sender: Option<String>,
    round_id: Option<i32>,
    time: chrono::DateTime<Utc>,
    urgent: i32,
}

#[get("/<round_id>")]
pub async fn get_tickets_by_round_id(mut db: Connection<Cmdb>, round_id: i64) -> Json<Vec<Ticket>> {
    match query_as("SELECT * FROM ticket WHERE round_id = ?")
        .bind(round_id)
        .fetch_all(&mut **db)
        .await
    {
        Ok(ticket) => Json(ticket),
        Err(val) => panic!("{}", val),
    }
}

#[get("/User/<ckey>?<page>&<from>&<to>")]
pub async fn get_tickets_by_user(
    mut db: Connection<Cmdb>,
    ckey: &str,
    page: Option<i64>,
    from: Option<String>,
    to: Option<String>,
) -> Json<Vec<Ticket>> {
    let mut ridsticks: Vec<(i32, i32)> = Vec::new();

    let offset = (page.unwrap_or(1) - 1) * 15;

    {
        let mut rows: std::pin::Pin<
            Box<dyn Stream<Item = Result<sqlx::mysql::MySqlRow, sqlx::Error>> + Send>,
        >;

        if from.is_some() && to.is_some() {
            rows = query("SELECT DISTINCT round_id, ticket FROM ticket WHERE (sender = ? OR recipient = ?) AND (time >= ? AND time <= ?) ORDER BY round_id DESC LIMIT 15 OFFSET ?")
                .bind(ckey)
                .bind(ckey)
                .bind(from.unwrap())
                .bind(to.unwrap())
                .bind(offset)
                .fetch(&mut **db)
        } else {
            rows = query("SELECT DISTINCT round_id, ticket FROM ticket WHERE (sender = ? OR recipient = ?) ORDER BY round_id DESC LIMIT 15 OFFSET ?")
            .bind(ckey)
            .bind(ckey)
            .bind(offset)
            .fetch(&mut **db);
        }

        let mut row_result = rows.try_next().await;
        while row_result.is_ok() {
            match row_result.as_mut().unwrap() {
                Some(value) => ridsticks.push((
                    value.try_get("round_id").unwrap(),
                    value.try_get("ticket").unwrap(),
                )),
                None => break,
            };

            row_result = rows.try_next().await;
        }
    }

    let mut query_vec: Vec<String> = Vec::new();

    for roundid_ticket in ridsticks {
        query_vec.push(format!(
            "(round_id = {} AND ticket = {})",
            roundid_ticket.0, roundid_ticket.1
        ));
    }

    let query_string = format!("SELECT * FROM ticket WHERE ({})", query_vec.join(" OR "));

    let query_result: Result<Vec<Ticket>, sqlx::Error> =
        query_as(&query_string).fetch_all(&mut **db).await;

    match query_result {
        Ok(value) => Json(value),
        Err(_) => Json(Vec::new()),
    }
}
