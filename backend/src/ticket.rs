use chrono::Utc;
use rocket::futures::Stream;
use rocket::{futures::TryStreamExt, serde::json::Json};
use rocket_db_pools::Connection;
use serde::Serialize;
use sqlx::Row;
use sqlx::{prelude::FromRow, query, query_as};
use utoipa::ToSchema;

use crate::admin::AuthenticatedUser;
use crate::{Cmdb, admin::Staff};

#[derive(FromRow, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct Ticket {
    id: i64,
    ticket: i32,
    action: String,
    message: String,
    recipient: Option<String>,
    sender: Option<String>,
    round_id: Option<i32>,
    #[schema(value_type = String)]
    time: chrono::DateTime<Utc>,
    urgent: i32,
}

/// Get all tickets from a specific round
#[utoipa::path(
    get,
    path = "/api/Ticket/{round_id}",
    tag = "ticket",
    security(("session_cookie" = [])),
    params(("round_id" = i64, Path, description = "Round ID")),
    responses(
        (status = 200, description = "List of tickets", body = Vec<Ticket>),
        (status = 401, description = "Not authorized")
    )
)]
#[get("/<round_id>")]
pub async fn get_tickets_by_round_id(
    mut db: Connection<Cmdb>,
    _admin: AuthenticatedUser<Staff>,
    round_id: i64,
) -> Json<Vec<Ticket>> {
    match query_as("SELECT * FROM ticket WHERE round_id = ?")
        .bind(round_id)
        .fetch_all(&mut **db)
        .await
    {
        Ok(ticket) => Json(ticket),
        Err(val) => panic!("{}", val),
    }
}

/// Get tickets involving a specific player
#[utoipa::path(
    get,
    path = "/api/Ticket/User/{ckey}",
    tag = "ticket",
    security(("session_cookie" = [])),
    params(
        ("ckey" = String, Path, description = "Player ckey"),
        ("page" = Option<i64>, Query, description = "Page number (1-indexed, 15 results per page)"),
        ("from" = Option<String>, Query, description = "Start date filter (YYYY-MM-DD)"),
        ("to" = Option<String>, Query, description = "End date filter (YYYY-MM-DD)")
    ),
    responses(
        (status = 200, description = "List of tickets", body = Vec<Ticket>),
        (status = 401, description = "Not authorized")
    )
)]
#[get("/User/<ckey>?<page>&<from>&<to>")]
pub async fn get_tickets_by_user(
    mut db: Connection<Cmdb>,
    _admin: AuthenticatedUser<Staff>,
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

        if let Some(from) = from
            && let Some(to) = to
        {
            rows = query("SELECT DISTINCT round_id, ticket FROM ticket WHERE (sender = ? OR recipient = ?) AND (time >= ? AND time <= ?) ORDER BY round_id DESC LIMIT 15 OFFSET ?")
                .bind(ckey)
                .bind(ckey)
                .bind(from)
                .bind(to)
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
