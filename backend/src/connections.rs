use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};
use rocket::serde::json::Json;
use rocket_db_pools::Connection;
use sqlx::{MySqlConnection, prelude::FromRow, query_as};
use utoipa::ToSchema;

use crate::{
    Cmdb,
    admin::{AuthenticatedUser, Staff},
};

#[derive(serde::Serialize, FromRow, Hash, Eq, PartialEq, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct LoginTriplet {
    id: i64,
    ckey: String,
    ip1: i32,
    ip2: i32,
    ip3: i32,
    ip4: i32,
    last_known_cid: String,
    #[schema(value_type = String)]
    login_date: DateTime<Utc>,
}

#[derive(serde::Serialize, Default, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionHistory {
    triplets: Vec<LoginTriplet>,
    all_ckeys: Vec<String>,
    all_cids: Vec<String>,
    all_ips: Vec<String>,
}

impl ConnectionHistory {
    fn annotate(triplets: Vec<LoginTriplet>) -> Self {
        let mut unique_ckeys: Vec<String> = Vec::new();
        let mut unique_cids: Vec<String> = Vec::new();
        let mut unique_ips: Vec<String> = Vec::new();

        for triplet in triplets.iter() {
            if !unique_ckeys.contains(&triplet.ckey) {
                unique_ckeys.push(triplet.ckey.clone());
            }

            if !unique_cids.contains(&triplet.last_known_cid) {
                unique_cids.push(triplet.last_known_cid.clone());
            }

            let computed_ip = format!(
                "{}.{}.{}.{}",
                triplet.ip1, triplet.ip2, triplet.ip3, triplet.ip4
            );

            if !unique_ips.contains(&computed_ip) {
                unique_ips.push(computed_ip);
            }
        }

        Self {
            triplets,
            all_cids: unique_cids,
            all_ckeys: unique_ckeys,
            all_ips: unique_ips,
        }
    }
}

/// Get connection history by IP address
#[utoipa::path(
    get,
    path = "/api/Connections/Ip",
    tag = "connections",
    params(("ip" = String, Query, description = "IP address to search (e.g., 192.168.1.1)")),
    responses(
        (status = 200, description = "Connection history for the IP", body = ConnectionHistory),
        (status = 401, description = "Not authorized")
    )
)]
#[get("/Ip?<ip>")]
pub async fn ip(
    mut db: Connection<Cmdb>,
    _admin: AuthenticatedUser<Staff>,
    ip: String,
) -> Json<ConnectionHistory> {
    let parts: Vec<&str> = ip.split('.').collect();

    let query = match query_as(
        "SELECT * FROM login_triplets WHERE ip1 = ? AND ip2 = ? AND ip3 = ? AND ip4 = ?",
    )
    .bind(parts[0])
    .bind(parts[1])
    .bind(parts[2])
    .bind(parts[3])
    .fetch_all(&mut **db)
    .await
    {
        Ok(query) => query,
        Err(_) => return Json(ConnectionHistory::default()),
    };

    Json(ConnectionHistory::annotate(query))
}

/// Get connection history by computer ID
#[utoipa::path(
    get,
    path = "/api/Connections/Cid",
    tag = "connections",
    params(("cid" = String, Query, description = "Computer ID to search")),
    responses(
        (status = 200, description = "Connection history for the CID", body = ConnectionHistory),
        (status = 401, description = "Not authorized")
    )
)]
#[get("/Cid?<cid>")]
pub async fn cid(
    mut db: Connection<Cmdb>,
    _admin: AuthenticatedUser<Staff>,
    cid: String,
) -> Json<ConnectionHistory> {
    let query_result: Result<Vec<LoginTriplet>, sqlx::Error> =
        query_as("SELECT * FROM login_triplets WHERE last_known_cid = ?")
            .bind(cid)
            .fetch_all(&mut **db)
            .await;

    let query = match query_result {
        Ok(query) => query,
        Err(_) => return Json(ConnectionHistory::default()),
    };

    Json(ConnectionHistory::annotate(query))
}

async fn get_triplets_by_ckey(db: &mut MySqlConnection, ckey: String) -> Option<Vec<LoginTriplet>> {
    let query_result: Result<Vec<LoginTriplet>, sqlx::Error> =
        query_as("SELECT * FROM login_triplets WHERE ckey = ?")
            .bind(ckey)
            .fetch_all(db)
            .await;

    query_result.ok()
}

/// Get connection history by ckey
#[utoipa::path(
    get,
    path = "/api/Connections/Ckey",
    tag = "connections",
    params(("ckey" = String, Query, description = "Player ckey to search")),
    responses(
        (status = 200, description = "Connection history for the ckey", body = ConnectionHistory),
        (status = 401, description = "Not authorized")
    )
)]
#[get("/Ckey?<ckey>")]
pub async fn ckey(
    mut db: Connection<Cmdb>,
    _admin: AuthenticatedUser<Staff>,
    ckey: String,
) -> Json<ConnectionHistory> {
    Json(ConnectionHistory::annotate(
        match get_triplets_by_ckey(&mut db, ckey).await {
            Some(query) => query,
            None => return Json(ConnectionHistory::default()),
        },
    ))
}

/// Get full connection history by all CIDs associated with a ckey
#[utoipa::path(
    get,
    path = "/api/Connections/FullByAllCid",
    tag = "connections",
    params(("ckey" = String, Query, description = "Player ckey to search")),
    responses(
        (status = 200, description = "Full connection history for all CIDs", body = ConnectionHistory),
        (status = 401, description = "Not authorized")
    )
)]
#[get("/FullByAllCid?<ckey>")]
pub async fn connection_history_by_cid(
    mut db: Connection<Cmdb>,
    _admin: AuthenticatedUser<Staff>,
    ckey: String,
) -> Json<ConnectionHistory> {
    let triplets = match get_triplets_by_ckey(&mut db, ckey).await {
        Some(query) => query,
        None => return Json(ConnectionHistory::default()),
    };

    let mut unique: HashSet<String> = HashSet::new();

    for triplet in triplets.into_iter() {
        unique.insert(triplet.last_known_cid);
    }

    let cid_string_vec = unique.into_iter().collect::<Vec<String>>().join(",");

    let query_result: Result<Vec<LoginTriplet>, sqlx::Error> =
        query_as("SELECT * FROM login_triplets WHERE FIND_IN_SET(last_known_cid, ?)")
            .bind(cid_string_vec)
            .fetch_all(&mut **db)
            .await;

    let query = match query_result {
        Ok(query) => query,
        Err(_) => return Json(ConnectionHistory::default()),
    };

    Json(ConnectionHistory::annotate(query))
}

/// Get full connection history by all IPs associated with a ckey
#[utoipa::path(
    get,
    path = "/api/Connections/FullByAllIps",
    tag = "connections",
    params(("ckey" = String, Query, description = "Player ckey to search")),
    responses(
        (status = 200, description = "Full connection history for all IPs", body = ConnectionHistory),
        (status = 401, description = "Not authorized")
    )
)]
#[get("/FullByAllIps?<ckey>")]
pub async fn connection_history_by_ip(
    mut db: Connection<Cmdb>,
    _admin: AuthenticatedUser<Staff>,
    ckey: String,
) -> Json<ConnectionHistory> {
    let triplets = match get_triplets_by_ckey(&mut db, ckey).await {
        Some(query) => query,
        None => return Json(ConnectionHistory::default()),
    };

    let mut unique: HashMap<String, LoginTriplet> = HashMap::new();

    for triplet in triplets.into_iter() {
        let ip_string = format!(
            "{}.{}.{}.{}",
            triplet.ip1, triplet.ip2, triplet.ip3, triplet.ip4
        );
        unique.insert(ip_string, triplet);
    }

    let mut building_string: Vec<String> = Vec::new();

    for tuple in unique {
        let unique_triplet = tuple.1;
        building_string.push(format!{"(ip1 = {} AND ip2 = {} AND ip3 = {} AND ip4 = {})", unique_triplet.ip1, unique_triplet.ip2, unique_triplet.ip3, unique_triplet.ip4});
    }

    let ip_string = format!(
        "SELECT * FROM login_triplets WHERE {}",
        building_string.join(" OR ")
    );

    let query_result: Result<Vec<LoginTriplet>, sqlx::Error> =
        query_as(&ip_string).fetch_all(&mut **db).await;

    let query = match query_result {
        Ok(query) => query,
        Err(_) => return Json(ConnectionHistory::default()),
    };

    Json(ConnectionHistory::annotate(query))
}
