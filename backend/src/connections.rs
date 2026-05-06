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
pub struct LoginHwid {
    id: i64,
    ckey: String,
    hwid: String,
    #[schema(value_type = String)]
    login_date: DateTime<Utc>,
}

#[derive(serde::Serialize, Default, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct HwidHistory {
    hwids: Vec<LoginHwid>,
    all_ckeys: Vec<String>,
    all_hwids: Vec<String>,
}

impl HwidHistory {
    fn annotate(hwids: Vec<LoginHwid>) -> Self {
        let mut unique_ckeys: Vec<String> = Vec::new();
        let mut unique_hwids: Vec<String> = Vec::new();

        for entry in hwids.iter() {
            if !unique_ckeys.contains(&entry.ckey) {
                unique_ckeys.push(entry.ckey.clone());
            }
            if !unique_hwids.contains(&entry.hwid) {
                unique_hwids.push(entry.hwid.clone());
            }
        }

        Self {
            hwids,
            all_ckeys: unique_ckeys,
            all_hwids: unique_hwids,
        }
    }
}

#[derive(serde::Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CkeyLink {
    ckey_a: String,
    ckey_b: String,
    shared_ips: Vec<String>,
    shared_cids: Vec<String>,
    shared_hwids: Vec<String>,
}

#[derive(serde::Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MultiKeyTrace {
    root_ckey: String,
    connected_ckeys: Vec<String>,
    links: Vec<CkeyLink>,
    depth_reached: u32,
    truncated: bool,
}

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

async fn get_hwids_by_ckey(db: &mut MySqlConnection, ckey: &str) -> Option<Vec<LoginHwid>> {
    query_as("SELECT * FROM login_hwid WHERE ckey = ?")
        .bind(ckey)
        .fetch_all(db)
        .await
        .ok()
}

/// Get HWID history by hardware ID
#[utoipa::path(
    get,
    path = "/api/Connections/Hwid",
    tag = "connections",
    params(("hwid" = String, Query, description = "Hardware ID to search")),
    responses(
        (status = 200, description = "HWID history", body = HwidHistory),
        (status = 401, description = "Not authorized")
    )
)]
#[get("/Hwid?<hwid>")]
pub async fn hwid(
    mut db: Connection<Cmdb>,
    _admin: AuthenticatedUser<Staff>,
    hwid: String,
) -> Json<HwidHistory> {
    let query_result: Result<Vec<LoginHwid>, sqlx::Error> =
        query_as("SELECT * FROM login_hwid WHERE hwid = ?")
            .bind(hwid)
            .fetch_all(&mut **db)
            .await;

    let query = match query_result {
        Ok(query) => query,
        Err(_) => return Json(HwidHistory::default()),
    };

    Json(HwidHistory::annotate(query))
}

/// Get HWID history by ckey
#[utoipa::path(
    get,
    path = "/api/Connections/HwidByCkey",
    tag = "connections",
    params(("ckey" = String, Query, description = "Player ckey to search")),
    responses(
        (status = 200, description = "HWID history for the ckey", body = HwidHistory),
        (status = 401, description = "Not authorized")
    )
)]
#[get("/HwidByCkey?<ckey>")]
pub async fn hwid_by_ckey(
    mut db: Connection<Cmdb>,
    _admin: AuthenticatedUser<Staff>,
    ckey: String,
) -> Json<HwidHistory> {
    Json(HwidHistory::annotate(
        match get_hwids_by_ckey(&mut db, &ckey).await {
            Some(query) => query,
            None => return Json(HwidHistory::default()),
        },
    ))
}

/// Get full HWID history by all HWIDs associated with a ckey
#[utoipa::path(
    get,
    path = "/api/Connections/FullByAllHwid",
    tag = "connections",
    params(("ckey" = String, Query, description = "Player ckey to search")),
    responses(
        (status = 200, description = "Full HWID history for all HWIDs", body = HwidHistory),
        (status = 401, description = "Not authorized")
    )
)]
#[get("/FullByAllHwid?<ckey>")]
pub async fn full_by_all_hwid(
    mut db: Connection<Cmdb>,
    _admin: AuthenticatedUser<Staff>,
    ckey: String,
) -> Json<HwidHistory> {
    let hwids = match get_hwids_by_ckey(&mut db, &ckey).await {
        Some(query) => query,
        None => return Json(HwidHistory::default()),
    };

    let mut unique: HashSet<String> = HashSet::new();
    for entry in hwids.into_iter() {
        unique.insert(entry.hwid);
    }

    let hwid_string_vec = unique.into_iter().collect::<Vec<String>>().join(",");

    let query_result: Result<Vec<LoginHwid>, sqlx::Error> =
        query_as("SELECT * FROM login_hwid WHERE FIND_IN_SET(hwid, ?)")
            .bind(hwid_string_vec)
            .fetch_all(&mut **db)
            .await;

    let query = match query_result {
        Ok(query) => query,
        Err(_) => return Json(HwidHistory::default()),
    };

    Json(HwidHistory::annotate(query))
}

fn link_key(a: &str, b: &str) -> (String, String) {
    if a < b {
        (a.to_string(), b.to_string())
    } else {
        (b.to_string(), a.to_string())
    }
}

/// Trace all connected accounts via shared IPs, CIDs, and HWIDs using breadth-first search
#[utoipa::path(
    get,
    path = "/api/Connections/Trace",
    tag = "connections",
    params(
        ("ckey" = String, Query, description = "Player ckey to trace"),
        ("max_depth" = Option<u32>, Query, description = "Maximum BFS depth (1-5, default 3)")
    ),
    responses(
        (status = 200, description = "Multikey trace results", body = MultiKeyTrace),
        (status = 401, description = "Not authorized")
    )
)]
#[get("/Trace?<ckey>&<max_depth>")]
pub async fn trace(
    mut db: Connection<Cmdb>,
    _admin: AuthenticatedUser<Staff>,
    ckey: String,
    max_depth: Option<u32>,
) -> Json<MultiKeyTrace> {
    let max_depth = max_depth.unwrap_or(3).clamp(1, 5);
    let max_ckeys: usize = 200;

    let mut visited: HashSet<String> = HashSet::new();
    let mut frontier: Vec<String> = vec![ckey.clone()];
    let mut links: HashMap<(String, String), CkeyLink> = HashMap::new();
    let mut depth: u32 = 0;
    let mut truncated = false;

    visited.insert(ckey.clone());

    while !frontier.is_empty() && depth < max_depth {
        depth += 1;

        let placeholders = frontier.iter().map(|_| "?").collect::<Vec<_>>().join(",");
        let mut next_frontier: HashSet<String> = HashSet::new();

        // CID connections via self-join
        #[derive(FromRow)]
        struct CidLink {
            frontier_ckey: String,
            connected_ckey: String,
            shared_cid: String,
        }
        let cid_sql = format!(
            "SELECT DISTINCT t1.ckey AS frontier_ckey, t2.ckey AS connected_ckey, t1.last_known_cid AS shared_cid \
             FROM login_triplets t1 \
             JOIN login_triplets t2 ON t1.last_known_cid = t2.last_known_cid \
             WHERE t1.ckey IN ({}) AND t1.ckey != t2.ckey",
            placeholders
        );
        let mut cid_query = sqlx::query_as::<_, CidLink>(&cid_sql);
        for f in &frontier {
            cid_query = cid_query.bind(f);
        }
        if let Ok(rows) = cid_query.fetch_all(&mut **db).await {
            for row in rows {
                if visited.contains(&row.connected_ckey) {
                    continue;
                }
                let key = link_key(&row.frontier_ckey, &row.connected_ckey);
                let link = links.entry(key.clone()).or_insert_with(|| CkeyLink {
                    ckey_a: key.0.clone(),
                    ckey_b: key.1.clone(),
                    shared_ips: Vec::new(),
                    shared_cids: Vec::new(),
                    shared_hwids: Vec::new(),
                });
                if !link.shared_cids.contains(&row.shared_cid) {
                    link.shared_cids.push(row.shared_cid);
                }
                next_frontier.insert(row.connected_ckey);
            }
        }

        // IP connections via self-join
        #[derive(FromRow)]
        struct IpLink {
            frontier_ckey: String,
            connected_ckey: String,
            shared_ip: String,
        }
        let ip_sql = format!(
            "SELECT DISTINCT t1.ckey AS frontier_ckey, t2.ckey AS connected_ckey, \
             CONCAT(t1.ip1, '.', t1.ip2, '.', t1.ip3, '.', t1.ip4) AS shared_ip \
             FROM login_triplets t1 \
             JOIN login_triplets t2 ON t1.ip1 = t2.ip1 AND t1.ip2 = t2.ip2 AND t1.ip3 = t2.ip3 AND t1.ip4 = t2.ip4 \
             WHERE t1.ckey IN ({}) AND t1.ckey != t2.ckey",
            placeholders
        );
        let mut ip_query = sqlx::query_as::<_, IpLink>(&ip_sql);
        for f in &frontier {
            ip_query = ip_query.bind(f);
        }
        if let Ok(rows) = ip_query.fetch_all(&mut **db).await {
            for row in rows {
                if visited.contains(&row.connected_ckey) {
                    continue;
                }
                let key = link_key(&row.frontier_ckey, &row.connected_ckey);
                let link = links.entry(key.clone()).or_insert_with(|| CkeyLink {
                    ckey_a: key.0.clone(),
                    ckey_b: key.1.clone(),
                    shared_ips: Vec::new(),
                    shared_cids: Vec::new(),
                    shared_hwids: Vec::new(),
                });
                if !link.shared_ips.contains(&row.shared_ip) {
                    link.shared_ips.push(row.shared_ip);
                }
                next_frontier.insert(row.connected_ckey);
            }
        }

        // HWID connections via self-join
        #[derive(FromRow)]
        struct HwidLink {
            frontier_ckey: String,
            connected_ckey: String,
            shared_hwid: String,
        }
        let hwid_sql = format!(
            "SELECT DISTINCT h1.ckey AS frontier_ckey, h2.ckey AS connected_ckey, h1.hwid AS shared_hwid \
             FROM login_hwid h1 \
             JOIN login_hwid h2 ON h1.hwid = h2.hwid \
             WHERE h1.ckey IN ({}) AND h1.ckey != h2.ckey",
            placeholders
        );
        let mut hwid_query = sqlx::query_as::<_, HwidLink>(&hwid_sql);
        for f in &frontier {
            hwid_query = hwid_query.bind(f);
        }
        if let Ok(rows) = hwid_query.fetch_all(&mut **db).await {
            for row in rows {
                if visited.contains(&row.connected_ckey) {
                    continue;
                }
                let key = link_key(&row.frontier_ckey, &row.connected_ckey);
                let link = links.entry(key.clone()).or_insert_with(|| CkeyLink {
                    ckey_a: key.0.clone(),
                    ckey_b: key.1.clone(),
                    shared_ips: Vec::new(),
                    shared_cids: Vec::new(),
                    shared_hwids: Vec::new(),
                });
                if !link.shared_hwids.contains(&row.shared_hwid) {
                    link.shared_hwids.push(row.shared_hwid);
                }
                next_frontier.insert(row.connected_ckey);
            }
        }

        for new_ckey in &next_frontier {
            visited.insert(new_ckey.clone());
        }

        if visited.len() >= max_ckeys {
            truncated = true;
            break;
        }

        frontier = next_frontier.into_iter().collect();
    }

    let connected_ckeys: Vec<String> = visited
        .into_iter()
        .filter(|k| k != &ckey)
        .collect();

    Json(MultiKeyTrace {
        root_ckey: ckey,
        connected_ckeys,
        links: links.into_values().collect(),
        depth_reached: depth,
        truncated,
    })
}
