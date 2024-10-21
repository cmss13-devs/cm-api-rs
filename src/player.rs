use rocket::{
    form::Form,
    http::Status,
    serde::{json::Json, Serialize},
};
use rocket_db_pools::Connection;
use sqlx::{prelude::FromRow, query, query_as, MySqlConnection, Row};

use crate::{admin::Admin, Cmdb};

#[derive(Serialize, FromRow)]
#[serde(crate = "rocket::serde", rename_all = "camelCase")]
pub struct Player {
    id: i64,
    ckey: Option<String>,
    last_login: Option<String>,
    is_permabanned: Option<i32>,
    permaban_reason: Option<String>,
    permaban_date: Option<String>,
    permaban_admin_id: Option<i64>,
    is_time_banned: Option<i32>,
    time_ban_reason: Option<String>,
    time_ban_admin_id: Option<i64>,
    time_ban_date: Option<String>,
    time_ban_expiration: Option<i64>,
    last_known_ip: Option<String>,
    last_known_cid: Option<String>,
    migrated_notes: Option<i32>,
    migrated_bans: Option<i32>,
    migrated_jobbans: Option<i32>,
    stickyban_whitelisted: Option<i32>,
    discord_link_id: Option<i64>,
    whitelist_status: Option<String>,
    byond_account_age: Option<String>,
    first_join_date: Option<String>,

    #[sqlx(skip)]
    notes: Vec<Note>,

    #[sqlx(skip)]
    jobbans: Vec<JobBan>,

    #[sqlx(skip)]
    permaban_admin_ckey: Option<String>,

    #[sqlx(skip)]
    time_ban_admin_ckey: Option<String>,

    #[sqlx(skip)]
    discord_id: Option<String>,
}

impl Player {
    async fn add_metadata(mut self, db: &mut MySqlConnection) -> Player {
        match get_player_notes(db, self.id).await {
            Some(notes) => self.notes = notes,
            None => (),
        }

        match get_player_jobbans(db, self.id).await {
            Some(jobbans) => self.jobbans = jobbans,
            None => (),
        }

        if self.is_permabanned.is_some() && self.is_permabanned.unwrap() != 0 {
            self.permaban_admin_ckey = get_player_ckey(db, self.permaban_admin_id.unwrap()).await;
        }

        if self.is_time_banned.is_some() && self.is_time_banned.unwrap() != 0 {
            self.time_ban_admin_ckey = get_player_ckey(db, self.time_ban_admin_id.unwrap()).await;
        }

        self.discord_id = get_discord_id_from_player_id(db, self.id).await;

        self
    }
}

#[derive(Serialize, FromRow)]
#[serde(crate = "rocket::serde", rename_all = "camelCase")]
pub struct Note {
    id: i64,
    player_id: i64,
    admin_id: i64,
    text: String,
    date: String,
    is_ban: i32,
    ban_time: Option<i64>,
    is_confidential: i32,
    admin_rank: String,
    note_category: i32,
    round_id: Option<i32>,
}

async fn get_player_notes(db: &mut MySqlConnection, id: i64) -> Option<Vec<Note>> {
    let user_notes_result: Result<Vec<Note>, sqlx::Error> =
        query_as("SELECT * FROM player_notes WHERE player_id = ?")
            .bind(id)
            .fetch_all(db)
            .await;

    match user_notes_result {
        Ok(notes) => Some(notes),
        Err(_) => None,
    }
}

#[get("/<id>/AppliedNotes")]
pub async fn applied_notes(mut db: Connection<Cmdb>, id: i64) -> Json<Vec<Note>> {
    let user_notes_result: Result<Vec<Note>, sqlx::Error> =
        query_as("SELECT * FROM player_notes WHERE player_id = ?")
            .bind(id)
            .fetch_all(&mut **db)
            .await;

    match user_notes_result {
        Ok(notes) => Json(notes),
        Err(_) => Json(Vec::new()),
    }
}

#[derive(Serialize, FromRow)]
#[serde(crate = "rocket::serde", rename_all = "camelCase")]
pub struct JobBan {
    id: i64,
    player_id: i64,
    admin_id: i64,
    text: String,
    date: String,
    ban_time: i64,
    expiration: i64,
    role: String,
}

async fn get_player_jobbans(db: &mut MySqlConnection, id: i64) -> Option<Vec<JobBan>> {
    let user_jobbans_result: Result<Vec<JobBan>, sqlx::Error> =
        query_as("SELECT * FROM player_job_bans WHERE player_id = ?")
            .bind(id)
            .fetch_all(db)
            .await;

    match user_jobbans_result {
        Ok(jobbans) => Some(jobbans),
        Err(_) => None,
    }
}

async fn get_discord_id_from_player_id(db: &mut MySqlConnection, id: i64) -> Option<String> {
    let discord_search = query("SELECT discord_id FROM discord_links WHERE player_id = ?")
        .bind(id)
        .fetch_one(db)
        .await;

    match discord_search {
        Ok(search) => Some(search.get("discord_id")),
        Err(_) => None,
    }
}

#[get("/?<ckey>&<discord_id>")]
pub async fn index(
    mut db: Connection<Cmdb>,
    ckey: Option<String>,
    discord_id: Option<String>,
) -> Option<Json<Player>> {
    let user_result: Result<Player, sqlx::Error>;

    if ckey.is_some() {
        let unwrapped_ckey = ckey.unwrap();
        user_result = query_as("SELECT * FROM players WHERE ckey = ?")
            .bind(unwrapped_ckey)
            .fetch_one(&mut **db)
            .await;
    } else if discord_id.is_some() {
        let unwrapped_discord_id = discord_id.unwrap();

        let discord_search = query("SELECT player_id FROM discord_links WHERE discord_id = ?")
            .bind(unwrapped_discord_id)
            .fetch_one(&mut **db)
            .await;

        let player_id: i64 = match discord_search {
            Ok(search) => search.get("player_id"),
            Err(_) => return None,
        };

        user_result = query_as("SELECT * FROM players WHERE id = ?")
            .bind(player_id)
            .fetch_one(&mut **db)
            .await;
    } else {
        return None;
    }

    let user = match user_result {
        Ok(user) => user,
        Err(error) => panic!("Error retrieving data: {error:?}"),
    };

    Some(Json(user.add_metadata(&mut **db).await))
}

#[get("/<id>")]
pub async fn id(mut db: Connection<Cmdb>, id: i32) -> Option<Json<Player>> {
    let user_result = query_as("SELECT * FROM players WHERE id = ?")
        .bind(id)
        .fetch_one(&mut **db)
        .await;

    let user: Player = match user_result {
        Ok(user) => user,
        Err(error) => panic!("Error retrieving data: {error:?}"),
    };

    Some(Json(user.add_metadata(&mut **db).await))
}

#[derive(FromForm)]
pub struct NewNote {
    message: String,
    category: i32,
    confidential: i32,
}

#[post("/<id>", data = "<input>")]
pub async fn new_note(
    mut db: Connection<Cmdb>,
    admin: Admin,
    id: i32,
    input: Form<NewNote>,
) -> Status {
    let executor = &mut **db;

    let admin_id_option = get_player_id(executor, admin.username).await;

    let admin_id = match admin_id_option {
        Some(admin_id) => admin_id,
        None => return Status::Unauthorized,
    };

    let now = chrono::Utc::now();
    let date = format!("{}", now.format("%Y-%m-%d %H:%M:%S"));

    let _ = query("
        INSERT INTO player_notes (player_id, admin_id, text, date, is_ban, is_confidential, admin_rank, note_category)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
        .bind(id)
        .bind(admin_id)
        .bind(input.message.clone())
        .bind(date)
        .bind(0)
        .bind(if input.confidential > 0 {1} else {0})
        .bind("[cmdb]".to_string())
        .bind(input.category.clone())
        .execute(executor).await;

    Status::Accepted
}

async fn get_player_id(db: &mut MySqlConnection, ckey: String) -> Option<i32> {
    let player_search = query("SELECT id FROM players WHERE ckey = ?")
        .bind(ckey)
        .fetch_one(db)
        .await;

    let player_id: i32 = match player_search {
        Ok(search) => search.get("id"),
        Err(_) => return None,
    };

    Some(player_id)
}

async fn get_player_ckey(db: &mut MySqlConnection, id: i64) -> Option<String> {
    let player_search = query("SELECT ckeyd FROM players WHERE id = ?")
        .bind(id)
        .fetch_one(db)
        .await;

    let player_ckey: String = match player_search {
        Ok(search) => search.get("ckey"),
        Err(_) => return None,
    };

    Some(player_ckey)
}
