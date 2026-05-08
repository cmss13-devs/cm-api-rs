use rocket::{State, http::Status, serde::json::Json};
use rocket_db_pools::Connection;
use serde::{Deserialize, Serialize};
use serenity::all::{GuildId, Http, UserId};
use sqlx::{FromRow, Row, query, query_as};
use std::time::Duration;

use crate::{
    Cmapi, Cmdb, Config,
    admin::{AuthenticatedUser, Player},
    authentik::{
        AuthentikConfig, AuthentikError, DiscourseConfig, get_discord_id_from_sources,
        get_user_by_uuid, get_user_oauth_sources,
    },
};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActiveBan {
    pub ban_type: String,
    pub reference_id: String,
    pub reason: String,
    pub date: Option<String>,
    pub expiration: Option<i64>,
    pub role: Option<String>,
    pub stickyban_identifier: Option<String>,
    pub has_active_appeal: bool,
    pub appeal_url: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MyBansResponse {
    pub ckey: String,
    pub bans: Vec<ActiveBan>,
}

#[derive(Debug, Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct SubmitAppealRequest {
    pub ban_type: String,
    pub ban_reference_id: String,
    pub appeal_reason: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppealResponse {
    pub topic_url: String,
    pub topic_id: i64,
}

#[derive(Debug, FromRow)]
#[allow(dead_code)]
struct BanAppealRow {
    id: i64,
    discourse_topic_url: String,
}

#[derive(Debug, FromRow)]
struct PlayerBanRow {
    id: i64,
    is_permabanned: Option<i32>,
    permaban_reason: Option<String>,
    permaban_date: Option<String>,
    is_time_banned: Option<i32>,
    time_ban_reason: Option<String>,
    time_ban_date: Option<String>,
    time_ban_expiration: Option<i64>,
}

#[derive(Debug, FromRow)]
struct JobBanRow {
    id: i64,
    text: String,
    date: Option<String>,
    expiration: Option<i64>,
    role: String,
}

#[derive(Debug, FromRow)]
struct StickybanRow {
    id: i32,
    identifier: String,
    reason: String,
    date: String,
}

#[derive(Debug, FromRow)]
#[allow(dead_code)]
struct NoteRow {
    text: Option<String>,
    date: String,
    is_ban: i32,
    ban_time: Option<i64>,
    admin_rank: String,
    note_category: Option<i32>,
}

struct ResolvedUser {
    ckey: String,
    discord_id: Option<String>,
}

async fn resolve_user(
    user: &AuthenticatedUser<Player>,
    authentik_config: &AuthentikConfig,
) -> Result<ResolvedUser, (Status, Json<AuthentikError>)> {
    let http_client = reqwest::Client::new();
    let authentik_user = get_user_by_uuid(&http_client, authentik_config, &user.sub)
        .await
        .map_err(|e| {
            (
                Status::NotFound,
                Json(AuthentikError {
                    error: "user_not_found".to_string(),
                    message: e,
                }),
            )
        })?;

    let user_sources = get_user_oauth_sources(&http_client, authentik_config, authentik_user.pk)
        .await
        .map_err(|e| {
            (
                Status::InternalServerError,
                Json(AuthentikError {
                    error: "fetch_sources_failed".to_string(),
                    message: e,
                }),
            )
        })?;

    let discord_id =
        get_discord_id_from_sources(&user_sources, &authentik_user.attributes);

    let byond_source = user_sources.iter().find(|s| s.source.slug == "byond");
    let ckey = if let Some(byond) = byond_source {
        byond
            .identifier
            .strip_prefix("user:")
            .unwrap_or(&byond.identifier)
            .to_lowercase()
    } else {
        authentik_user
            .uuid
            .as_ref()
            .map(|u| u.replace('-', "").to_lowercase())
            .ok_or_else(|| {
                (
                    Status::BadRequest,
                    Json(AuthentikError {
                        error: "no_ckey".to_string(),
                        message: "No BYOND account linked and no UUID available".to_string(),
                    }),
                )
            })?
    };

    Ok(ResolvedUser { ckey, discord_id })
}

fn byond_time_now() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let epoch_2000 = 946684800i64; // 2000-01-01 in unix seconds
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    (now - epoch_2000) / 60 // BYOND time is in deciseconds from 2000, stored as minutes
}

#[get("/MyBans")]
pub async fn get_my_bans(
    user: AuthenticatedUser<Player>,
    config: &State<Config>,
    mut db: Connection<Cmdb>,
    mut api_db: Connection<Cmapi>,
) -> Result<Json<MyBansResponse>, (Status, Json<AuthentikError>)> {
    let authentik_config = config.authentik.as_ref().ok_or_else(|| {
        (
            Status::InternalServerError,
            Json(AuthentikError {
                error: "not_configured".to_string(),
                message: "Authentik is not configured".to_string(),
            }),
        )
    })?;

    let resolved = resolve_user(&user, authentik_config).await?;
    let ckey = &resolved.ckey;

    let player: Option<PlayerBanRow> = query_as(
        "SELECT id, is_permabanned, permaban_reason, permaban_date, \
         is_time_banned, time_ban_reason, time_ban_date, time_ban_expiration \
         FROM players WHERE ckey = ?",
    )
    .bind(ckey)
    .fetch_optional(&mut **db)
    .await
    .map_err(|e| {
        (
            Status::InternalServerError,
            Json(AuthentikError {
                error: "database_error".to_string(),
                message: format!("Failed to query player: {}", e),
            }),
        )
    })?;

    let mut bans: Vec<ActiveBan> = Vec::new();

    if let Some(ref player) = player {
        if player.is_permabanned == Some(1) {
            bans.push(ActiveBan {
                ban_type: "permaban".to_string(),
                reference_id: player.id.to_string(),
                reason: player
                    .permaban_reason
                    .clone()
                    .unwrap_or_else(|| "No reason given".to_string()),
                date: player.permaban_date.clone(),
                expiration: None,
                role: None,
                stickyban_identifier: None,
                has_active_appeal: false,
                appeal_url: None,
            });
        }

        let byond_now = byond_time_now();
        if player.is_time_banned == Some(1)
            && let Some(exp) = player.time_ban_expiration
            && exp > byond_now
        {
            bans.push(ActiveBan {
                ban_type: "timeban".to_string(),
                reference_id: player.id.to_string(),
                reason: player
                    .time_ban_reason
                    .clone()
                    .unwrap_or_else(|| "No reason given".to_string()),
                date: player.time_ban_date.clone(),
                expiration: Some(exp),
                role: None,
                stickyban_identifier: None,
                has_active_appeal: false,
                appeal_url: None,
            });
        }

        let job_bans: Vec<JobBanRow> = query_as(
            "SELECT id, text, date, expiration, role \
             FROM player_job_bans \
             WHERE player_id = ? AND (expiration IS NULL OR expiration > UNIX_TIMESTAMP())",
        )
        .bind(player.id)
        .fetch_all(&mut **db)
        .await
        .unwrap_or_default();

        for jb in job_bans {
            bans.push(ActiveBan {
                ban_type: "jobban".to_string(),
                reference_id: jb.id.to_string(),
                reason: jb.text,
                date: jb.date,
                expiration: jb.expiration,
                role: Some(jb.role),
                stickyban_identifier: None,
                has_active_appeal: false,
                appeal_url: None,
            });
        }
    }

    let matched_stickybans: Vec<StickybanRow> = query_as(
        "SELECT s.id, s.identifier, s.reason, s.date \
         FROM stickyban_matched_ckey mc \
         JOIN stickyban s ON s.id = mc.linked_stickyban \
         WHERE mc.ckey = ? AND mc.whitelisted = 0 AND s.active = 1",
    )
    .bind(&ckey)
    .fetch_all(&mut **db)
    .await
    .unwrap_or_default();

    for sb in matched_stickybans {
        bans.push(ActiveBan {
            ban_type: "stickyban".to_string(),
            reference_id: sb.id.to_string(),
            reason: sb.reason,
            date: Some(sb.date),
            expiration: None,
            role: None,
            stickyban_identifier: Some(sb.identifier),
            has_active_appeal: false,
            appeal_url: None,
        });
    }

    if let Some(reason) = check_discord_ban_for_user(resolved.discord_id.as_deref(), config).await {
        bans.push(ActiveBan {
            ban_type: "discord".to_string(),
            reference_id: "discord".to_string(),
            reason,
            date: None,
            expiration: None,
            role: None,
            stickyban_identifier: None,
            has_active_appeal: false,
            appeal_url: None,
        });
    }

    let active_keys: Vec<String> = bans
        .iter()
        .map(|b| format!("{}:{}", b.ban_type, b.reference_id))
        .collect();

    #[derive(Debug, FromRow)]
    struct FullAppealRow {
        id: i64,
        ban_type: String,
        ban_reference_id: String,
    }
    let open_appeals_full: Vec<FullAppealRow> = query_as(
        "SELECT id, ban_type, ban_reference_id FROM ban_appeals WHERE ckey = ? AND status = 'open'",
    )
    .bind(&ckey)
    .fetch_all(&mut **api_db)
    .await
    .unwrap_or_default();

    for appeal in &open_appeals_full {
        let key = format!("{}:{}", appeal.ban_type, appeal.ban_reference_id);
        if !active_keys.contains(&key) {
            let _ = query("UPDATE ban_appeals SET status = 'expired' WHERE id = ?")
                .bind(appeal.id)
                .execute(&mut **api_db)
                .await;
        }
    }

    for ban in &mut bans {
        let appeal: Option<BanAppealRow> = query_as(
            "SELECT id, discourse_topic_url FROM ban_appeals \
             WHERE ckey = ? AND ban_type = ? AND ban_reference_id = ? AND status = 'open' \
             AND created_at > DATE_SUB(NOW(), INTERVAL 30 DAY)",
        )
        .bind(&ckey)
        .bind(&ban.ban_type)
        .bind(&ban.reference_id)
        .fetch_optional(&mut **api_db)
        .await
        .unwrap_or(None);

        if let Some(appeal) = appeal {
            ban.has_active_appeal = true;
            ban.appeal_url = Some(appeal.discourse_topic_url);
        }
    }

    Ok(Json(MyBansResponse {
        ckey: resolved.ckey,
        bans,
    }))
}

#[post("/Submit", format = "json", data = "<request>")]
pub async fn submit_appeal(
    user: AuthenticatedUser<Player>,
    config: &State<Config>,
    mut db: Connection<Cmdb>,
    mut api_db: Connection<Cmapi>,
    request: Json<SubmitAppealRequest>,
) -> Result<Json<AppealResponse>, (Status, Json<AuthentikError>)> {
    let authentik_config = config.authentik.as_ref().ok_or_else(|| {
        (
            Status::InternalServerError,
            Json(AuthentikError {
                error: "not_configured".to_string(),
                message: "Authentik is not configured".to_string(),
            }),
        )
    })?;

    let discourse_config = authentik_config.discourse.as_ref().ok_or_else(|| {
        (
            Status::InternalServerError,
            Json(AuthentikError {
                error: "not_configured".to_string(),
                message: "Discourse is not configured".to_string(),
            }),
        )
    })?;

    let appeal_categories = discourse_config.appeal_categories.as_ref().ok_or_else(|| {
        (
            Status::InternalServerError,
            Json(AuthentikError {
                error: "not_configured".to_string(),
                message: "Appeal categories are not configured".to_string(),
            }),
        )
    })?;

    let category_id = appeal_categories.get(&request.ban_type).ok_or_else(|| {
        (
            Status::BadRequest,
            Json(AuthentikError {
                error: "invalid_ban_type".to_string(),
                message: format!(
                    "No appeal category configured for ban type '{}'",
                    request.ban_type
                ),
            }),
        )
    })?;

    let resolved = resolve_user(&user, authentik_config).await?;
    let ckey = &resolved.ckey;

    if request.appeal_reason.trim().is_empty() {
        return Err((
            Status::BadRequest,
            Json(AuthentikError {
                error: "empty_appeal".to_string(),
                message: "Appeal reason cannot be empty".to_string(),
            }),
        ));
    }

    let existing: Option<BanAppealRow> = query_as(
        "SELECT id, discourse_topic_url FROM ban_appeals \
         WHERE ckey = ? AND ban_type = ? AND ban_reference_id = ? AND status = 'open' \
         AND created_at > DATE_SUB(NOW(), INTERVAL 30 DAY)",
    )
    .bind(&ckey)
    .bind(&request.ban_type)
    .bind(&request.ban_reference_id)
    .fetch_optional(&mut **api_db)
    .await
    .map_err(|e| {
        (
            Status::InternalServerError,
            Json(AuthentikError {
                error: "database_error".to_string(),
                message: format!("Failed to check existing appeals: {}", e),
            }),
        )
    })?;

    if existing.is_some() {
        return Err((
            Status::Conflict,
            Json(AuthentikError {
                error: "appeal_exists".to_string(),
                message: "You already have an active appeal for this ban".to_string(),
            }),
        ));
    }

    validate_ban_active(
        ckey,
        &request.ban_type,
        &request.ban_reference_id,
        resolved.discord_id.as_deref(),
        config,
        &mut db,
    )
    .await?;

    let http_client = reqwest::Client::new();
    let authentik_user = get_user_by_uuid(&http_client, authentik_config, &user.sub)
        .await
        .map_err(|e| {
            (
                Status::InternalServerError,
                Json(AuthentikError {
                    error: "authentik_error".to_string(),
                    message: e,
                }),
            )
        })?;

    let discourse_username = get_or_create_discourse_user(
        &http_client,
        discourse_config,
        &authentik_user.uid,
        authentik_user.email.as_deref().unwrap_or(&user.email),
        &authentik_user.username,
    )
    .await
    .map_err(|e| {
        (
            Status::InternalServerError,
            Json(AuthentikError {
                error: "discourse_error".to_string(),
                message: e,
            }),
        )
    })?;

    let ban_type_display = match request.ban_type.as_str() {
        "permaban" => "Permanent Ban",
        "timeban" => "Temporary Ban",
        "stickyban" => "Sticky Ban",
        "jobban" => "Job Ban",
        "discord" => "Discord Ban",
        _ => &request.ban_type,
    };

    let title = format!("{} - {} Appeal", discourse_username, ban_type_display);
    let topic_body = format!(
        "# {} - {} Appeal\n\n## BYOND ckey\n{}\n\n## Appeal\n{}",
        discourse_username, ban_type_display, ckey, request.appeal_reason
    );
    let topic = create_discourse_topic(
        &http_client,
        discourse_config,
        &discourse_username,
        &title,
        &topic_body,
        *category_id,
    )
    .await
    .map_err(|e| {
        (
            Status::InternalServerError,
            Json(AuthentikError {
                error: "discourse_error".to_string(),
                message: format!("Failed to create topic: {}", e),
            }),
        )
    })?;

    let whisper_body =
        build_whisper_content(ckey, &request.ban_type, &request.ban_reference_id, resolved.discord_id.as_deref(), config, &mut db).await;

    let _ = create_discourse_whisper(
        &http_client,
        discourse_config,
        topic.topic_id,
        &whisper_body,
    )
    .await;

    let topic_url = format!(
        "{}/t/{}",
        discourse_config.base_url.trim_end_matches('/'),
        topic.topic_id
    );

    query(
        "INSERT INTO ban_appeals (ckey, ban_type, ban_reference_id, discourse_topic_id, discourse_topic_url, status) \
         VALUES (?, ?, ?, ?, ?, 'open')",
    )
    .bind(&ckey)
    .bind(&request.ban_type)
    .bind(&request.ban_reference_id)
    .bind(topic.topic_id)
    .bind(&topic_url)
    .execute(&mut **api_db)
    .await
    .map_err(|e| {
        (
            Status::InternalServerError,
            Json(AuthentikError {
                error: "database_error".to_string(),
                message: format!("Failed to save appeal: {}", e),
            }),
        )
    })?;

    Ok(Json(AppealResponse {
        topic_url,
        topic_id: topic.topic_id,
    }))
}

async fn validate_ban_active(
    ckey: &str,
    ban_type: &str,
    reference_id: &str,
    discord_id: Option<&str>,
    config: &State<Config>,
    db: &mut Connection<Cmdb>,
) -> Result<(), (Status, Json<AuthentikError>)> {
    match ban_type {
        "permaban" => {
            let row: Option<(i32,)> = query_as(
                "SELECT is_permabanned as `0` FROM players WHERE ckey = ? AND is_permabanned = 1",
            )
            .bind(ckey)
            .fetch_optional(&mut ***db)
            .await
            .unwrap_or(None);
            if row.is_none() {
                return Err((
                    Status::BadRequest,
                    Json(AuthentikError {
                        error: "ban_not_active".to_string(),
                        message: "This permaban is no longer active".to_string(),
                    }),
                ));
            }
        }
        "timeban" => {
            let byond_now = byond_time_now();
            let row: Option<(i64,)> = query_as(
                "SELECT time_ban_expiration as `0` FROM players WHERE ckey = ? AND is_time_banned = 1",
            )
            .bind(ckey)
            .fetch_optional(&mut ***db)
            .await
            .unwrap_or(None);
            match row {
                Some((exp,)) if exp > byond_now => {}
                _ => {
                    return Err((
                        Status::BadRequest,
                        Json(AuthentikError {
                            error: "ban_not_active".to_string(),
                            message: "This time ban is no longer active".to_string(),
                        }),
                    ));
                }
            }
        }
        "jobban" => {
            let ban_id: i64 = reference_id.parse().map_err(|_| {
                (
                    Status::BadRequest,
                    Json(AuthentikError {
                        error: "invalid_reference".to_string(),
                        message: "Invalid job ban reference ID".to_string(),
                    }),
                )
            })?;
            let row: Option<(i64,)> = query_as(
                "SELECT id as `0` FROM player_job_bans \
                 WHERE id = ? AND (expiration IS NULL OR expiration > UNIX_TIMESTAMP())",
            )
            .bind(ban_id)
            .fetch_optional(&mut ***db)
            .await
            .unwrap_or(None);
            if row.is_none() {
                return Err((
                    Status::BadRequest,
                    Json(AuthentikError {
                        error: "ban_not_active".to_string(),
                        message: "This job ban is no longer active".to_string(),
                    }),
                ));
            }
        }
        "stickyban" => {
            let sticky_id: i32 = reference_id.parse().map_err(|_| {
                (
                    Status::BadRequest,
                    Json(AuthentikError {
                        error: "invalid_reference".to_string(),
                        message: "Invalid stickyban reference ID".to_string(),
                    }),
                )
            })?;
            let row: Option<(i32,)> = query_as(
                "SELECT s.id as `0` FROM stickyban s \
                 JOIN stickyban_matched_ckey mc ON mc.linked_stickyban = s.id \
                 WHERE s.id = ? AND s.active = 1 AND mc.ckey = ? AND mc.whitelisted = 0",
            )
            .bind(sticky_id)
            .bind(ckey)
            .fetch_optional(&mut ***db)
            .await
            .unwrap_or(None);
            if row.is_none() {
                return Err((
                    Status::BadRequest,
                    Json(AuthentikError {
                        error: "ban_not_active".to_string(),
                        message: "This stickyban is no longer active against you".to_string(),
                    }),
                ));
            }
        }
        "discord" => {
            if check_discord_ban_for_user(discord_id, config).await.is_none() {
                return Err((
                    Status::BadRequest,
                    Json(AuthentikError {
                        error: "ban_not_active".to_string(),
                        message: "You are not currently banned from the Discord server"
                            .to_string(),
                    }),
                ));
            }
        }
        _ => {
            return Err((
                Status::BadRequest,
                Json(AuthentikError {
                    error: "invalid_ban_type".to_string(),
                    message: format!("Unknown ban type '{}'", ban_type),
                }),
            ));
        }
    }
    Ok(())
}

async fn build_whisper_content(
    ckey: &str,
    ban_type: &str,
    reference_id: &str,
    discord_id: Option<&str>,
    config: &State<Config>,
    db: &mut Connection<Cmdb>,
) -> String {
    let mut content = String::new();
    content.push_str("## Ban Appeal Details\n\n");
    content.push_str(&format!("**Ckey:** {}\n", ckey));
    content.push_str(&format!("**Ban Type:** {}\n", ban_type));
    content.push_str(&format!("**Reference ID:** {}\n\n", reference_id));

    match ban_type {
        "permaban" => {
            if let Ok(Some(row)) = sqlx::query(
                "SELECT permaban_reason, permaban_date FROM players WHERE ckey = ?",
            )
            .bind(ckey)
            .fetch_optional(&mut ***db)
            .await
            {
                let reason: Option<String> = row.get("permaban_reason");
                let date: Option<String> = row.get("permaban_date");
                content.push_str("### Permaban Details\n\n");
                content.push_str(&format!(
                    "**Reason:** {}\n",
                    reason.unwrap_or_else(|| "N/A".to_string())
                ));
                content.push_str(&format!(
                    "**Date:** {}\n\n",
                    date.unwrap_or_else(|| "N/A".to_string())
                ));
            }
        }
        "timeban" => {
            if let Ok(Some(row)) = sqlx::query(
                "SELECT time_ban_reason, time_ban_date, time_ban_expiration FROM players WHERE ckey = ?",
            )
            .bind(ckey)
            .fetch_optional(&mut ***db)
            .await
            {
                let reason: Option<String> = row.get("time_ban_reason");
                let date: Option<String> = row.get("time_ban_date");
                let expiration: Option<i64> = row.get("time_ban_expiration");
                content.push_str("### Time Ban Details\n\n");
                content.push_str(&format!(
                    "**Reason:** {}\n",
                    reason.unwrap_or_else(|| "N/A".to_string())
                ));
                content.push_str(&format!(
                    "**Date:** {}\n",
                    date.unwrap_or_else(|| "N/A".to_string())
                ));
                if let Some(exp) = expiration {
                    content.push_str(&format!("**Expiration (BYOND time):** {}\n\n", exp));
                }
            }
        }
        "jobban" => {
            if let Ok(Some(row)) = sqlx::query(
                "SELECT text, date, expiration, role FROM player_job_bans WHERE id = ?",
            )
            .bind(reference_id)
            .fetch_optional(&mut ***db)
            .await
            {
                let text: String = row.get("text");
                let date: Option<String> = row.get("date");
                let role: String = row.get("role");
                content.push_str("### Job Ban Details\n\n");
                content.push_str(&format!("**Role:** {}\n", role));
                content.push_str(&format!("**Reason:** {}\n", text));
                content.push_str(&format!(
                    "**Date:** {}\n\n",
                    date.unwrap_or_else(|| "N/A".to_string())
                ));
            }
        }
        "stickyban" => {
            if let Ok(Some(row)) = sqlx::query(
                "SELECT identifier, reason, date FROM stickyban WHERE id = ?",
            )
            .bind(reference_id)
            .fetch_optional(&mut ***db)
            .await
            {
                let identifier: String = row.get("identifier");
                let reason: String = row.get("reason");
                let date: String = row.get("date");
                content.push_str("### Stickyban Details\n\n");
                content.push_str(&format!("**Identifier:** {}\n", identifier));
                content.push_str(&format!("**Reason:** {}\n", reason));
                content.push_str(&format!("**Date:** {}\n\n", date));
            }
        }
        "discord" => {
            content.push_str("### Discord Ban\n\n");
            let reason = check_discord_ban_for_user(discord_id, config)
                .await
                .unwrap_or_else(|| "No reason provided".to_string());
            content.push_str(&format!("**Reason:** {}\n\n", reason));
        }
        _ => {}
    }

    let player_id: Option<i64> = query("SELECT id FROM players WHERE ckey = ?")
        .bind(ckey)
        .fetch_optional(&mut ***db)
        .await
        .ok()
        .flatten()
        .map(|row| row.get("id"));

    if let Some(player_id) = player_id {
        let notes: Vec<NoteRow> = query_as(
            "SELECT text, date, is_ban, ban_time, admin_rank, note_category \
             FROM player_notes \
             WHERE player_id = ? AND is_confidential = 0 \
             ORDER BY date DESC",
        )
        .bind(player_id)
        .fetch_all(&mut ***db)
        .await
        .unwrap_or_default();

        if !notes.is_empty() {
            content.push_str("### Player Notes\n\n");
            for note in &notes {
                let note_type = if note.is_ban != 0 { "BAN" } else { "NOTE" };
                content.push_str(&format!(
                    "- **[{}]** ({}) [{}]: {}\n",
                    note_type,
                    note.date,
                    note.admin_rank,
                    note.text.as_deref().unwrap_or("N/A")
                ));
            }
        }
    }

    content
}

async fn check_discord_ban_for_user(
    discord_id: Option<&str>,
    config: &Config,
) -> Option<String> {
    let discord_id = discord_id?;
    let discord_config = config.discord_bot.as_ref()?;
    let guild_id_str = discord_config.primary_guild_id.as_ref()?;

    check_discord_ban(&discord_config.token, guild_id_str, discord_id)
        .await
        .ok()?
}

async fn check_discord_ban(
    token: &str,
    guild_id_str: &str,
    discord_id: &str,
) -> Result<Option<String>, String> {
    let http = Http::new(token);
    let guild_id = guild_id_str
        .parse::<u64>()
        .map_err(|e| format!("Invalid guild ID: {}", e))?;
    let user_id = discord_id
        .parse::<u64>()
        .map_err(|e| format!("Invalid discord ID: {}", e))?;

    let result = tokio::time::timeout(
        Duration::from_secs(5),
        http.get_ban(GuildId::new(guild_id), UserId::new(user_id)),
    )
    .await;

    match result {
        Err(_) => Ok(None),
        Ok(Ok(Some(ban))) => Ok(Some(
            ban.reason
                .unwrap_or_else(|| "No reason provided".to_string()),
        )),
        Ok(Ok(None)) => Ok(None),
        Ok(Err(_)) => Ok(None),
    }
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct DiscourseTopicCreated {
    id: i64,
    topic_id: i64,
}

async fn create_discourse_topic(
    client: &reqwest::Client,
    config: &DiscourseConfig,
    as_username: &str,
    title: &str,
    body: &str,
    category_id: i64,
) -> Result<DiscourseTopicCreated, String> {
    let url = format!("{}/posts.json", config.base_url.trim_end_matches('/'));

    // Create as system to bypass category permissions
    let response = client
        .post(&url)
        .header("Api-Key", &config.api_key)
        .header("Api-Username", &config.api_username)
        .json(&serde_json::json!({
            "title": title,
            "raw": body,
            "category": category_id,
        }))
        .send()
        .await
        .map_err(|e| format!("Failed to create Discourse topic: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("Discourse API returned error {}: {}", status, body));
    }

    let created: DiscourseTopicCreated = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse Discourse response: {}", e))?;

    // Transfer ownership to the user
    let change_owner_url = format!(
        "{}/t/{}/change-owner",
        config.base_url.trim_end_matches('/'),
        created.topic_id
    );
    let _ = client
        .post(&change_owner_url)
        .header("Api-Key", &config.api_key)
        .header("Api-Username", &config.api_username)
        .form(&[
            ("username", as_username.to_string()),
            ("post_ids[]", created.id.to_string()),
        ])
        .send()
        .await;

    // Lock the post
    let lock_url = format!(
        "{}/posts/{}/locked",
        config.base_url.trim_end_matches('/'),
        created.id
    );
    let _ = client
        .put(&lock_url)
        .header("Api-Key", &config.api_key)
        .header("Api-Username", &config.api_username)
        .form(&[("locked", "true")])
        .send()
        .await;

    Ok(created)
}

async fn create_discourse_whisper(
    client: &reqwest::Client,
    config: &DiscourseConfig,
    topic_id: i64,
    body: &str,
) -> Result<(), String> {
    let url = format!("{}/posts.json", config.base_url.trim_end_matches('/'));

    let response = client
        .post(&url)
        .header("Api-Key", &config.api_key)
        .header("Api-Username", &config.api_username)
        .json(&serde_json::json!({
            "topic_id": topic_id,
            "raw": body,
            "whisper": true,
            "archetype": "regular",
        }))
        .send()
        .await
        .map_err(|e| format!("Failed to create Discourse whisper: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!(
            "Discourse whisper API returned error {}: {}",
            status, body
        ));
    }

    Ok(())
}

async fn get_or_create_discourse_user(
    client: &reqwest::Client,
    config: &DiscourseConfig,
    external_id: &str,
    email: &str,
    username: &str,
) -> Result<String, String> {
    let url = format!(
        "{}/u/by-external/{}/{}.json",
        config.base_url.trim_end_matches('/'),
        urlencoding::encode(&config.provider_name),
        urlencoding::encode(external_id)
    );

    let response = client
        .get(&url)
        .header("Api-Key", &config.api_key)
        .header("Api-Username", &config.api_username)
        .send()
        .await
        .map_err(|e| format!("Failed to query Discourse: {}", e))?;

    if response.status().is_success() {
        #[derive(Deserialize)]
        struct UserResp {
            user: UserData,
        }
        #[derive(Deserialize)]
        struct UserData {
            username: String,
        }
        let user_resp: UserResp = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse Discourse user: {}", e))?;
        return Ok(user_resp.user.username);
    }

    let password: String = (0..32)
        .map(|_| {
            let idx = rand::random::<u8>() % 62;
            match idx {
                0..=9 => (b'0' + idx) as char,
                10..=35 => (b'a' + idx - 10) as char,
                _ => (b'A' + idx - 36) as char,
            }
        })
        .collect();

    let create_url = format!("{}/users.json", config.base_url.trim_end_matches('/'));

    let mut payload = serde_json::json!({
        "name": username,
        "username": username,
        "email": email,
        "password": password,
        "active": true,
        "approved": true,
    });

    payload.as_object_mut().unwrap().insert(
        "external_ids".to_string(),
        serde_json::json!({ &config.provider_name: external_id }),
    );

    let create_response = client
        .post(&create_url)
        .header("Api-Key", &config.api_key)
        .header("Api-Username", &config.api_username)
        .json(&payload)
        .send()
        .await
        .map_err(|e| format!("Failed to create Discourse user: {}", e))?;

    if !create_response.status().is_success() {
        let status = create_response.status();
        let body = create_response.text().await.unwrap_or_default();
        return Err(format!(
            "Failed to create Discourse user ({}): {}",
            status, body
        ));
    }

    Ok(username.to_string())
}
