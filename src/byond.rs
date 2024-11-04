use sqlx::{prelude::FromRow, Error};
use std::net::ToSocketAddrs;
use std::sync::Mutex;

use chrono::{DateTime, Duration, Utc};
use http2byond::ByondTopicValue;
use rocket::{serde::json::Json, State};
use rocket_db_pools::Connection;
use sqlx::query_as;

use crate::{Cmdb, Config};

#[derive(Default)]
pub struct ByondTopic {
    cached_status: Mutex<Option<GameResponse>>,
    cache_time: Mutex<Option<DateTime<Utc>>>,
}

#[derive(serde::Serialize)]
struct GameRequest {
    query: String,
    auth: Option<String>,
    source: String,
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct GameResponse {
    statuscode: i32,
    response: String,
    data: GameStatus,
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
#[serde(crate = "rocket::serde")]
pub struct GameStatus {
    mode: String,
    vote: i32,
    ai: i32,
    host: Option<String>,
    round_id: i32,
    players: i32,
    revision: String,
    admins: i32,
    gamestate: i32,
    map_name: String,
    security_level: String,
    round_duration: f32,
    time_dilation_current: f32,
    time_dilation_avg: f32,
    time_dilation_avg_slow: f32,
    time_dilation_avg_fast: f32,
    mcpu: f32,
    cpu: f32,
}

#[get("/")]
pub async fn round(
    cache: &State<ByondTopic>,
    config: &State<Config>,
) -> Option<Json<GameResponse>> {
    {
        match cache.cache_time.lock() {
            Ok(real) => {
                if real.is_some() {
                    let cache_time = real.unwrap();
                    let five_minutes_ago = chrono::Utc::now() - Duration::seconds(60);

                    if cache_time > five_minutes_ago {
                        return Some(Json(cache.cached_status.lock().unwrap().clone().unwrap()));
                    }
                }
            }
            Err(_) => {}
        };
    }

    let topic_config_option = config.topic.clone();

    let topic_config = match topic_config_option {
        Some(config_result) => config_result,
        None => return None,
    };

    let topic = serde_json::to_string(&GameRequest {
        query: "status".to_string(),
        auth: Some(topic_config.auth.unwrap()),
        source: "cm-api-rs".to_string(),
    })
    .unwrap();

    let byond = match http2byond::send_byond(
        &topic_config
            .host
            .unwrap()
            .to_socket_addrs()
            .unwrap()
            .next()
            .unwrap(),
        &topic,
    ) {
        Ok(byond) => byond,
        Err(_) => return None,
    };

    let mut byond_string = match byond {
        ByondTopicValue::String(string) => string,
        ByondTopicValue::None => return None,
        ByondTopicValue::Number(_) => return None,
    };

    byond_string.pop();

    let byond_value = serde_json::from_str::<GameResponse>(&byond_string);

    let byond_json = match byond_value {
        Ok(value) => value,
        Err(error) => panic!("{error:?} {byond_string}"),
    };

    *cache.cached_status.lock().unwrap() = Some(byond_json.clone());
    *cache.cache_time.lock().unwrap() = Some(chrono::Utc::now());

    Some(Json(byond_json))
}

#[derive(serde::Serialize, FromRow)]
pub struct Round {
    id: i32,
}

#[get("/Recent")]
pub async fn recent(mut db: Connection<Cmdb>) -> Json<Vec<Round>> {
    let rounds: Result<Vec<Round>, Error> =
        query_as("SELECT * FROM mc_round ORDER BY id DESC LIMIT ?")
            .bind(10)
            .fetch_all(&mut **db)
            .await;

    match rounds {
        Ok(rounds) => Json(rounds),
        Err(_) => Json(Vec::new()),
    }
}
