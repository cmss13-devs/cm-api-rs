#![forbid(unsafe_code)]

use rocket::fairing::{Fairing, Info, Kind};
use rocket::figment::value::Value;
use rocket::http::Header;
use rocket::{
    fairing::AdHoc,
    figment::{
        providers::{Format, Serialized, Toml},
        Figment,
    },
};
use rocket::{Request, Response};
use rocket_db_pools::{sqlx::MySqlPool, Database};
use serde::{Deserialize, Serialize};

#[macro_use]
extern crate rocket;

pub struct CORS;

mod admin;
mod byond;
mod connections;
mod logging;
mod new_players;
mod player;
mod stickyban;
mod ticket;
mod twofactor;
mod whitelist;

#[rocket::async_trait]
impl Fairing for CORS {
    fn info(&self) -> Info {
        Info {
            name: "Add CORS headers to responses",
            kind: Kind::Response,
        }
    }

    async fn on_response<'r>(&self, _request: &'r Request<'_>, response: &mut Response<'r>) {
        response.set_header(Header::new("Access-Control-Allow-Origin", "*"));
        response.set_header(Header::new(
            "Access-Control-Allow-Methods",
            "POST, GET, PATCH, OPTIONS",
        ));
        response.set_header(Header::new("Access-Control-Allow-Headers", "*"));
        response.set_header(Header::new("Access-Control-Allow-Credentials", "true"));
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct TopicConfig {
    host: Option<String>,
    auth: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct LoggingConfig {
    webhook: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
#[derive(Default)]
struct Config {
    topic: Option<TopicConfig>,
    logging: Option<LoggingConfig>,
}

#[derive(Database)]
#[database("cmdb")]
pub struct Cmdb(MySqlPool);

#[launch]
fn rocket() -> _ {
    let figment = Figment::from(rocket::Config::default())
        .merge(Serialized::defaults(Config::default()))
        .merge(Toml::file("Rocket.toml").nested())
        .merge(Toml::file("Api.toml"));

    let base_url: String = match figment.find_value("host.base_url") {
        Ok(value) => match value {
            Value::String(_, val) => val,
            _ => panic!("base_url must be a string."),
        },
        Err(_) => "/".to_string(),
    };

    rocket::custom(figment)
        .manage(byond::ByondTopic::default())
        .attach(Cmdb::init())
        .attach(AdHoc::config::<Config>())
        .attach(CORS)
        .mount(
            format!("{}/User", base_url),
            routes![
                player::index,
                player::id,
                player::new_note,
                player::applied_notes,
                player::get_playtime,
                player::get_recent_playtime,
                player::get_total_playtime,
            ],
        )
        .mount(
            format!("{}/Round", base_url),
            routes![byond::round, byond::recent],
        )
        .mount(
            format!("{}/Connections", base_url),
            routes![
                connections::ip,
                connections::cid,
                connections::ckey,
                connections::connection_history_by_cid,
                connections::connection_history_by_ip
            ],
        )
        .mount(
            format!("{}/Stickyban", base_url),
            routes![
                stickyban::all_stickybans,
                stickyban::whitelist,
                stickyban::get_matched_cids,
                stickyban::get_matched_ckey,
                stickyban::get_matched_ip,
                stickyban::get_all_cid,
                stickyban::get_all_ckey,
                stickyban::get_all_ip
            ],
        )
        .mount(
            format!("{}/Ticket", base_url),
            routes![ticket::get_tickets_by_round_id, ticket::get_tickets_by_user],
        )
        .mount(
            format!("{base_url}/Whitelist"),
            routes![whitelist::get_all_whitelistees],
        )
        .mount(
            format! {"{}/NewPlayers", base_url},
            routes![new_players::get_new_players],
        )
        .mount(
            format!("{}/TwoFactor", base_url),
            routes![twofactor::twofactor_validate],
        )
}
