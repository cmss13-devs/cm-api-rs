use rocket::fairing::{Fairing, Info, Kind};
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

mod admin;
mod byond;
mod connections;
mod logging;
mod player;
mod stickyban;
mod ticket;

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
struct Config {
    topic: Option<TopicConfig>,
    logging: Option<LoggingConfig>,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            topic: None,
            logging: None,
        }
    }
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

    let mut base_url = "/api";
    if cfg!(debug_assertions) {
        base_url = "";
    }

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
                player::applied_notes
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
}
