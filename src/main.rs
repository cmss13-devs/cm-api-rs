use rocket::{
    fairing::AdHoc,
    figment::{
        providers::{Format, Serialized, Toml},
        Figment,
    },
};
use rocket_db_pools::{sqlx::MySqlPool, Database};
use serde::{Deserialize, Serialize};

#[macro_use]
extern crate rocket;

mod admin;
mod byond;
mod connections;
mod logging;
mod player;
mod stickyban;

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

    rocket::custom(figment)
        .manage(byond::ByondTopic::default())
        .attach(Cmdb::init())
        .attach(AdHoc::config::<Config>())
        .mount(
            "/User",
            routes![
                player::index,
                player::id,
                player::new_note,
                player::applied_notes
            ],
        )
        .mount("/Round", routes![byond::round, byond::recent])
        .mount(
            "/Connections",
            routes![
                connections::ip,
                connections::cid,
                connections::ckey,
                connections::connection_history_by_cid,
                connections::connection_history_by_ip
            ],
        )
        .mount(
            "/Stickyban",
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
}
