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
mod player;

#[derive(Debug, Deserialize, Serialize, Clone)]
struct TopicConfig {
    host: Option<String>,
    auth: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
struct Config {
    topic: Option<TopicConfig>,
}

impl Default for Config {
    fn default() -> Config {
        Config { topic: None }
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
}
