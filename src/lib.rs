use rocket::{routes, Build, Rocket};
use rocket_db_pools::Database;
use rocket_dyn_templates::Template;

pub mod auth;
pub mod database;
pub mod email;
pub mod error;
pub mod jobs;
pub mod models;
#[cfg(feature = "oauth")]
pub mod oauth;
pub mod response;
pub mod routes;
pub mod passwords;
pub mod token;

use email::common::Configurable;

pub fn rocket() -> Rocket<Build> {
    email::Email::check_conf();

    rocket::build()
        .attach(database::AppDb::init())
        .attach(Template::fairing())
        .attach(jobs::BackgroundQueue::fairing())
        .mount("/accounts", routes![
            routes::accounts::registration_form,
            routes::accounts::create_account,
            routes::accounts::login_form,
            routes::accounts::authenticate,
            routes::accounts::logout,
            routes::accounts::verify_with_token,
            routes::accounts::verify
        ])
        .mount("/", routes![routes::home::home])
}
