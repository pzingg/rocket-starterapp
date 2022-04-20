//! Home routes, mounted at "/"

use rocket::get;
use rocket::request::FlashMessage;
use rocket_dyn_templates::Template;
use crate::response::flash_context;

#[get("/")]
pub async fn home<'a>(flash: Option<FlashMessage<'_>>) -> Template {
    let context = flash_context(flash);
    Template::render("index", &context.into_json())
}
