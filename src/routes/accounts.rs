//! Accounts routes, mounted at "/accounts"

use std::sync::Arc;

use rocket::{get, post};
use rocket::form::{Form, Contextual, FromForm, Options, Context};
use rocket::http::CookieJar;
use rocket::request::FlashMessage;
use rocket::response::Redirect;
use rocket::uri;
use rocket_db_pools::Connection;
use rocket_dyn_templates::Template;
use serde::{Deserialize, Serialize};

use crate::auth;
use crate::database::AppDb;
use crate::jobs::{Message, PostgresQueue};
use crate::models::Account;
use crate::response::{flash_context, RenderOrRedirect};
use crate::token::UserToken;

#[derive(Clone, Debug, Default, Deserialize, FromForm, Serialize)]
pub struct NewAccount<'v> {
    #[serde(skip)]
    pub policy: crate::passwords::PasswordPolicy,
    #[field(validate = len(1..))]
    pub name: &'v str,
    #[field(validate = contains('@').or_else(msg!("invalid email address")))]
    pub email: &'v str,
    #[field(validate = len(8..))]
    pub password: &'v str,
}

#[derive(Debug, FromForm)]
pub struct NewAccountSubmit<'v> {
    account: NewAccount<'v>
}

#[get("/register")]
pub async fn registration_form<'a>(cookies: &CookieJar<'a>, flash: Option<FlashMessage<'_>>) ->  RenderOrRedirect {
    if auth::is_authenticated(cookies) {
        return Redirect::to("/dashboard").into()
    }

    let context = Context::default();
    Template::render("accounts/register", &context).into()
}

#[post("/register", data = "<form>")]
pub async fn create_account<'a>(
    form: Form<Contextual<'a, NewAccountSubmit<'a>>>,
    mut db: Connection<AppDb>,
    queue: PostgresQueue,
    cookies: &CookieJar<'a>,
    flash: Option<FlashMessage<'_>>,
) -> RenderOrRedirect {
    if auth::is_authenticated(cookies) {
        return Redirect::to("/dashboard").into()
    }

    match &form.value {
        // Form parsed successfully. value is the `NewAccountSubmit`.
        Some(value) => {
            let conn: &mut sqlx::PgConnection = db.as_mut();
            let _ignore = match Account::register(&value.account, conn).await {
                Ok(uid) =>
                    queue.push(Message::SendVerifyAccountEmail(uid), None).await,
                Err(e) => {
                    rocket::error!("Error with registering: {:?}", e);
                    queue.push(Message::SendAccountOddRegisterAttemptEmail(value.account.email.to_string()), None).await
                }
            };

            // No matter what, just appear as if it worked.
            Redirect::to("/accounts/verify").into()
        },
        None => Template::render("accounts/register", &form.context).into(),
    }
}

pub fn default_redirect_path() -> String {
    "/".to_owned()
}

#[derive(Clone, Debug, Default, Deserialize, FromForm, Serialize)]
pub struct LoginData {
    pub email: String,
    pub password: String, // not checking strength, just presence
    #[serde(default = "default_redirect_path")]
    pub redirect: String,
}

#[get("/login")]
pub async fn login_form<'a>(flash: Option<FlashMessage<'_>>) -> Template {
    let context = flash_context(flash);
    Template::render("accounts/login", &context.into_json())
}

#[post("/login", data = "<form>")]
pub async fn authenticate<'a>(form: Form<LoginData>) -> RenderOrRedirect {
    let context = flash_context(None);
    RenderOrRedirect::Template(
        Template::render("accounts/reset_password/requested", &context.into_json()))
}

#[post("/logout")]
pub async fn logout() -> Redirect {
    // request.get_session().clear();
    Redirect::to(uri!("/"))
}

#[get("/verify/<token>")]
pub async fn verify_with_token<'a>(db: Connection<AppDb>, flash: Option<FlashMessage<'_>>, token: UserToken) -> Template {
    let context = flash_context(flash);
    Template::render("accounts/verify", &context.into_json())
}

/// Just renders a standard "Check your email and verify" page.
#[get("/verify")]
pub async fn verify<'a>(flash: Option<FlashMessage<'_>>) -> Template {
    let context = flash_context(flash);
    Template::render("accounts/verify/index", &context.into_json())
}

#[derive(Clone, Debug, Default, Deserialize, FromForm, Serialize)]
pub struct ResetPasswordData {
    pub email: String,
}

#[get("/reset")]
pub async fn reset_password_form<'a>(flash: Option<FlashMessage<'_>>) -> Template {
    let context = flash_context(flash);
    Template::render("accounts/reset_password/index", &context.into_json())
}

#[post("/reset", data = "<form>")]
pub async fn request_reset<'a>(form: Form<ResetPasswordData>) -> RenderOrRedirect {
    let context = flash_context(None);
    RenderOrRedirect::Template(
        Template::render("accounts/reset_password/requested", &context.into_json()))
}

#[derive(Clone, Debug, Default, Deserialize, FromForm, Serialize)]
pub struct ChangePasswordData {
    // Unused in rendering, but stored here to enable password
    // checking with relative values.
    pub name: Option<String>,
    pub email: Option<String>,

    pub password: String,
    pub password_confirm: String,
}

impl ChangePasswordData {
    pub fn new() -> Self {
        Default::default()
    }
}

#[get("/reset/<token>")]
pub async fn reset_password_with_token<'a>(db: Connection<AppDb>, flash: Option<FlashMessage<'_>>, token: UserToken) -> Template {
    let mut context = flash_context(None);
    if let Ok(_account) = Account::validate_token(&token, db).await {
        context.insert("form", &ChangePasswordData::new());
        context.insert("uidb64", &token.uidb64);
        context.insert("ts", &token.ts);
        context.insert("token", &token.token);

        Template::render("accounts/reset_password/change_password", context.into_json())
    } else {
        Template::render("accounts/invalid_token", context.into_json())
    }
}