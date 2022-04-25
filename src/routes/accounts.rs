//! Accounts routes, mounted at "/accounts"

use rocket::form::{Context, Contextual, Form, FromForm};
use rocket::http::CookieJar;
use rocket::request::FlashMessage;
use rocket::response::Redirect;
use rocket::uri;
use rocket::{get, post};
use rocket_db_pools::Connection;
use rocket_dyn_templates::Template;
use serde::{Deserialize, Serialize};

use crate::auth;
use crate::database::AppDb;
use crate::jobs::{Message, PostgresQueue};
use crate::models::{Account, User};
use crate::passwords::{validate_pattern, validate_strength, REGEX_ANH,
    PasswordScore::SafelyUnguessable};
use crate::response::RenderOrRedirect;
use crate::token::UserToken;

#[derive(Clone, Debug, Default, Deserialize, FromForm, Serialize)]
pub struct NewAccount<'v> {
    #[field(validate = len(1..))]
    pub name: &'v str,
    #[field(validate = contains('@').or_else(msg!("invalid email address")))]
    pub email: &'v str,
    #[field(validate = len(8..))]
    #[field(validate = validate_pattern(&REGEX_ANH))]
    #[field(validate = validate_strength(SafelyUnguessable, vec![self.name, self.email].as_slice()))]
    pub password: &'v str,
}

#[derive(Debug, FromForm)]
pub struct NewAccountSubmit<'v> {
    account: NewAccount<'v>,
}

/// Show the registration form.
#[get("/register")]
pub async fn registration_form<'a>(
    // flash: Option<FlashMessage<'_>>,
    cookies: &CookieJar<'a>,
) -> RenderOrRedirect {
    if auth::is_authenticated(cookies) {
        return Redirect::to(uri!("/dashboard")).into();
    }

    let context = Context::default();
    Template::render("accounts/register", &context).into()
}

/// POST-handler for registering a new account.
#[post("/register", data = "<form>")]
pub async fn create_account<'a>(
    // flash: Option<FlashMessage<'_>>,
    cookies: &CookieJar<'a>,
    mut db: Connection<AppDb>,
    form: Form<Contextual<'a, NewAccountSubmit<'a>>>,
    queue: PostgresQueue,
) -> RenderOrRedirect {
    if auth::is_authenticated(cookies) {
        return Redirect::to(uri!("/dashboard")).into();
    }

    match &form.value {
        // Form parsed successfully. value is the `NewAccountSubmit`.
        Some(value) => {
            let conn: &mut sqlx::PgConnection = db.as_mut();
            let _ignore = match Account::register(&value.account, conn).await {
                Ok(email) => queue.push(Message::SendVerifyAccountEmail(email), None).await,
                Err(e) => {
                    rocket::error!("Error with registering: {:?}", e);
                    queue
                        .push(
                            Message::SendAccountOddRegisterAttemptEmail(
                                value.account.email.to_string(),
                            ),
                            None,
                        )
                        .await
                }
            };

            // No matter what, just appear as if it worked.
            Redirect::to(uri!("/accounts/verify")).into()
        }
        None => Template::render("accounts/register", &form.context).into(),
    }
}

#[derive(Clone, Debug, Default, Deserialize, FromForm, Serialize)]
pub struct LoginData<'v> {
    #[field(validate = contains('@').or_else(msg!("invalid email address")))]
    pub email: &'v str,
    #[field(validate = len(1..))]
    pub password: &'v str,
}

#[derive(Debug, FromForm)]
pub struct LoginSubmit<'v> {
    account: LoginData<'v>,
}

/// Show the login form.
#[get("/login")]
pub async fn login_form<'a>(
    // flash: Option<FlashMessage<'_>>,
    cookies: &CookieJar<'a>,
) -> RenderOrRedirect {
    if auth::is_authenticated(cookies) {
        return Redirect::to(uri!("/dashboard")).into();
    }

    let context = Context::default();
    Template::render("accounts/login", &context).into()
}

/// POST-handler for logging in.
#[post("/login", data = "<form>")]
pub async fn authenticate<'a>(
    // flash: Option<FlashMessage<'_>>,
    cookies: &CookieJar<'a>,
    mut db: Connection<AppDb>,
    form: Form<Contextual<'a, LoginSubmit<'a>>>,
) -> RenderOrRedirect {
    if auth::is_authenticated(cookies) {
        return Redirect::to(uri!("/dashboard")).into();
    }

    if let Some(value) = &form.value {
        // Form parsed successfully. value is the `LoginSubmit`.
        let conn: &mut sqlx::PgConnection = db.as_mut();
        if let Ok(user) = Account::authenticate(&value.account, conn).await {
            let _ignore = Account::update_last_login(user.id, conn).await;
            auth::set_user(cookies, user);
            return Redirect::to(uri!("/dashboard")).into();
        }
    }

    Template::render("accounts/login", &form.context).into()
}

/// Just renders a standard "Check your email and verify" page.
#[post("/logout")]
pub async fn logout<'a>(
    // flash: Option<FlashMessage<'_>>,
    cookies: &CookieJar<'a>,
) -> Redirect {
    auth::clear_user(cookies);
    Redirect::to(uri!("/"))
}

/// Just renders a standard "Check your email and verify" page.
#[get("/verify")]
pub async fn verify<'a>(
    // flash: Option<FlashMessage<'_>>
) -> Template {
    let context = Context::default();
    Template::render("accounts/verify/index", &context)
}

/// Given a link (of form {uidb64}-{ts}-{token}), verifies the
/// token and user, signs them in, and redirects to the dashboard.
///
/// In general, we do not want to leak information, so any errors here
/// should simply report as "invalid or expired".
#[get("/verify/<token>")]
pub async fn verify_with_token<'a>(
    // flash: Option<FlashMessage<'_>>,
    cookies: &CookieJar<'a>,
    mut db: Connection<AppDb>,
    token: UserToken,
) -> RenderOrRedirect {
    let conn: &mut sqlx::PgConnection = db.as_mut();
    match Account::validate_token(&token, conn).await {
        Ok(account) => {
            let _ignore = Account::mark_verified(account.id, conn).await;

            auth::set_user(cookies, User {
                id: account.id,
                name: account.name,
                is_admin: account.is_admin,
                is_anonymous: false,
            });

            Redirect::to(uri!("/dashboard")).into()
        },
        Err(_) => {
           let context = Context::default();
            Template::render("accounts/invalid_token", &context).into()
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, FromForm, Serialize)]
pub struct SendLinkData<'v> {
    #[field(validate = contains('@').or_else(msg!("invalid email address")))]
    pub email: &'v str,
}

#[derive(Debug, FromForm)]
pub struct SendLinkSubmit<'v> {
    pub account: SendLinkData<'v>,
}

/// Just renders a standard "Enter Your Email" password reset page.
#[get("/resend")]
pub async fn resend_link_form<'a>(
    // flash: Option<FlashMessage<'_>>
) -> Template {
    let context = Context::default();
    Template::render("accounts/resend_link/index", &context)
}

/// Processes the reset password request, which ultimately just passes
/// it to a background worker to execute - we do this to avoid any timing
/// attacks re: leaking user existence.
#[post("/resend", data = "<form>")]
pub async fn resend_link<'a>(
    queue: PostgresQueue,
    form: Form<Contextual<'a, SendLinkSubmit<'a>>>
) -> Template {
    match &form.value {
        Some(value) => {

            let _ignore = queue
                .push(
                    Message::SendVerifyAccountEmail(
                        value.account.email.to_string(),
                    ),
                    None,
                )
                .await;

            let context = Context::default();
            Template::render("accounts/resend_link/requested", &context)
        },
        None =>
            Template::render("accounts/resend_link/index", &form.context),
    }
}

/// Just renders a standard "Enter Your Email" password reset page.
#[get("/reset")]
pub async fn reset_password_form<'a>(
    // flash: Option<FlashMessage<'_>>
) -> Template {
    let context = Context::default();
    Template::render("accounts/reset_password/index", &context)
}

/// Processes the reset password request, which ultimately just passes
/// it to a background worker to execute - we do this to avoid any timing
/// attacks re: leaking user existence.
#[post("/reset", data = "<form>")]
pub async fn request_reset<'a>(
    queue: PostgresQueue,
    form: Form<Contextual<'a, SendLinkSubmit<'a>>>
) -> Template {
    match &form.value {
        Some(value) => {
            let _ignore = queue
                .push(
                    Message::SendResetPasswordEmail(
                        value.account.email.to_string(),
                    ),
                    None,
                )
                .await;

            let context = Context::default();
            Template::render("accounts/reset_password/requested", &context)
        },
        None =>
            Template::render("accounts/reset_password/index", &form.context),
    }
}

#[derive(Clone, Debug, Default, Deserialize, FromForm, Serialize)]
pub struct ChangePasswordData<'v> {
    pub name: &'v str,
    pub email: &'v str,
    #[field(validate = len(8..))]
    #[field(validate = validate_pattern(&REGEX_ANH))]
    #[field(validate = validate_strength(SafelyUnguessable, vec![self.name, self.email].as_slice()))]
    pub password: &'v str,
    #[field(validate = len(1..))]
    #[field(validate = eq(self.password))]
    pub password_confirm: &'v str,
}

#[derive(Debug, FromForm)]
pub struct ChangePasswordSubmit<'v> {
    pub account: ChangePasswordData<'v>
}

/// Given a link (of form {uidb64}-{ts}-{token}), verifies the
/// token and user, and presents them a change password form.
///
/// In general, we do not want to leak information, so any errors here
/// should simply report as "invalid or expired". It's a bit verbose, but
/// such is Rust for this type of thing. Write it once and move on. ;P
#[get("/reset/<token>")]
pub async fn reset_password_with_token<'a>(
    // flash: Option<FlashMessage<'_>>,
    mut db: Connection<AppDb>,
    token: UserToken,
) -> Template {
    let conn: &mut sqlx::PgConnection = db.as_mut();
    match Account::validate_token(&token, conn).await {
        Ok(account) => {
            let context = serde_json::json!({
                "token": token.to_string(),
                "values": {
                    "account.name": [account.name],
                    "account.email": [account.email],
                },
                "errors": [],
                "form_errors": [],
                "data_fields": [],
            });

            Template::render(
                "accounts/reset_password/change_password",
                context
            )
        },
        Err(_) => {
            let context = Context::default();
            Template::render("accounts/invalid_token", &context)
        }
    }
}

/// Verifies the password is fine, and if so, signs the user in and redirects
/// them to the dashboard with a flash message.
#[post("/reset/<token>", data = "<form>")]
pub async fn reset_password<'a>(
    // flash: Option<FlashMessage<'_>>,
    cookies: &CookieJar<'a>,
    mut db: Connection<AppDb>,
    token: UserToken,
    form: Form<Contextual<'a, ChangePasswordSubmit<'a>>>,
    queue: PostgresQueue,
) -> RenderOrRedirect {
    let conn: &mut sqlx::PgConnection = db.as_mut();
    match Account::validate_token(&token, conn).await {
        Ok(account) => {
            // Note! This is a case where we need to fetch the user ahead of form validation.
            // While it would be nice to avoid the DB hit, validating that their password is secure
            // requires pulling some account values...
            match &form.value {
                Some(value) => {
                    let _ignore = Account::update_password_and_last_login(account.id, value.account.password, conn).await;
                    let _ignore = queue.push(
                        Message::SendResetPasswordEmail(
                            account.email.clone(),
                        ),
                        None,
                    ).await;

                    auth::set_user(cookies, User {
                        id: account.id,
                        name: account.name,
                        is_admin: account.is_admin,
                        is_anonymous: false,
                    });

                    // request.flash("Password Reset", "Your password was successfully reset.")?;
                    Redirect::to(uri!("/dashboard")).into()
                },
                None => {
                    Template::render("accounts/reset_password/change_password", &form.context).into()
                },
            }

        },
        Err(_) => {
            // request.flash("Password Reset", "The link you used is invalid. Please request another password reset.")?;
            Redirect::to(uri!("/")).into()
        }
    }
}
