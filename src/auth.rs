use anyhow::anyhow;
use rocket::http::{Cookie, CookieJar};
use serde_json;

use crate::models::User;
use crate::error;

/// `Authentication` is kind of a request guard - it returns a Future which will resolve
/// with either the current authenticated user, or "error" out if the user has no session data
/// that'd tie them to a user profile, or if the session cache can't be read, or if the database
/// has issues, or... pick your poison I guess.

#[inline(always)]
pub fn is_authenticated(cookies: &CookieJar) -> bool {
    cookies.get_private("sku").is_some()
}

pub fn set_user(cookies: &CookieJar, user: User) {
    cookies.add_private(
        Cookie::new("sku", serde_json::json!(user).to_string()));
}

pub fn clear_user(cookies: &CookieJar) {
    cookies.remove_private(Cookie::named("sku"));
}

pub fn user(cookies: &CookieJar) -> error::Result<User> {
    match cookies.get_private("sku") {
        Some(cookie) => serde_json::from_str::<User>(cookie.value())
            .map_err(|_| error::Error::from(anyhow!("corrupt session cookie"))),
        None => Ok(User::default()),
    }
}
