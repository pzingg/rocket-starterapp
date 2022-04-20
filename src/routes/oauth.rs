//! Routes for OAuth2

use rocket::form::FromForm;
use serde::{Deserialize, Serialize};

use crate::oauth;

fn default_provider() -> String {
  oauth::client::DEFAULT_PROVIDER.to_string()
}

#[derive(Clone, Debug, Default, Deserialize, FromForm, Serialize)]
pub struct OAuthLoginData {
  #[serde(default = "default_provider")]
  pub provider: String,
  pub email_hint: bool,
  pub email: String,
}

impl OAuthLoginData {
  pub fn new(provider: &str) -> Self {
      let provider = if oauth::client::valid_provider(provider) {
          provider
      } else {
          oauth::client::DEFAULT_PROVIDER
      };

      let hints = oauth::client::provider_hints(provider);
      OAuthLoginData {
          provider: provider.to_string(),
          email_hint: hints.map_or(false, |hint| hint.uses_email_hint),
          ..Default::default()
      }
  }
}

#[derive(Clone, Debug, Default, Deserialize, FromForm, Serialize)]
pub struct LinkIdentityData {
    pub provider: String,
    pub username: String,
    pub name: String,
    pub email: String,
}
