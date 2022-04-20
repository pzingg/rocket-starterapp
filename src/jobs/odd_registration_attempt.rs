use std::env;

use anyhow::anyhow;
use serde::{Deserialize, Serialize};
use tera::Context;

use crate::email::Email;
use crate::error;
use crate::jobs::{JobRun, PostgresQueue};
use crate::models::Account;

/// An email that gets sent if a user attempts to register
/// under an already registered email. We don't want to say
/// "this email exists already", as that reveals that a user has
/// registered for this service.
///
/// Instead we'll just send the registered account an email asking
/// if they meant to reset their password, and display to the user
/// registering the standard "verify" flow.
#[derive(Debug, Serialize, Deserialize)]
pub struct SendAccountOddRegisterAttemptEmail {
    pub to: String,
}

// TODO: Use Figment for configuration.
pub fn build_context(name: &str) -> Context {
    let mut context = Context::new();
    context.insert("name", name);
    context.insert(
        "action_url",
        &format!(
            "{}/accounts/reset",
            env::var("JELLY_DOMAIN").expect("JELLY_DOMAIN not set?")
        ),
    );
    context
}

#[rocket::async_trait]
impl JobRun for SendAccountOddRegisterAttemptEmail {
    async fn run(self, state: &PostgresQueue) -> error::Result<()> {
        let mut conn_result = state.pool.acquire().await;
        let conn = conn_result
            .as_mut()
            .map_err(|_| error::Error::from(anyhow!("failed to acquire connection")))?;

        let name = Account::fetch_name_from_email(&self.to, conn)
            .await
            .map_err(|e| {
                anyhow!(
                    "Error fetching user name for odd registration attempt: {:?}",
                    e
                )
            })?;

        let email = Email::new(
            "odd-registration-attempt",
            &[self.to],
            "Did you want to reset your password?",
            build_context(&name),
            state.templates.clone(),
        );

        email?.send()?;

        Ok(())
    }
}
