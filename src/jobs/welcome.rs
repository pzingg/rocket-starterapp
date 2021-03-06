use std::env::var;

use anyhow::anyhow;
use serde::{Deserialize, Serialize};
use tera::Context;

use crate::email::Email;
use crate::error;
use crate::jobs::{JobRun, PostgresQueue};
use crate::models::Account;

/// A job for sending a Welcome email, generally dispatched after an account
/// has been verified.
#[derive(Debug, Serialize, Deserialize)]
pub struct SendWelcomeAccountEmail {
    pub to: String,
}

pub fn build_context(name: &str) -> Context {
    let mut context = Context::new();
    context.insert("name", name);
    context.insert(
        "help_url",
        &var("JELLY_HELP_URL").expect("JELLY_HELP_URL not set?"),
    );
    context
}

#[rocket::async_trait]
impl JobRun for SendWelcomeAccountEmail {
    async fn run(self, state: &PostgresQueue) -> error::Result<()> {
        let mut conn_result = state.pool.acquire().await;
        let conn = conn_result
            .as_mut()
            .map_err(|_| error::Error::from(anyhow!("failed to acquire connection")))?;

        let account = Account::get_by_email(&self.to, conn)
            .await
            .map_err(|e| anyhow!("Error fetching user name/email: {:?}", e))?;

        let email = Email::new(
            "welcome",
            &[account.email],
            "Welcome to the service",
            build_context(&account.name),
            state.templates.clone(),
        );

        email?.send()?;

        Ok(())
    }
}
