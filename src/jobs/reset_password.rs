use std::env;

use crate::token::OneTimeUseTokenGenerator;
use anyhow::anyhow;
use serde::{Deserialize, Serialize};
use tera::Context;

use crate::email::Email;
use crate::error;
use crate::models::Account;
use crate::jobs::{JobRun, PostgresQueue};

#[derive(Debug, Serialize, Deserialize)]
pub struct SendResetPasswordEmail {
    pub to: String,
}

pub fn build_context(verify_url: &str) -> Context {
    let mut context = Context::new();
    context.insert("action_url", verify_url);
    context
}

#[rocket::async_trait]
impl JobRun for SendResetPasswordEmail {
    async fn run(self, state: &PostgresQueue) -> error::Result<()> {
        let mut conn_result = state.pool.acquire().await;
        let conn = conn_result
            .as_mut()
            .map_err(|e| error::Error::from(anyhow!("failed to acquire connection")))?;

        let account = Account::get_by_email(&self.to, conn)
            .await
            .map_err(|e| anyhow!("Error fetching account for password reset: {:?}", e))?;

        let domain = env::var("JELLY_DOMAIN").expect("No JELLY_DOMAIN value set!");

        let verify_url = format!(
            "{}/accounts/reset/{}-{}",
            domain,
            base64_url::encode(&format!("{}", account.id)),
            account
                .create_reset_token()
                .map_err(|e| { anyhow!("Error creating verification token: {:?}", e) })?
        );

        let email = Email::new(
            "reset-password",
            &[account.email],
            "Reset your account password",
            build_context(&verify_url),
            state.templates.clone(),
        );

        email?.send()?;

        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SendPasswordWasResetEmail {
    pub to: String,
}

#[rocket::async_trait]
impl JobRun for SendPasswordWasResetEmail {
    async fn run(self, state: &PostgresQueue) -> error::Result<()> {
        let email = Email::new(
            "password-was-reset",
            &[self.to],
            "Your Password Was Reset",
            Context::new(),
            state.templates.clone(),
        );

        email?.send()?;

        Ok(())
    }
}
