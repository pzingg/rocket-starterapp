use std::env;

use anyhow::anyhow;
use serde::{Deserialize, Serialize};
use tera::Context;

use crate::email::Email;
use crate::error;
use crate::jobs::{JobRun, PostgresQueue};
use crate::models::Account;
use crate::token::OneTimeUseTokenGenerator;

#[derive(Debug, Serialize, Deserialize)]
pub struct SendVerifyAccountEmail {
    pub to: i32,
}

pub fn build_context(verify_url: &str) -> Context {
    let mut context = Context::new();
    context.insert("action_url", &verify_url);
    context
}

#[rocket::async_trait]
impl JobRun for SendVerifyAccountEmail {
    async fn run(self, state: &PostgresQueue) -> error::Result<()> {
        let mut conn_result = state.pool.acquire().await;
        let conn = conn_result
            .as_mut()
            .map_err(|e| error::Error::from(anyhow!("failed to acquire connection")))?;

        let account = Account::get(self.to, conn)
            .await
            .map_err(|e| anyhow!("Error fetching account for verification: {:?}", e))?;

        let domain = env::var("JELLY_DOMAIN").expect("No JELLY_DOMAIN value set!");

        let verify_url = format!(
            "{}/accounts/verify/{}-{}",
            domain,
            base64_url::encode(&format!("{}", account.id)),
            account
                .create_reset_token()
                .map_err(|e| { anyhow!("Error creating verification token: {:?}", e) })?
        );

        let email = Email::new(
            "verify-account",
            &[account.email],
            "Verify your new account",
            build_context(&verify_url),
            state.templates.clone(),
        );

        email?.send()?;

        Ok(())
    }
}
