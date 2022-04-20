use anyhow::{anyhow, Context};
use serde::Serialize;

use super::common::env_exists_and_not_empty;
pub use super::common::Email;

use crate::error;

#[derive(Serialize, Debug)]
struct EmailAddress<'a> {
    email: &'a String,
}

#[derive(Serialize, Debug)]
struct Personalization<'a> {
    to: Vec<EmailAddress<'a>>,
}

#[derive(Serialize, Debug)]
struct Content<'a> {
    r#type: &'a String,
    value: &'a String,
}

#[derive(Serialize, Debug)]
struct SendgridV3Data<'a> {
    personalizations: Vec<Personalization<'a>>,
    from: EmailAddress<'a>,
    subject: &'a String,
    content: Vec<Content<'a>>,
}

/// Check that all needed environment variables are set and not empty.
/// TODO: Use Figment for configuration.
pub fn check_conf() {
    env_exists_and_not_empty("SENDGRID_API_KEY");
}

impl Email {
    /// Send the email.
    pub fn send_via_sendgrid(&self, base_api_url: &str) -> error::Result<()> {
        let text_plain = "text/plain".to_string();
        let text_html = "text/html".to_string();
        let data = SendgridV3Data {
            personalizations: vec![Personalization {
                to: vec![EmailAddress { email: &self.to }],
            }],
            from: EmailAddress { email: &self.from },
            subject: &self.subject,
            content: vec![
                Content {
                    r#type: &text_plain,
                    value: &self.body,
                },
                Content {
                    r#type: &text_html,
                    value: &self.body_html,
                },
            ],
        };
        debug!("sendgrid payload: {}", serde_json::to_string(&data)?);

        // TODO 106: use external server for test
        let api_key = var("SENDGRID_API_KEY").expect("SENDGRID_API_KEY not set!");
        let resp = minreq::post(base_api_url.to_string() + "/v3/mail/send")
            .with_header("Authorization: Bearer", api_key)
            .with_json(&data)?
            .with_timeout(30)
            .send()
            .context("Posting mail via sendgrid API")?;

        if resp.status_code == 200 {
            debug!("Mail sent to {} via sendgrid.", &self.to);
            Ok(())
        } else {
            Err(anyhow!(
                "Sending mail to {} via sendgrid failed. API call returns code {} : {} \n {} ",
                &self.to,
                resp.status_code,
                resp.reason_phrase,
                resp.as_str()?
            ))
        }
    }
}
