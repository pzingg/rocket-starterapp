use anyhow::anyhow;

pub use tera::Context;

pub mod common;
pub use common::Configurable;
pub use common::Email;
use crate::error;

#[cfg(feature = "email-mock")]
pub mod mock;
#[cfg(feature = "email-postmark")]
pub mod postmark;
#[cfg(feature = "email-sendgrid")]
pub mod sendgrid;
#[cfg(feature = "email-smtp")]
pub mod smtp;

impl Configurable for Email {
    fn check_conf() {
        #[cfg(feature = "email-postmark")]
        postmark::check_conf();
        #[cfg(feature = "email-smtp")]
        smtp::check_conf();
        #[cfg(feature = "email-sendgrid")]
        sendgrid::check_conf();
        #[cfg(feature = "email-mock")]
        mock::check_conf();
    }
}

impl Email {
    pub fn send(self) -> error::Result<()> {
        #[allow(unused_mut)]
        let mut res = Err(error::Error::from(anyhow!("No email provider configured")));
        #[cfg(feature = "email-postmark")]
        if res.is_err() {
            res = Email::send_via_postmark(&self, "https://api.postmarkapp.com");
        }
        #[cfg(feature = "email-sendgrid")]
        if res.is_err() {
            res = Email::send_via_sendgrid(&self, "https://api.sendgrid.com");
        }
        #[cfg(feature = "email-smtp")]
        if res.is_err() {
            res = Email::send_via_smtp(&self);
        }
        #[cfg(feature = "email-mock")]
        if res.is_err() {
            res = Email::send_via_mock(&self);
        }
        res
    }
}
