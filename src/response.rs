use rocket::response::{Redirect, Responder};
use rocket_dyn_templates::Template;
use serde::{Deserialize, Serialize};

#[derive(Debug, Responder)]
pub enum RenderOrRedirect {
    Template(Template),
    Redirect(Redirect),
}

impl From<Template> for RenderOrRedirect {
    fn from(t: Template) -> Self {
        Self::Template(t)
    }
}

impl From<Redirect> for RenderOrRedirect {
    fn from(t: Redirect) -> Self {
        Self::Redirect(t)
    }
}

/// A `FlashMessage` is a generic message that can be shoved into the Session
/// between requests. This isn't particularly useful for JSON-based workflows, but
/// for the traditional webapp side it works well.
#[derive(Debug, Deserialize, Serialize)]
struct FlashMessage {
    kind: String,
    message: String,
}

pub fn flash_context(flash: Option<rocket::request::FlashMessage>) -> tera::Context {
    let mut context = tera::Context::new();
    let mut messages: Vec<FlashMessage> = Vec::new();
    if let Some(msg) = flash {
        let (kind, message) = msg.into_inner();
        messages.push(FlashMessage { kind, message });
    }
    context.insert("flash_messages", &messages);
    context
}
