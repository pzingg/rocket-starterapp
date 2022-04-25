//! Password strength checks

use std::collections::HashSet;

use fancy_regex::Regex;
use rocket::form;
use rocket::form::{Error, Errors, FromFormField};
use serde::{Deserialize, Serialize};
use zxcvbn::zxcvbn;

/// For validating passwords. [`pattern`] is the regex that the
/// password must match, and [`message`] is the user-facing
/// error message that will be presented if the password does
/// match the regex.
#[derive(Clone)]
pub struct RegexConfig {
    pattern: Regex,
    message: String,
}

impl RegexConfig {
    fn new(pattern: &str, message: &str) -> Self {
        RegexConfig {
            pattern: Regex::new(pattern).unwrap(),
            message: message.to_owned(),
        }
    }
}

lazy_static::lazy_static! {
    /// A [`RegexConfig`] for any combination of alphanumerics and hyphens.
    pub static ref REGEX_ANH: RegexConfig = RegexConfig::new(
        r#"^[-a-zA-Z0-9]+$"#,
        "can only contain uppercase, lowercase, numbers, and hyphens."
    );

    /// A [`RegexConfig`] that requires at least one of uppercase, lowercase,
    /// number, and symbol. We use the `fancy_regex` crate, which can handle
    /// `?=` positive lookahead (non-capturing) groups.
    pub static ref REGEX_ULNS: RegexConfig = RegexConfig::new(
        r#"^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[-_.@#$%^&*!?])[-_.@#$%^&*!?a-zA-Z0-9]+$"#,
        "must contain at least one each of uppercase, lowercase, number, and symbol from this set: -_@#$%^&*!?."
    );
}

impl Default for RegexConfig {
    fn default() -> Self {
        REGEX_ANH.clone()
    }
}

/// The mininum score of password attackability, as determined
/// by the `zxcvbn` algorithm.
#[repr(u8)]
#[derive(Clone, Debug, FromFormField, Serialize, Deserialize)]
pub enum PasswordScore {
    TooGuessable = 0,      // risky password. (guesses < 10^3)
    VeryGuessable = 1,     // protection from throttled online attacks. (guesses < 10^6)
    SomewhatGuessable = 2, // protection from unthrottled online attacks. (guesses < 10^8)
    SafelyUnguessable = 3, // moderate protection from offline slow-hash scenario. (guesses < 10^10)
    VeryUnguessable = 4,   // strong protection from offline slow-hash scenario. (guesses >= 10^10)
}

/// Pulls out non-duplicated words of four or more characters
/// from a list of inputs. Words are converted to lowercase
/// before testing for duplicates. The results are used
/// to seed the `zxcvbn` dictionary, when determining whether
/// a submitted password is too similar to components of a user's
/// name or email address.
///
/// Example:
///
/// ```rust
/// use jelly::forms::split_inputs;
///
/// let user_inputs = &["Jeffry A Bezos", "jbezos@amazon.com"];
/// let result = split_inputs(user_inputs);
/// assert_eq!(result, vec!["jeffry", "bezos", "jbezos", "amazon"])
/// ```
fn split_inputs<T: AsRef<str>>(inputs: &[T]) -> Vec<String> {
    let splitter = Regex::new(r#"\W"#).unwrap();
    let mut uniques: HashSet<String> = HashSet::new();
    let mut result: Vec<String> = Vec::new();
    for input in inputs {
        let words: Vec<String> = splitter
            .replace_all(input.as_ref(), " ")
            .split(' ')
            .filter(|w| w.len() > 3)
            .map(|w| w.to_lowercase())
            .collect();
        for word in words {
            if !uniques.contains(&word) {
                uniques.insert(word.clone());
                result.push(word);
            }
        }
    }
    result
}

/// Validate password against fancy regex.
pub fn validate_pattern<'v>(
    password: &'v str,
    config: &'v RegexConfig,
) -> form::Result<'v, ()> {
    match config.pattern.is_match(password) {
        Err(_) => Err(Error::validation("bad pattern").into()),
        Ok(true) => Ok(()),
        Ok(_) => Err(Error::validation(&config.message).into()),
    }
}

/// Validate password strength using zxcvbn algorithm.
pub fn validate_strength<'v, T: AsRef<str>>(
    password: &'v str,
    strength: PasswordScore,
    user_inputs: &[T],
) -> form::Result<'v, ()> {
    let words = split_inputs(user_inputs);
    match zxcvbn(
        password,
        words
            .iter()
            .map(|s| s.as_ref())
            .collect::<Vec<&str>>()
            .as_slice(),
    ) {
        Err(_) => Err(Error::validation("cannot be blank").into()),
        Ok(estimate) if estimate.score() >= strength as u8 => Ok(()),
        Ok(estimate) => {
            let mut errors = Errors::new();
            match estimate.feedback() {
                Some(feedback) => {
                    let message = feedback
                        .warning()
                        .map(|w| w.to_string())
                        .unwrap_or_else(|| "not strong enough".to_string());

                    errors.push(Error::validation(message));

                    feedback
                        .suggestions()
                        .iter()
                        .for_each(|s| errors.push(Error::validation(s.to_string())));
                },
                None => errors.push(Error::validation("not strong enough")),
            }

            Err(errors)
        }
    }
}
