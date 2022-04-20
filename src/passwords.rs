//! Password strength checks

use std::collections::HashSet;

use fancy_regex::Regex;
use rocket::form::{FromForm, FromFormField};
use serde::{Deserialize, Serialize};

/// Part of the [`PasswordPolicy`] that determines validity
/// for new passwords. [`pattern`] is the regex that the
/// password must match, and [`message`] is the user-facing
/// error message that will be presented if the password does
/// match the regex.
#[derive(Clone, Debug, Deserialize, FromForm, Serialize)]
pub struct RegexConfig {
    pattern: String,
    message: String,
}

impl RegexConfig {
    fn new(pattern: &str, message: &str) -> Self {
        RegexConfig {
            pattern: pattern.to_owned(),
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

/// Besides being required, you can set three more
/// validations on new passwords, by setting these fields
/// to a `Some` value:
///
/// * [`length`]:   Some((min_length, max_length))
/// * [`regex`]:    Some(regex_config) -- see the description and two
///    predefined statics for the [`RegexConfig`] struct
/// * [`strength`]: Some(min_password_score) -- see the description for
///    the [`PasswordScore`] enum. Usually you want a minimum score
///    of SafelyUnguessable
///
/// If any of these are set to a Some value, the password
/// will be validated against the optional argument.
#[derive(Clone, Debug, FromForm, Serialize, Deserialize)]
pub struct PasswordPolicy {
    length: Option<(usize, usize)>,
    regex: Option<RegexConfig>,
    strength: Option<PasswordScore>,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        PasswordPolicy {
            length: Some((8, 255)),
            regex: Some(REGEX_ANH.clone()),
            strength: Some(PasswordScore::SafelyUnguessable),
        }
    }
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
pub fn split_inputs(inputs: &[&str]) -> Vec<String> {
    let splitter = Regex::new(r#"\W"#).unwrap();
    let mut uniques: HashSet<String> = HashSet::new();
    let mut result: Vec<String> = Vec::new();
    for input in inputs {
        let words: Vec<String> = splitter
            .replace_all(*input, " ")
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
