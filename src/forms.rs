

/*
use rocket::data::{FromData, Outcome};
use rocket::form::{parser::RawStrParser, Context, SharedStack};

use serde::Serialize;

fn make_context<'v, T: Serialize + FromData>(input: T) -> Option<Context<'v>> {
    let encoded = serde_urlencoded::ser::to_string(input).ok();

    decode_context::<'v, Form<T>>(&encoded);
}

pub fn decode_context<'a, Form<T: FromData<'a>>>(string: &RawStr) -> Option<Context> {
    let buffer = SharedStack::new();
    let mut context = T::init(Options::Lenient);
    for field in RawStrParser::new(&buffer, string) {
        T::push_value(&mut ctxt, field)
    }

    T::finalize(context);
}
*/

