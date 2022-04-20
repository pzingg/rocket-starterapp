

#[rocket::main]
async fn main() {
    // Load .env files
    dotenv::dotenv().ok();
    pretty_env_logger::init();

    if let Err(e) = mainlib::rocket().launch().await {
        println!("Whoops! Rocket didn't launch!");
        // We drop the error to get a Rocket-formatted panic.
        drop(e);
    };
}
