


## Database

- Use `rocket_db_pools` crate with `sqlx_postgres` feature.
- See database pool definition for "app_db" in `src/database.rs`.
- Configure database URL in Rocket.toml as `default.databases.app_db`.
- Create the database with `sqlx database create --database_url <URL>`.
- Run the account migrations with `sqlx migrate run --database_url <URL>`.
