use rocket_db_pools::{sqlx::PgPool, Connection, Database};
use sqlx::{pool::PoolConnection, Postgres, Transaction};

pub const NAME: &str = "app_db";

#[derive(Database)]
#[database("app_db")]
pub struct AppDb(PgPool);

pub type AppDbConnection = Connection<AppDb>;

pub type PoolConn = PoolConnection<Postgres>;

pub type PgTransaction<'a> = Transaction<'a, Postgres>;



