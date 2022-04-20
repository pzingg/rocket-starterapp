//! Set up background jobs

use std::env;
use std::fmt::Debug;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use anyhow::anyhow;
use rocket::{Build, Orbit, Rocket};
use rocket::config::LogLevel;
use rocket::fairing::{Fairing, Info, Kind};
use rocket::figment::providers::Serialized;
use rocket::futures::StreamExt;
use rocket::http::Status;
use rocket::request::{FromRequest, Request, Outcome};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sqlx::{ConnectOptions, PgPool, Postgres};
use sqlx::types::{Json, Uuid};
use tera::Tera;
use tokio_stream::{self as stream};

use crate::database;
use crate::error;

mod odd_registration_attempt;
use odd_registration_attempt::SendAccountOddRegisterAttemptEmail;
mod reset_password;
use reset_password::{SendPasswordWasResetEmail, SendResetPasswordEmail};
mod verify;
use verify::SendVerifyAccountEmail;
mod welcome;
use welcome::SendWelcomeAccountEmail;

pub const DEFAULT_QUEUE: &str = "default";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    SendResetPasswordEmail(String),
    SendPasswordWasResetEmail(String),
    SendAccountOddRegisterAttemptEmail(String),
    SendVerifyAccountEmail(i32),
    SendWelcomeAccountEmail(i32),
}

// We use a INT as Postgres representation for performance reasons
#[derive(Debug, Clone, sqlx::Type, PartialEq)]
#[repr(i32)]
enum PostgresJobStatus {
    Queued,
    Running,
    Failed,
}

#[derive(sqlx::FromRow, Debug, Clone)]
struct PostgresJob {
    id: Uuid,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,

    scheduled_for: chrono::DateTime<chrono::Utc>,
    failed_attempts: i32,
    status: PostgresJobStatus,
    message: Json<Message>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Job {
    pub id: Uuid,
    pub message: Message,
}

impl From<PostgresJob> for Job {
    fn from(item: PostgresJob) -> Self {
        Job {
            id: item.id,
            message: item.message.0,
        }
    }
}

/// Fixed queue parameters
const CONCURRENCY: usize = 50;
const QUEUE_EMPTY_DELAY: u64 = 500;
const QUEUE_INTERVAL: u64 = 125;

#[derive(Debug, Clone)]
pub struct PostgresQueue {
    pool: PgPool,
    templates: Arc<RwLock<Tera>>,
    max_attempts: i32,
}

impl PostgresQueue {
    pub fn new(pool: PgPool, templates: Arc<RwLock<Tera>>, max_attempts: i32) -> PostgresQueue {
        PostgresQueue {
            pool,
            templates,
            max_attempts,
        }
    }

    pub async fn push(
        &self,
        job: Message,
        date: Option<chrono::DateTime<chrono::Utc>>,
    ) -> error::Result<()> {
        let scheduled_for = date.unwrap_or_else(chrono::Utc::now);
        let failed_attempts: i32 = 0;
        let message = Json(job.clone());
        let status = PostgresJobStatus::Queued;
        let now = chrono::Utc::now();

        // ULID to UUID. We use Ulid so that job_ids are ordered by creation time.
        let job_id: Uuid = ulid::Ulid::new().into();
        let query = "INSERT INTO queue
            (id, created_at, updated_at, scheduled_for, failed_attempts, status, message)
            VALUES ($1, $2, $3, $4, $5, $6, $7)";

        sqlx::query(query)
            .bind(job_id)
            .bind(now)
            .bind(now)
            .bind(scheduled_for)
            .bind(failed_attempts)
            .bind(status)
            .bind(message)
            .execute(&self.pool)
            .await?;

        rocket::info!("pushed job {:?}", job);
        Ok(())
    }

    /// pull fetches at most `number_of_jobs` from the queue.
    pub async fn pull(&self, number_of_jobs: u32) -> error::Result<Vec<Job>> {
        let now = chrono::Utc::now();

        // Note use of UPDATE SKIP LOCKED for performance
        let query = "UPDATE queue
            SET status = $1, updated_at = $2
            WHERE id IN (
                SELECT id
                FROM queue
                WHERE status = $3 AND scheduled_for <= $4 AND failed_attempts < $5
                ORDER BY scheduled_for
                FOR UPDATE SKIP LOCKED
                LIMIT $6
            )
            RETURNING *";

        let jobs: Vec<PostgresJob> = sqlx::query_as::<_, PostgresJob>(query)
            .bind(PostgresJobStatus::Running)
            .bind(now)
            .bind(PostgresJobStatus::Queued)
            .bind(now)
            .bind(self.max_attempts)
            .bind(number_of_jobs)
            .fetch_all(&self.pool)
            .await?;

        Ok(jobs.into_iter().map(Into::into).collect())
    }

    pub async fn delete_job(&self, job_id: Uuid) -> error::Result<()> {
        let query = "DELETE FROM queue WHERE id = $1";

        sqlx::query(query).bind(job_id).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn fail_job(&self, job_id: Uuid) -> error::Result<()> {
        let now = chrono::Utc::now();
        let query = "UPDATE queue
            SET status = $1, updated_at = $2, failed_attempts = failed_attempts + 1
            WHERE id = $3";

        sqlx::query(query)
            .bind(PostgresJobStatus::Queued)
            .bind(now)
            .bind(job_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn clear(&self) -> error::Result<()> {
        let query = "DELETE FROM queue";

        sqlx::query(query).execute(&self.pool).await?;
        Ok(())
    }
}

/// From background_jobs crate
#[rocket::async_trait]
pub trait JobRun: 'static + Serialize + DeserializeOwned {
    async fn run(self, state: &PostgresQueue) -> error::Result<()>;
}

async fn run_worker(queue: PostgresQueue) {
    loop {
        let jobs = match queue.pull(CONCURRENCY as u32).await {
            Ok(jobs) => jobs,
            Err(err) => {
                println!("run_worker: pulling jobs: {}", err);
                rocket::tokio::time::sleep(Duration::from_millis(QUEUE_EMPTY_DELAY)).await;
                Vec::new()
            }
        };

        let number_of_jobs = jobs.len();
        if number_of_jobs > 0 {
            println!("Fetched {} jobs", number_of_jobs);
        }

        stream::iter(jobs)
            .for_each_concurrent(CONCURRENCY, |job| async {
                let job_id = job.id;
                let res = match handle_job(job, &queue).await {
                    Ok(_) => {
                        println!("run_worker: job({}) was handled successfully", job_id);
                        queue.delete_job(job_id).await
                    },
                    Err(err) => {
                        println!("run_worker: handling job({}): {}", job_id, &err);
                        queue.fail_job(job_id).await
                    }
                };

                match res {
                    Ok(_) => {}
                    Err(err) => {
                        println!("run_worker: deleting / failing job: {}", &err);
                    }
                }
            })
            .await;

        // sleep not to overload our database
        rocket::tokio::time::sleep(Duration::from_millis(QUEUE_INTERVAL)).await;
    }
}

async fn handle_job(job: Job, state: &PostgresQueue) -> error::Result<()> {
    match job.message {
        Message::SendResetPasswordEmail(email) =>
            SendResetPasswordEmail { to: email }.run(state).await,
        Message::SendPasswordWasResetEmail(email) =>
            SendPasswordWasResetEmail { to: email }.run(state).await,
        Message::SendAccountOddRegisterAttemptEmail(email) =>
            SendAccountOddRegisterAttemptEmail { to: email }.run(state).await,
        Message::SendVerifyAccountEmail(uid) =>
            SendVerifyAccountEmail { to: uid }.run(state).await,
        Message::SendWelcomeAccountEmail(uid) =>
            SendWelcomeAccountEmail { to: uid }.run(state).await,
    }
}

/// Loads a glob of Tera templates (for sending emails) into memory behind an `Arc<RwLock<>>`.
/// Note: As opposed to the Rocket dyn_templates crate, these templates do not have
/// the ".tera" extension, because we have ".txt" and ".html" templates.
fn load_templates() -> error::Result<Arc<RwLock<Tera>>> {
    // TODO: Use Figment to specify the location.
    let templates_glob = env::var("EMAIL_TEMPLATES_GLOB").expect("EMAIL_TEMPLATES_GLOB not set!");
    let tera = Tera::new(&templates_glob)
        .map_err(|e| error::Error::from(anyhow!("failed to compile templates {}", e)))?;

    Ok(Arc::new(RwLock::new(tera)))
}

/// Copied from contrib/db_pools
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(crate = "rocket::serde")]
pub struct PoolConfig {
    /// Database-specific connection and configuration URL.
    ///
    /// The format of the URL is database specific; consult your database's
    /// documentation.
    pub url: String,
    /// Minimum number of connections to maintain in the pool.
    ///
    /// **Note:** `deadpool` drivers do not support and thus ignore this value.
    ///
    /// _Default:_ `None`.
    pub min_connections: Option<u32>,
    /// Maximum number of connections to maintain in the pool.
    ///
    /// _Default:_ `workers * 4`.
    pub max_connections: usize,
    /// Number of seconds to wait for a connection before timing out.
    ///
    /// If the timeout elapses before a connection can be made or retrieved from
    /// a pool, an error is returned.
    ///
    /// _Default:_ `5`.
    pub connect_timeout: u64,
    /// Maximum number of seconds to keep a connection alive for.
    ///
    /// After a connection is established, it is maintained in a pool for
    /// efficient connection retrieval. When an `idle_timeout` is set, that
    /// connection will be closed after the timeout elapses. If an
    /// `idle_timeout` is not specified, the behavior is driver specific but
    /// typically defaults to keeping a connection active indefinitely.
    ///
    /// _Default:_ `None`.
    pub idle_timeout: Option<u64>,
}

type PgConnectOptions = <<Postgres as sqlx::Database>::Connection as sqlx::Connection>::Options;

async fn create_database_pool(rocket: &Rocket<Build>) -> error::Result<PgPool> {
    let workers: usize = rocket.figment()
        .extract_inner(rocket::Config::WORKERS)
        .unwrap_or_else(|_| rocket::Config::default().workers);

    let figment = rocket.figment()
        .focus(&format!("databases.{}", database::NAME))
        .merge(Serialized::default("max_connections", workers * 4))
        .merge(Serialized::default("connect_timeout", 5u64));
    let config = figment.extract::<PoolConfig>()?;
    let mut opts = config.url
        .parse::<PgConnectOptions>()
        .map_err(|e| error::Error::from(anyhow!("invalid pg connection options {}", e)))?;

    opts.disable_statement_logging();
    if let Ok(level) = figment.extract_inner::<LogLevel>(rocket::Config::LOG_LEVEL) {
        if !matches!(level, LogLevel::Normal | LogLevel::Off) {
            opts.log_statements(level.into())
                .log_slow_statements(level.into(), Duration::default());
        }
    }

    sqlx::pool::PoolOptions::<Postgres>::new()
        .max_connections(config.max_connections as u32)
        .connect_timeout(Duration::from_secs(config.connect_timeout))
        .idle_timeout(config.idle_timeout.map(Duration::from_secs))
        .min_connections(config.min_connections.unwrap_or_default())
        .connect_with(opts)
        .await
        .map_err(|e| error::Error::from(anyhow!("could not connect pool to db {}", e)))
}


#[derive(Default)]
pub struct BackgroundQueue;

impl BackgroundQueue {
    pub fn fairing() -> impl Fairing {
        BackgroundQueue::default()
    }
}

#[rocket::async_trait]
impl Fairing for BackgroundQueue {
    fn info(&self) -> Info {
        Info {
            name: "Background Jobs",
            kind: Kind::Ignite | Kind::Liftoff,
        }
    }

    /// The ignite callback. Returns `Ok` if ignition should proceed and `Err`
    /// if ignition and launch should be aborted.
    ///
    /// This method is called during ignition and if `Kind::Ignite` is in the
    /// `kind` field of the `Info` structure for this fairing. The `rocket`
    /// parameter is the `Rocket` instance that is currently being built for
    /// this application.
    ///
    /// ## Default Implementation
    ///
    /// The default implementation of this method simply returns `Ok(rocket)`.
    async fn on_ignite(&self, rocket: Rocket<Build>) -> rocket::fairing::Result {
        match create_database_pool(&rocket).await {
            Ok(pool) =>
                match load_templates() {
                    Ok(templates) => {
                        let queue = PostgresQueue::new(pool, templates, 5);
                        Ok(rocket.manage(queue))
                    },
                    Err(e) => {
                        log::error!("background_jobs failed to load templates: {}", e);
                        Err(rocket)
                    }
            },
            Err(e) => {
                log::error!("background_jobs failed to connect to db: {}", e);
                Err(rocket)
            }
        }
    }

    /// Here's where the PostgresQueue is run
    async fn on_liftoff(&self, rocket: &Rocket<Orbit>) {
        match rocket.state::<PostgresQueue>() {
            Some(queue) => {
                // queue is an Arc pointer, so this just copies the reference
                let worker_queue = queue.clone();
                let _queue_task_handle = rocket::tokio::spawn(async move { run_worker(worker_queue).await });
                log::info!("job queue worker task spawned");
            }
            None => {
                log::error!("could not fetch job queue");
            }
        }
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for PostgresQueue {
    type Error = error::Error;

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        match req.rocket().state::<PostgresQueue>() {
            Some(queue) => {
                Outcome::Success(queue.clone())
            }
            None => {
                log::error!("could not fetch job queue");
                Outcome::Failure((Status::InternalServerError,
                    error::Error::from(anyhow!("could not fetch job queue"))))
            }
        }
    }
}
