#![forbid(unsafe_code)]
#![warn(clippy::all, clippy::pedantic)]

mod encryption;
mod models;
mod routes;
mod storage;
mod utils;

use actix_web::{
    web::{Data, PayloadConfig},
    App, HttpServer,
};
use anyhow::Result;
use dotenvy::dotenv;
use log::{info, warn};
use sqlx::{
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
    Pool, Sqlite,
};
use storage::Storage;

use crate::routes::{file::file_routes, gen::gen_routes, user::user_routes};

struct ConfigCache {
    public_url: String,
    registration_type: models::RegistrationType,
    pre_shared_secret: Option<String>,
}

struct AppData {
    pool: Pool<Sqlite>,
    storage: Storage,
    config: ConfigCache,
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();

    pretty_env_logger::init_custom_env("LUMEN_LOG");
    info!("Starting Lumen...");

    if std::env::var("LUMEN_LOG").unwrap_or_default() == "debug" {
        warn!("Lumen is running in debug mode. This is not recommended for production use.");
    }

    let storage = Storage::new("data").await?;
    let pool = SqlitePoolOptions::new()
        .connect_with(
            SqliteConnectOptions::new()
                .filename("data/lumen.db")
                .create_if_missing(true),
        )
        .await?;

        let config = ConfigCache {
            public_url: std::env::var("PUBLIC_URL").expect("PUBLIC_URL not set in environment"),
            registration_type: match std::env::var("REGISTRATION_TYPE").unwrap_or_else(|_| String::from("Open")).as_str() {
                "PreSharedSecret" => models::RegistrationType::PreSharedSecret,
                "Closed" => models::RegistrationType::Closed,
                _ => models::RegistrationType::Open,
            },
            pre_shared_secret: std::env::var("PRE_SHARED_SECRET").ok(),
        };

        if let models::RegistrationType::PreSharedSecret = config.registration_type {
            if config.pre_shared_secret.is_none() {
                panic!("Server configuration error: Pre-shared secret registration is enabled, but no pre-shared secret is set");
            }
        }

    info!("Running migrations...");

    // todo: support other databases (mysql, postgresql, etc)
    sqlx::migrate!().run(&pool).await?;
    let data = Data::new(AppData { pool, storage, config });

    let bind = std::env::var("BIND").expect("BIND not set in environment");
    info!("Lumen is running on http://{}", bind);
    HttpServer::new(move || {
        App::new()
            .app_data(data.clone())
            .app_data(PayloadConfig::default().limit(1024 * 1024 * 100)) // 100MB
            .configure(gen_routes)
            .configure(user_routes)
            .configure(file_routes)
    })
    .bind(bind)?
    .run()
    .await?;

    Ok(())
}
