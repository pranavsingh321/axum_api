mod models;
mod handler;
mod error;

use axum::{
    extract::Extension,
    routing::{get, post},
    Router
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, fmt::layer};
use tower_http::cors::{Any, CorsLayer};
use sqlx::postgres::PgPoolOptions;


#[tokio::main]
async fn main() {
    //initialize logging
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
                std::env::var("RUST_LOG").unwrap_or_else(|_| "axum_api=debug".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    //database setup
    let database_url = std::env::var("DATABASE_URL")
        .expect("set DATABASE_URL");

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("unable to connect to database");

    let cors = CorsLayer::new().allow_origin(Any);

    let app = Router::new()
        .route("/", get(|| async {"hello world"}))
        .route("/register", post(handler::auth::register))
        .layer(cors)
        .layer(Extension(pool));

    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 3000));
    tracing::debug!("listening on {}", addr);

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .expect("failed to start server");
}
