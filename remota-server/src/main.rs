use std::{env, net::SocketAddr, path::PathBuf};

use remota_server::router;
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let address = env::var("REMOTA_LISTEN")
        .unwrap_or_else(|_| "0.0.0.0:8080".to_owned())
        .parse::<SocketAddr>()
        .expect("REMOTA_LISTEN must be a socket address");
    let ui_dir = PathBuf::from(env::var("REMOTA_UI_DIR").unwrap_or_else(|_| "/opt/remota/ui".to_owned()));
    let listener = TcpListener::bind(address).await.expect("failed to bind Remota server");

    info!(%address, ui_dir = %ui_dir.display(), "Remota server listening");
    axum::serve(listener, router(ui_dir))
        .with_graceful_shutdown(shutdown_signal())
        .await
        .expect("Remota server failed");
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
