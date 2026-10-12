use std::{env, net::SocketAddr, path::PathBuf};

use std::{fs, sync::Arc};

use remota_server::{router, store::Store, webos::HttpWebos, AppState};
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
    let ui_dir =
        PathBuf::from(env::var("REMOTA_UI_DIR").unwrap_or_else(|_| "/opt/remota/ui".to_owned()));
    let database = PathBuf::from(
        env::var("REMOTA_DATABASE").unwrap_or_else(|_| "/var/lib/remota/remota.db".to_owned()),
    );
    let store = Store::open(&database).expect("failed to open the Remota database");
    let token_file = env::var("REMOTA_SERVICE_TOKEN_FILE")
        .unwrap_or_else(|_| "/run/secrets/remota_service_token".to_owned());
    let token = fs::read_to_string(&token_file)
        .expect("failed to read the Remota service token")
        .trim()
        .to_owned();
    let webos_url =
        env::var("WEBOS_INTERNAL_URL").unwrap_or_else(|_| "http://webos:3000".to_owned());
    let state = AppState::new(store, Arc::new(HttpWebos::new(&webos_url, token)));
    let listener = TcpListener::bind(address)
        .await
        .expect("failed to bind Remota server");

    info!(%address, ui_dir = %ui_dir.display(), "Remota server listening");
    axum::serve(listener, router(ui_dir, state))
        .with_graceful_shutdown(shutdown_signal())
        .await
        .expect("Remota server failed");
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
