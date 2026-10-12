use std::{env, fs, net::SocketAddr, path::PathBuf, sync::Arc};

use remota_server::{
    about::About,
    policy::{parse_networks, protected_networks, Denies},
    router, sessions,
    store::Store,
    webos::{HttpWebos, SharedWebos},
    AppState,
};
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::EnvFilter;

fn setting(name: &str, default: &str) -> String {
    env::var(name).unwrap_or_else(|_| default.to_owned())
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let address: SocketAddr = setting("REMOTA_LISTEN", "0.0.0.0:8080")
        .parse()
        .expect("REMOTA_LISTEN must be a socket address");
    let control: SocketAddr = setting("REMOTA_CONTROL_LISTEN", "0.0.0.0:8081")
        .parse()
        .expect("REMOTA_CONTROL_LISTEN must be a socket address");
    let ui_dir = PathBuf::from(setting("REMOTA_UI_DIR", "/opt/remota/ui"));
    let database = PathBuf::from(setting("REMOTA_DATABASE", "/var/lib/remota/remota.db"));
    let store = Store::open(&database).expect("failed to open the Remota database");
    let token_file = setting(
        "REMOTA_SERVICE_TOKEN_FILE",
        "/run/secrets/remota_service_token",
    );
    let token = fs::read_to_string(&token_file)
        .unwrap_or_else(|error| {
            panic!("failed to read the Remota service token {token_file}: {error}")
        })
        .trim()
        .to_owned();
    let webos_url = setting("WEBOS_INTERNAL_URL", "http://webos:3000");
    let webos: SharedWebos = Arc::new(HttpWebos::new(&webos_url, token.clone()));

    // SidiOS's own networks are always denied: the subnets this container shares with webOS and
    // Caddy, plus anything the operator lists.
    let protected: Vec<String> = setting("REMOTA_PROTECTED_HOSTS", "webos,caddy")
        .split(',')
        .map(|host| host.trim().to_owned())
        .filter(|host| !host.is_empty())
        .collect();
    let mut denied = protected_networks(&protected);
    denied.extend(parse_networks(&setting("REMOTA_DENY_CIDRS", "")));
    info!(networks = ?denied, "denied SidiOS networks");

    // The image records the fork commit it was built from (AGPL source offer, FR-016).
    let commit = fs::read_to_string(setting("REMOTA_COMMIT_FILE", "/opt/remota/COMMIT")).ok();
    let about = About::new(commit.as_deref());
    info!(commit = ?about.commit, "Remota build");
    let state = AppState::with_denies(store, webos.clone(), Denies::new(denied)).with_about(about);
    tokio::spawn(sessions::check_loop(webos, state.sessions.clone()));

    let control_listener = TcpListener::bind(control)
        .await
        .expect("failed to bind the Remota control port");
    let control_app = sessions::control_router(state.sessions.clone(), token);
    tokio::spawn(async move {
        let _ = axum::serve(control_listener, control_app).await;
    });

    let listener = TcpListener::bind(address)
        .await
        .expect("failed to bind Remota server");
    info!(%address, %control, ui_dir = %ui_dir.display(), "Remota server listening");
    axum::serve(listener, router(ui_dir, state))
        .with_graceful_shutdown(shutdown_signal())
        .await
        .expect("Remota server failed");
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
