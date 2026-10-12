use std::path::PathBuf;

use axum::{
    extract::DefaultBodyLimit,
    http::StatusCode,
    middleware,
    response::{IntoResponse, Response},
    routing::{any, get},
    Json, Router,
};
use serde_json::json;
use tower_http::{services::ServeDir, trace::TraceLayer};

pub mod identity;
pub mod model;
pub mod policy;
pub mod sessions;
pub mod ssh;
pub mod store;
pub mod tree;
pub mod webos;

use std::sync::Arc;

use identity::require_identity;
use policy::{Denies, PolicyClient};
use sessions::Sessions;
use store::Store;
use webos::SharedWebos;

/// Largest JSON body the API accepts (a node with a 16 KB private key fits easily).
const MAX_BODY_BYTES: usize = 64 * 1024;

#[derive(Clone)]
pub struct AppState {
    pub store: Store,
    pub webos: SharedWebos,
    pub policy: PolicyClient,
    pub denies: Arc<Denies>,
    pub sessions: Sessions,
}

impl AppState {
    pub fn new(store: Store, webos: SharedWebos) -> Self {
        Self::with_denies(store, webos, Denies::new([]))
    }

    pub fn with_denies(store: Store, webos: SharedWebos, denies: Denies) -> Self {
        Self {
            policy: PolicyClient::new(webos.clone()),
            denies: Arc::new(denies),
            sessions: Sessions::default(),
            store,
            webos,
        }
    }
}

/// The whole service. Only `/healthz` (the container health check) answers without a SidiOS
/// identity; the API and the UI itself refuse any request the gateway did not identify.
pub fn router(ui_dir: PathBuf, state: AppState) -> Router {
    let identified = Router::new()
        .merge(tree::routes())
        .merge(sessions::routes())
        .route("/api/{*rest}", any(api_not_found))
        .fallback_service(ServeDir::new(ui_dir).append_index_html_on_directories(true))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(middleware::from_fn(require_identity))
        .with_state(state);
    Router::new()
        .route("/healthz", get(healthz))
        .merge(identified)
        .layer(TraceLayer::new_for_http())
}

async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, "ok\n")
}

async fn api_not_found() -> Response {
    (StatusCode::NOT_FOUND, Json(json!({ "code": "not_found" }))).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use http_body_util::BodyExt;
    use std::sync::Arc;
    use tower::ServiceExt;
    use webos::fake::FakeWebos;

    const ADA: &str = "0123456789abcdef01234567";

    fn app(store: Store) -> Router {
        router(
            PathBuf::from("missing-ui"),
            AppState::new(store, Arc::new(FakeWebos::default())),
        )
    }

    fn request(path: &str, user: Option<&str>) -> Request<Body> {
        let mut builder = Request::builder().uri(path);
        if let Some(user) = user {
            builder = builder.header("x-webos-user", user);
        }
        builder.body(Body::empty()).unwrap()
    }

    async fn body(response: Response) -> serde_json::Value {
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn health_endpoint_is_available_without_identity() {
        let response = app(Store::open_in_memory().unwrap())
            .oneshot(request("/healthz", None))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            "ok\n"
        );
    }

    #[tokio::test]
    async fn every_other_path_refuses_requests_without_identity() {
        for path in [
            "/",
            "/index.html",
            "/api/tree",
            "/api/anything",
            "/session/x",
        ] {
            for user in [None, Some("not-a-user-key"), Some("")] {
                let response = app(Store::open_in_memory().unwrap())
                    .oneshot(request(path, user))
                    .await
                    .unwrap();
                assert_eq!(
                    response.status(),
                    StatusCode::UNAUTHORIZED,
                    "{path} {user:?}"
                );
                assert_eq!(body(response).await, json!({ "code": "unauthorized" }));
            }
        }
    }

    #[tokio::test]
    async fn relay_routes_are_not_present() {
        for path in ["/relay", "/api/relay", "/agent", "/api/agent"] {
            let response = app(Store::open_in_memory().unwrap())
                .oneshot(request(path, Some(ADA)))
                .await
                .unwrap();

            assert_eq!(
                response.status(),
                StatusCode::NOT_FOUND,
                "unexpected route: {path}"
            );
        }
    }
}
