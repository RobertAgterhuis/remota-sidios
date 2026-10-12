use std::path::PathBuf;

use axum::{
    extract::State,
    http::StatusCode,
    middleware,
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde_json::json;
use tower_http::{services::ServeDir, trace::TraceLayer};

pub mod identity;
pub mod store;

use identity::{require_identity, WebosUser};
use store::Store;

#[derive(Clone)]
pub struct AppState {
    pub store: Store,
}

/// The whole service. Only `/healthz` (the container health check) answers without a SidiOS
/// identity; the API and the UI itself refuse any request the gateway did not identify.
pub fn router(ui_dir: PathBuf, store: Store) -> Router {
    let identified = Router::new()
        .route("/api/tree", get(tree))
        .fallback_service(ServeDir::new(ui_dir).append_index_html_on_directories(true))
        .layer(middleware::from_fn(require_identity))
        .with_state(AppState { store });
    Router::new()
        .route("/healthz", get(healthz))
        .merge(identified)
        .layer(TraceLayer::new_for_http())
}

async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, "ok\n")
}

async fn tree(State(state): State<AppState>, user: WebosUser) -> Response {
    let result = tokio::task::spawn_blocking(move || state.store.for_user(&user.key).tree()).await;
    match result {
        Ok(Ok(tree)) => Json(tree).into_response(),
        _ => internal_error(),
    }
}

fn internal_error() -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({ "code": "internal_error" })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use http_body_util::BodyExt;
    use store::{NewConnection, Store};
    use tower::ServiceExt;

    const ADA: &str = "0123456789abcdef01234567";
    const BOB: &str = "76543210fedcba9876543210";

    fn app(store: Store) -> Router {
        router(PathBuf::from("missing-ui"), store)
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
    async fn the_tree_route_returns_only_the_callers_rows() {
        let store = Store::open_in_memory().unwrap();
        for (user, id) in [(ADA, "ada-box"), (BOB, "bob-box")] {
            store
                .for_user(user)
                .add_connection(&NewConnection {
                    id,
                    folder_id: None,
                    name: id,
                    protocol: "ssh",
                    host: "10.20.0.5",
                    port: Some(22),
                })
                .unwrap();
        }

        let response = app(store)
            .oneshot(request("/api/tree", Some(ADA)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let tree = body(response).await;
        assert_eq!(tree["connections"].as_array().unwrap().len(), 1);
        assert_eq!(tree["connections"][0]["id"], "ada-box");
        assert_eq!(tree["folders"], json!([]));
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
