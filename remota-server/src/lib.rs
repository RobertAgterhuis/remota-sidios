use std::path::PathBuf;

use axum::{http::StatusCode, response::IntoResponse, routing::get, Router};
use tower_http::{services::ServeDir, trace::TraceLayer};

pub fn router(ui_dir: PathBuf) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .fallback_service(ServeDir::new(ui_dir).append_index_html_on_directories(true))
        .layer(TraceLayer::new_for_http())
}

async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, "ok\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    #[tokio::test]
    async fn health_endpoint_is_available() {
        let response = router(PathBuf::from("missing-ui"))
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            "ok\n"
        );
    }

    #[tokio::test]
    async fn relay_routes_are_not_present() {
        for path in ["/relay", "/api/relay", "/agent", "/api/agent"] {
            let response = router(PathBuf::from("missing-ui"))
                .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
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
