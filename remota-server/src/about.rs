//! `GET /api/about`: which source this server was built from (AGPL-3.0 section 13; SidiOS FR-016).
//! The image records the fork commit it checked out; the dialog links to that exact source.

use axum::{extract::State, routing::get, Json, Router};
use serde::Serialize;

use crate::AppState;

pub const SOURCE_REPOSITORY: &str = "https://github.com/RobertAgterhuis/remota-sidios";
pub const LICENSE: &str = "AGPL-3.0-only";

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct About {
    pub name: &'static str,
    pub version: &'static str,
    pub license: &'static str,
    /// The full fork commit, when the image recorded one.
    pub commit: Option<String>,
    pub source: String,
}

impl About {
    /// `recorded` is the content of the image's commit file; anything but a commit hash is ignored.
    pub fn new(recorded: Option<&str>) -> Self {
        let commit = recorded
            .map(str::trim)
            .filter(|c| (7..=40).contains(&c.len()) && c.bytes().all(|b| b.is_ascii_hexdigit()))
            .map(str::to_ascii_lowercase);
        let source = match &commit {
            Some(commit) => format!("{SOURCE_REPOSITORY}/tree/{commit}"),
            None => SOURCE_REPOSITORY.to_owned(),
        };
        Self {
            name: "Remota for SidiOS",
            version: env!("CARGO_PKG_VERSION"),
            license: LICENSE,
            commit,
            source,
        }
    }
}

impl Default for About {
    fn default() -> Self {
        Self::new(None)
    }
}

pub fn routes() -> Router<AppState> {
    Router::new().route("/api/about", get(about))
}

async fn about(State(state): State<AppState>) -> Json<About> {
    Json((*state.about).clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn links_to_the_exact_commit_when_recorded() {
        let commit = "98dce4cec360cc8626201cf7c0cb96e703455d65";
        let about = About::new(Some(&format!("{commit}\n")));
        assert_eq!(about.commit.as_deref(), Some(commit));
        assert_eq!(
            about.source,
            format!("https://github.com/RobertAgterhuis/remota-sidios/tree/{commit}")
        );
        assert_eq!(about.license, "AGPL-3.0-only");
    }

    #[test]
    fn falls_back_to_the_repository_without_a_valid_commit() {
        for recorded in [None, Some(""), Some("main"), Some("<script>"), Some("abc")] {
            let about = About::new(recorded);
            assert_eq!(about.commit, None, "{recorded:?}");
            assert_eq!(about.source, SOURCE_REPOSITORY);
        }
    }

    #[tokio::test]
    async fn is_served_to_signed_in_users_only() {
        use axum::{body::Body, http::Request};
        use http_body_util::BodyExt;
        use std::{path::PathBuf, sync::Arc};
        use tower::ServiceExt;

        let dir = tempfile::tempdir().unwrap();
        let store = crate::store::Store::open(&dir.path().join("remota.db")).unwrap();
        let webos = Arc::new(crate::webos::fake::FakeWebos::default());
        let state = AppState::new(store, webos).with_about(About::new(Some("98dce4c")));
        let app = crate::router(PathBuf::from("missing-ui"), state);
        let get = |user: Option<&str>| {
            let mut request = Request::get("/api/about");
            if let Some(user) = user {
                request = request.header("x-webos-user", user);
            }
            request.body(Body::empty()).unwrap()
        };
        let anonymous = app.clone().oneshot(get(None)).await.unwrap();
        assert_eq!(anonymous.status(), axum::http::StatusCode::UNAUTHORIZED);
        let response = app
            .oneshot(get(Some("0123456789abcdef01234567")))
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let about: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(about["commit"], "98dce4c");
        assert_eq!(about["license"], "AGPL-3.0-only");
        assert_eq!(
            about["source"],
            "https://github.com/RobertAgterhuis/remota-sidios/tree/98dce4c"
        );
    }
}
