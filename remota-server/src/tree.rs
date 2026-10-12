//! The tree routes (SidiOS `contracts/remota-api.md`): read the caller's tree, save and move nodes,
//! trash, restore, and delete. Secrets sent with a node are sealed in the SidiOS vault before the
//! node is stored, and credentials no longer used anywhere are deleted from the vault.

use std::collections::BTreeSet;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
    Json, Router,
};
use serde::Deserialize;
use serde_json::json;

use crate::{
    identity::WebosUser,
    model::{Document, Node, TreeError},
    store::{Store, StoreError},
    webos::{NewCredential, SharedWebos, WebosError},
    AppState,
};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/tree", get(read_tree))
        .route("/api/nodes/{id}", put(save_node).delete(trash_node))
        .route("/api/trash/{id}/restore", post(restore_node))
        .route("/api/trash/{id}", delete(delete_forever))
        .route("/api/trash", delete(empty_trash))
}

/// An error answer: `{ "code": … }` with no echo of the input.
#[derive(Debug)]
pub struct ApiError(pub StatusCode, pub &'static str);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "code": self.1 }))).into_response()
    }
}

impl From<StoreError> for ApiError {
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::Tree(TreeError::NotFound) => Self(StatusCode::NOT_FOUND, "not_found"),
            StoreError::Tree(TreeError::Invalid(code)) => {
                Self(StatusCode::UNPROCESSABLE_ENTITY, code)
            }
            StoreError::Database(_) => Self(StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
        }
    }
}

impl From<WebosError> for ApiError {
    fn from(error: WebosError) -> Self {
        match error {
            WebosError::Refused(StatusCode::FORBIDDEN, _) => {
                Self(StatusCode::FORBIDDEN, "forbidden")
            }
            WebosError::Refused(StatusCode::BAD_REQUEST, _) => {
                Self(StatusCode::UNPROCESSABLE_ENTITY, "invalid_secret")
            }
            _ => Self(StatusCode::BAD_GATEWAY, "vault_unavailable"),
        }
    }
}

pub type ApiResult<T> = Result<T, ApiError>;

/// Runs a store operation off the async runtime.
pub async fn blocking<T: Send + 'static>(
    task: impl FnOnce() -> Result<T, StoreError> + Send + 'static,
) -> ApiResult<T> {
    tokio::task::spawn_blocking(task)
        .await
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "internal_error"))?
        .map_err(ApiError::from)
}

async fn read_tree(State(state): State<AppState>, user: WebosUser) -> ApiResult<Json<Document>> {
    let store = state.store.clone();
    Ok(Json(
        blocking(move || store.for_user(&user.key).document()).await?,
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SaveNode {
    #[serde(default)]
    parent_id: Option<String>,
    node: Node,
}

async fn save_node(
    State(state): State<AppState>,
    user: WebosUser,
    Path(id): Path<String>,
    Json(body): Json<SaveNode>,
) -> ApiResult<Json<Document>> {
    let SaveNode {
        parent_id,
        mut node,
    } = body;
    if node.id() != id {
        return Err(ApiError(StatusCode::UNPROCESSABLE_ENTITY, "id_mismatch"));
    }
    let owned = owned_credentials(&state.webos, &user.key).await?;
    let sealed = seal_secrets(&state.webos, &user.key, &mut node, &owned).await;
    let saved = match sealed {
        Ok(()) => {
            change(&state.store, &user.key, move |doc| {
                doc.upsert(parent_id.as_deref(), node)
            })
            .await
        }
        Err(error) => Err(error),
    };
    collect_garbage(&state, &user.key).await;
    saved.map(Json)
}

async fn trash_node(
    State(state): State<AppState>,
    user: WebosUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Document>> {
    change(&state.store, &user.key, move |doc| doc.delete(&id))
        .await
        .map(Json)
}

async fn restore_node(
    State(state): State<AppState>,
    user: WebosUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Document>> {
    change(&state.store, &user.key, move |doc| doc.restore(&id))
        .await
        .map(Json)
}

async fn delete_forever(
    State(state): State<AppState>,
    user: WebosUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Document>> {
    let result = change(&state.store, &user.key, move |doc| doc.delete_forever(&id)).await;
    collect_garbage(&state, &user.key).await;
    result.map(Json)
}

async fn empty_trash(State(state): State<AppState>, user: WebosUser) -> ApiResult<Json<Document>> {
    let result = change(&state.store, &user.key, |doc| {
        doc.empty_trash();
        Ok(())
    })
    .await;
    collect_garbage(&state, &user.key).await;
    result.map(Json)
}

/// Applies one change to the user's tree and answers the tree afterwards.
pub async fn change(
    store: &Store,
    user: &str,
    operation: impl FnOnce(&mut Document) -> Result<(), TreeError> + Send + 'static,
) -> ApiResult<Document> {
    let store = store.clone();
    let user = user.to_owned();
    blocking(move || store.for_user(&user).update(operation).map(|(_, doc)| doc)).await
}

pub async fn owned_credentials(webos: &SharedWebos, user: &str) -> ApiResult<BTreeSet<String>> {
    Ok(webos
        .list_credentials(user)
        .await?
        .into_iter()
        .map(|credential| credential.id)
        .collect())
}

/// Seals every new secret in `node` (not its children) and keeps only the credential IDs. Every
/// new secret gets a new credential, so a credential shared by two nodes is never changed under
/// the other one. An ID the user does not own is refused.
pub async fn seal_secrets(
    webos: &SharedWebos,
    user: &str,
    node: &mut Node,
    owned: &BTreeSet<String>,
) -> ApiResult<()> {
    for (label, username, secret) in node.secrets_mut() {
        if let Some((kind, value, passphrase)) = secret.pending() {
            let credential = NewCredential {
                id: None,
                kind: kind.to_owned(),
                label: label.chars().take(120).collect(),
                username,
                secret: value.to_owned(),
                passphrase: passphrase.map(str::to_owned),
            };
            secret.credential_id = Some(webos.save_credential(user, credential).await?);
            secret.clear_pending();
        } else if secret
            .credential_id
            .as_ref()
            .is_some_and(|id| !owned.contains(id))
        {
            return Err(ApiError(StatusCode::FORBIDDEN, "unknown_credential"));
        }
    }
    Ok(())
}

/// Deletes the user's vault credentials that neither the tree nor the trash uses any more.
/// Best effort: a failure leaves an unused, still-encrypted credential for the next pass.
pub async fn collect_garbage(state: &AppState, user: &str) {
    let store = state.store.clone();
    let owner = user.to_owned();
    let Ok(document) = blocking(move || store.for_user(&owner).document()).await else {
        return;
    };
    let Ok(owned) = owned_credentials(&state.webos, user).await else {
        return;
    };
    let used = document.credential_ids();
    for id in owned.difference(&used) {
        let _ = state.webos.delete_credential(user, id).await;
    }
}

#[cfg(test)]
mod tests {
    use std::{path::PathBuf, sync::Arc};

    use axum::{body::Body, http::Request};
    use http_body_util::BodyExt;
    use serde_json::Value;
    use tower::ServiceExt;

    use crate::{router, webos::fake::FakeWebos};

    use super::*;

    const ADA: &str = "0123456789abcdef01234567";
    const BOB: &str = "76543210fedcba9876543210";

    struct Harness {
        store: Store,
        webos: Arc<FakeWebos>,
    }

    impl Harness {
        fn new() -> Self {
            Self {
                store: Store::open_in_memory().unwrap(),
                webos: Arc::new(FakeWebos::default()),
            }
        }

        async fn call(
            &self,
            method: &str,
            path: &str,
            user: &str,
            body: Option<Value>,
        ) -> (StatusCode, Value, String) {
            let app = router(
                PathBuf::from("missing-ui"),
                AppState::new(self.store.clone(), self.webos.clone()),
            );
            let mut request = Request::builder()
                .method(method)
                .uri(path)
                .header("x-webos-user", user);
            if body.is_some() {
                request = request.header("content-type", "application/json");
            }
            let request = request
                .body(body.map_or(Body::empty(), |b| Body::from(b.to_string())))
                .unwrap();
            let response = app.oneshot(request).await.unwrap();
            let status = response.status();
            let bytes = response.into_body().collect().await.unwrap().to_bytes();
            let text = String::from_utf8_lossy(&bytes).into_owned();
            (
                status,
                serde_json::from_str(&text).unwrap_or(Value::Null),
                text,
            )
        }

        async fn save(
            &self,
            user: &str,
            parent: Option<&str>,
            node: Value,
        ) -> (StatusCode, Value, String) {
            let id = node["id"].as_str().unwrap().to_owned();
            self.call(
                "PUT",
                &format!("/api/nodes/{id}"),
                user,
                Some(json!({ "parentId": parent, "node": node })),
            )
            .await
        }
    }

    fn ssh(id: &str, credentials: Value) -> Value {
        json!({ "type": "connection", "id": id, "name": id,
                "conn": { "protocol": "ssh", "host": "10.20.0.5", "credentials": credentials } })
    }

    fn folder(id: &str, defaults: Value) -> Value {
        json!({ "type": "folder", "id": id, "name": id, "defaults": defaults, "children": [] })
    }

    #[tokio::test]
    async fn seals_a_password_and_never_returns_it() {
        let h = Harness::new();
        let (status, tree, text) = h
            .save(
                ADA,
                None,
                ssh("web", json!({ "username": "root", "password": "hunter2" })),
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        assert!(!text.contains("hunter2"));
        let id = tree["nodes"][0]["conn"]["credentials"]["credential_id"]
            .as_str()
            .unwrap()
            .to_owned();
        let stored = h.webos.credentials().get(&id).cloned().unwrap();
        assert_eq!(
            (stored.user.as_str(), stored.secret.as_str()),
            (ADA, "hunter2")
        );
        assert_eq!(stored.summary.kind, "password");

        let (_, _, again) = h.call("GET", "/api/tree", ADA, None).await;
        assert!(!again.contains("hunter2"));
        let db = h.store.for_user(ADA).document().unwrap();
        assert!(!serde_json::to_string(&db).unwrap().contains("hunter2"));
    }

    #[tokio::test]
    async fn seals_private_keys_with_their_passphrase_and_jump_host_secrets() {
        let h = Harness::new();
        let mut node = ssh(
            "web",
            json!({ "private_key": "-----BEGIN KEY-----", "passphrase": "pp" }),
        );
        node["conn"]["gateway"] =
            json!({ "host": "bastion", "username": "jump", "password": "jpw" });
        let (status, tree, text) = h.save(ADA, None, node).await;
        assert_eq!(status, StatusCode::OK);
        assert!(!text.contains("BEGIN KEY") && !text.contains("jpw"));
        let credentials = h.webos.credentials();
        let mut kinds: Vec<_> = credentials
            .values()
            .map(|c| (c.summary.kind.as_str(), c.secret.as_str()))
            .collect();
        kinds.sort();
        assert_eq!(
            kinds,
            [("password", "jpw"), ("private_key", "-----BEGIN KEY-----")]
        );
        assert!(tree["nodes"][0]["conn"]["gateway"]["credential_id"].is_string());
    }

    #[tokio::test]
    async fn keeps_an_existing_credential_when_no_new_secret_is_sent() {
        let h = Harness::new();
        let (_, tree, _) = h
            .save(ADA, None, ssh("web", json!({ "password": "one" })))
            .await;
        let id = tree["nodes"][0]["conn"]["credentials"]["credential_id"].clone();
        let mut renamed = ssh("web", json!({ "credential_id": id }));
        renamed["name"] = json!("renamed");
        let (status, tree, _) = h.save(ADA, None, renamed).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(tree["nodes"][0]["conn"]["credentials"]["credential_id"], id);
        assert_eq!(h.webos.credentials().len(), 1);
    }

    #[tokio::test]
    async fn a_replaced_or_removed_secret_is_deleted_from_the_vault() {
        let h = Harness::new();
        h.save(ADA, None, ssh("web", json!({ "password": "one" })))
            .await;
        h.save(ADA, None, ssh("web", json!({ "password": "two" })))
            .await;
        let secrets: Vec<_> = h
            .webos
            .credentials()
            .values()
            .map(|c| c.secret.clone())
            .collect();
        assert_eq!(secrets, ["two"]);

        h.save(ADA, None, ssh("web", json!({}))).await;
        assert!(h.webos.credentials().is_empty());
    }

    #[tokio::test]
    async fn refuses_another_users_credential_id() {
        let h = Harness::new();
        let (_, tree, _) = h
            .save(BOB, None, ssh("bob", json!({ "password": "bob's" })))
            .await;
        let bobs = tree["nodes"][0]["conn"]["credentials"]["credential_id"].clone();
        let (status, body, _) = h
            .save(ADA, None, ssh("steal", json!({ "credential_id": bobs })))
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body, json!({ "code": "unknown_credential" }));
        assert!(h
            .store
            .for_user(ADA)
            .document()
            .unwrap()
            .find("steal")
            .is_none());
    }

    #[tokio::test]
    async fn trash_keeps_credentials_until_deleted_for_good() {
        let h = Harness::new();
        h.save(ADA, None, ssh("web", json!({ "password": "one" })))
            .await;
        let (status, tree, _) = h.call("DELETE", "/api/nodes/web", ADA, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(tree["trash"].as_array().unwrap().len(), 1);
        assert_eq!(h.webos.credentials().len(), 1);

        let (status, tree, _) = h.call("POST", "/api/trash/web/restore", ADA, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(tree["nodes"][0]["id"], "web");

        h.call("DELETE", "/api/nodes/web", ADA, None).await;
        let (status, _, _) = h.call("DELETE", "/api/trash/web", ADA, None).await;
        assert_eq!(status, StatusCode::OK);
        assert!(h.webos.credentials().is_empty());
    }

    #[tokio::test]
    async fn empties_the_trash() {
        let h = Harness::new();
        h.save(ADA, None, ssh("a", json!({ "password": "one" })))
            .await;
        h.save(ADA, None, ssh("b", json!({}))).await;
        h.call("DELETE", "/api/nodes/a", ADA, None).await;
        h.call("DELETE", "/api/nodes/b", ADA, None).await;
        let (status, tree, _) = h.call("DELETE", "/api/trash", ADA, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(tree["trash"], json!([]));
        assert!(h.webos.credentials().is_empty());
    }

    #[tokio::test]
    async fn users_cannot_touch_each_others_nodes() {
        let h = Harness::new();
        h.save(ADA, None, folder("lab", json!({}))).await;
        h.save(ADA, Some("lab"), ssh("web", json!({}))).await;

        assert_eq!(
            h.call("DELETE", "/api/nodes/web", BOB, None).await.0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            h.save(BOB, Some("lab"), ssh("sneaky", json!({}))).await.0,
            StatusCode::UNPROCESSABLE_ENTITY
        );
        let (_, tree, _) = h.call("GET", "/api/tree", BOB, None).await;
        assert_eq!(tree, json!({ "nodes": [], "trash": [] }));
        assert!(h
            .store
            .for_user(ADA)
            .document()
            .unwrap()
            .find("web")
            .is_some());
    }

    #[tokio::test]
    async fn validates_the_request() {
        let h = Harness::new();
        let node = ssh("web", json!({}));
        let mismatched = h
            .call(
                "PUT",
                "/api/nodes/other",
                ADA,
                Some(json!({ "node": node })),
            )
            .await;
        assert_eq!(mismatched.1, json!({ "code": "id_mismatch" }));
        let unknown = h
            .call(
                "PUT",
                "/api/nodes/web",
                ADA,
                Some(json!({ "node": node, "extra": 1 })),
            )
            .await;
        assert_eq!(unknown.0, StatusCode::UNPROCESSABLE_ENTITY);
        let (status, body, _) = h.save(ADA, Some("missing"), ssh("web", json!({}))).await;
        assert_eq!(
            (status, body),
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                json!({ "code": "parent_not_found" })
            )
        );
    }
}
