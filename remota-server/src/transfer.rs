//! Import and export (SidiOS `contracts/remota-api.md`, "Import and export"):
//!
//! - `POST /api/import/mremoteng` (multipart `file`, optional `masterPassword`) adds the file's tree
//!   in a new folder named after the file; passwords are sealed through webOS first.
//! - `POST /api/import/remota` (multipart `file`) adds a Remota JSON export at the top level.
//! - `GET /api/export` downloads the tree as Remota JSON without any secret or credential ID.

use axum::{
    extract::{DefaultBodyLimit, Multipart, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use zeroize::Zeroizing;

use crate::{
    identity::WebosUser,
    importer::{self, ImportError, Report, MAX_FILE_BYTES},
    model::{Credentials, Document, Node},
    tree::{blocking, change, collect_garbage, ApiError, ApiResult},
    webos::{AuditEvent, NewCredential, SharedWebos},
    AppState,
};

const EXPORT_FORMAT: &str = "remota-sidios";
const EXPORT_VERSION: u32 = 1;

pub fn routes() -> Router<AppState> {
    // Multipart framing on top of the 5 MB file.
    let upload_limit = DefaultBodyLimit::max(MAX_FILE_BYTES + 64 * 1024);
    Router::new()
        .route(
            "/api/import/mremoteng",
            post(import_mremoteng).layer(upload_limit),
        )
        .route(
            "/api/import/remota",
            post(import_remota).layer(upload_limit),
        )
        .route("/api/export", get(export))
}

struct Upload {
    file_name: String,
    bytes: Vec<u8>,
    master_password: Option<Zeroizing<String>>,
}

fn too_large() -> ApiError {
    ApiError(StatusCode::PAYLOAD_TOO_LARGE, "file_too_large")
}

async fn read_upload(mut multipart: Multipart) -> ApiResult<Upload> {
    let invalid = || ApiError(StatusCode::BAD_REQUEST, "invalid_file");
    let mut upload = Upload {
        file_name: String::new(),
        bytes: Vec::new(),
        master_password: None,
    };
    let mut has_file = false;
    while let Some(field) = multipart.next_field().await.map_err(|_| too_large())? {
        match field.name() {
            Some("file") => {
                upload.file_name = field.file_name().unwrap_or("").to_owned();
                let bytes = field.bytes().await.map_err(|_| too_large())?;
                if bytes.len() > MAX_FILE_BYTES {
                    return Err(too_large());
                }
                upload.bytes = bytes.to_vec();
                has_file = true;
            }
            Some("masterPassword") => {
                let text = field.text().await.map_err(|_| invalid())?;
                upload.master_password = Some(Zeroizing::new(text));
            }
            _ => return Err(invalid()),
        }
    }
    if has_file {
        Ok(upload)
    } else {
        Err(invalid())
    }
}

/// The folder name for an import: the file name without its extension.
fn folder_name(file_name: &str) -> String {
    let base = file_name.rsplit(['/', '\\']).next().unwrap_or("");
    let stem = base.rsplit_once('.').map_or(base, |(stem, _)| stem);
    importer::clean_name(if stem.is_empty() {
        "mRemoteNG import"
    } else {
        stem
    })
}

fn import_error(error: &ImportError) -> ApiError {
    let status = match error {
        ImportError::InvalidFile => StatusCode::BAD_REQUEST,
        _ => StatusCode::UNPROCESSABLE_ENTITY,
    };
    ApiError(status, error.code())
}

async fn audit(webos: &SharedWebos, user: &str, event: &'static str, outcome: &'static str) {
    webos
        .audit(
            user,
            AuditEvent {
                event,
                outcome,
                protocol: None,
                host: None,
                port: None,
            },
        )
        .await;
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ImportAnswer {
    document: Document,
    report: Report,
    folder_id: Option<String>,
}

async fn import_mremoteng(
    State(state): State<AppState>,
    user: WebosUser,
    multipart: Multipart,
) -> ApiResult<Json<ImportAnswer>> {
    let result = mremoteng(&state, &user, multipart).await;
    let outcome = if result.is_ok() { "imported" } else { "failed" };
    audit(&state.webos, &user.key, "remota.import", outcome).await;
    result
}

async fn mremoteng(
    state: &AppState,
    user: &WebosUser,
    multipart: Multipart,
) -> ApiResult<Json<ImportAnswer>> {
    let upload = read_upload(multipart).await?;
    let name = folder_name(&upload.file_name);
    let xml = Zeroizing::new(
        String::from_utf8(upload.bytes)
            .map_err(|_| ApiError(StatusCode::BAD_REQUEST, "invalid_file"))?,
    );
    let master = upload.master_password;
    // Decryption is CPU-bound (PBKDF2): off the async workers.
    let imported = tokio::task::spawn_blocking(move || {
        importer::parse_mremoteng(&xml, &name, master.as_deref().map(String::as_str))
    })
    .await
    .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "internal_error"))?
    .map_err(|error| import_error(&error))?;
    let mut root = imported.root;
    let sealed = seal_imported(&state.webos, &user.key, &mut root).await;
    let folder_id = root.id().to_owned();
    let saved = match sealed {
        Ok(()) => {
            change(&state.store, &user.key, move |doc| {
                doc.import(vec![root]).map(drop)
            })
            .await
        }
        Err(error) => Err(error),
    };
    // Credentials sealed for an import that was not saved are deleted again.
    collect_garbage(state, &user.key).await;
    Ok(Json(ImportAnswer {
        document: saved?,
        report: imported.report,
        folder_id: Some(folder_id),
    }))
}

/// Seals every imported password; identical (username, domain, password) sets share one
/// credential, labelled `mRemoteNG: <username>[@<domain>]`.
async fn seal_imported(webos: &SharedWebos, user: &str, root: &mut Node) -> ApiResult<()> {
    type Login = (Option<String>, Option<String>, Zeroizing<String>);
    let mut sealed: Vec<(Login, String)> = Vec::new();
    let mut pending: Vec<&mut Credentials> = Vec::new();
    collect(root, &mut pending);
    for credentials in pending {
        let Some(password) = credentials.secret.password.take().map(Zeroizing::new) else {
            continue;
        };
        let key = (
            credentials.username.clone(),
            credentials.domain.clone(),
            password,
        );
        let known = sealed
            .iter()
            .find(|(login, _)| login.0 == key.0 && login.1 == key.1 && *login.2 == *key.2);
        let id = match known {
            Some((_, id)) => id.clone(),
            None => {
                let label = match (&key.0, &key.1) {
                    (Some(user), Some(domain)) => format!("mRemoteNG: {user}@{domain}"),
                    (Some(user), None) => format!("mRemoteNG: {user}"),
                    _ => "mRemoteNG".to_owned(),
                };
                let credential = NewCredential {
                    id: None,
                    kind: "password".into(),
                    label: label.chars().take(120).collect(),
                    username: key.0.clone(),
                    secret: key.2.to_string(),
                    passphrase: None,
                };
                let id = webos.save_credential(user, credential).await?;
                sealed.push((key, id.clone()));
                id
            }
        };
        credentials.secret.credential_id = Some(id);
    }
    Ok(())
}

fn collect<'a>(node: &'a mut Node, out: &mut Vec<&'a mut Credentials>) {
    match node {
        Node::Folder {
            defaults, children, ..
        } => {
            out.push(defaults);
            for child in children {
                collect(child, out);
            }
        }
        Node::Connection { conn, .. } => out.push(&mut conn.credentials),
    }
}

#[derive(Deserialize)]
struct RemotaFile {
    #[serde(default)]
    format: Option<String>,
    nodes: Vec<Node>,
}

async fn import_remota(
    State(state): State<AppState>,
    user: WebosUser,
    multipart: Multipart,
) -> ApiResult<Json<ImportAnswer>> {
    let result = remota(&state, &user, multipart).await;
    let outcome = if result.is_ok() { "imported" } else { "failed" };
    audit(&state.webos, &user.key, "remota.import", outcome).await;
    result
}

async fn remota(
    state: &AppState,
    user: &WebosUser,
    multipart: Multipart,
) -> ApiResult<Json<ImportAnswer>> {
    let upload = read_upload(multipart).await?;
    let invalid = || ApiError(StatusCode::BAD_REQUEST, "invalid_file");
    let file: RemotaFile = serde_json::from_slice(&upload.bytes).map_err(|_| invalid())?;
    if file.format.as_deref().is_some_and(|f| f != EXPORT_FORMAT) {
        return Err(invalid());
    }
    let mut nodes = file.nodes;
    // A file never brings secrets or another account's credential IDs; every node gets a new ID.
    for node in &mut nodes {
        importer::strip_secrets(node, true);
    }
    let mut report = Report::default();
    count(&nodes, &mut report);
    let document = change(&state.store, &user.key, move |doc| {
        doc.import(nodes).map(drop)
    })
    .await?;
    Ok(Json(ImportAnswer {
        document,
        report,
        folder_id: None,
    }))
}

fn count(nodes: &[Node], report: &mut Report) {
    for node in nodes {
        match node {
            Node::Folder { children, .. } => {
                report.folders += 1;
                count(children, report);
            }
            Node::Connection { .. } => report.connections += 1,
        }
    }
}

async fn export(State(state): State<AppState>, user: WebosUser) -> ApiResult<Response> {
    let store = state.store.clone();
    let key = user.key.clone();
    let mut nodes = blocking(move || store.for_user(&key).document())
        .await?
        .nodes;
    for node in &mut nodes {
        importer::strip_secrets(node, false);
    }
    audit(&state.webos, &user.key, "remota.export", "exported").await;
    let body = json!({
        "format": EXPORT_FORMAT,
        "version": EXPORT_VERSION,
        "nodes": nodes,
    });
    Ok((
        [
            (header::CONTENT_TYPE, "application/json"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"remota-export.json\"",
            ),
            (header::CACHE_CONTROL, "private, no-store"),
        ],
        Json(body),
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use std::{path::PathBuf, sync::Arc};

    use axum::{body::Body, http::Request};
    use http_body_util::BodyExt;
    use serde_json::Value;
    use tower::ServiceExt;

    use super::*;
    use crate::{router, store::Store, webos::fake::FakeWebos};

    const ADA: &str = "0123456789abcdef01234567";
    const BOUNDARY: &str = "remota-test-boundary";

    struct Harness {
        webos: Arc<FakeWebos>,
        state: AppState,
        _dir: tempfile::TempDir,
    }

    impl Harness {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let store = Store::open(&dir.path().join("remota.db")).unwrap();
            let webos = Arc::new(FakeWebos::default());
            let state = AppState::new(store, webos.clone());
            Self {
                webos,
                state,
                _dir: dir,
            }
        }

        async fn send(&self, request: Request<Body>) -> (StatusCode, Value, String) {
            let response = router(PathBuf::from("missing-ui"), self.state.clone())
                .oneshot(request)
                .await
                .unwrap();
            let status = response.status();
            let disposition = response
                .headers()
                .get(header::CONTENT_DISPOSITION)
                .map(|v| v.to_str().unwrap().to_owned())
                .unwrap_or_default();
            let bytes = response.into_body().collect().await.unwrap().to_bytes();
            let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
            (status, body, disposition)
        }

        async fn upload(
            &self,
            path: &str,
            file_name: &str,
            content: &[u8],
            master: Option<&str>,
        ) -> (StatusCode, Value) {
            let mut body = Vec::new();
            if let Some(master) = master {
                body.extend_from_slice(
                    format!(
                        "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"masterPassword\"\r\n\r\n{master}\r\n"
                    )
                    .as_bytes(),
                );
            }
            body.extend_from_slice(
                format!(
                    "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{file_name}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
                )
                .as_bytes(),
            );
            body.extend_from_slice(content);
            body.extend_from_slice(format!("\r\n--{BOUNDARY}--\r\n").as_bytes());
            let request = Request::post(path)
                .header("x-webos-user", ADA)
                .header(
                    "content-type",
                    format!("multipart/form-data; boundary={BOUNDARY}"),
                )
                .body(Body::from(body))
                .unwrap();
            let (status, body, _) = self.send(request).await;
            (status, body)
        }

        async fn export(&self) -> (StatusCode, Value, String) {
            self.send(
                Request::get("/api/export")
                    .header("x-webos-user", ADA)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
        }

        fn audits(&self) -> Vec<(&'static str, &'static str)> {
            self.webos
                .audits
                .lock()
                .unwrap()
                .iter()
                .map(|(_, event)| (event.event, event.outcome))
                .collect()
        }
    }

    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(format!(
            "{}/tests/fixtures/mremoteng/confCons.{name}.xml",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    }

    #[tokio::test]
    async fn imports_mremoteng_with_passwords_sealed_and_shared_then_exports_without_secrets() {
        let h = Harness::new();
        let (status, body) = h
            .upload(
                "/api/import/mremoteng",
                "confCons.xml",
                &fixture("gcm-custom"),
                Some("fixture-master-ü"),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["report"]["connections"], 4);
        assert_eq!(body["report"]["passwords"], 4);
        assert_eq!(body["document"]["nodes"][0]["name"], "confCons");
        let text = body.to_string();
        assert!(!text.contains("not-a-secret"), "no plaintext in the answer");

        // Three distinct (username, domain, password) sets: the two identical RDP logins share one.
        {
            let credentials = h.webos.credentials();
            assert_eq!(credentials.len(), 3);
            let labels: Vec<&str> = credentials
                .values()
                .map(|c| c.summary.label.as_str())
                .collect();
            assert!(labels.contains(&"mRemoteNG: administrator@CORP"));
            assert!(credentials
                .values()
                .any(|c| c.secret == "not-a-secret-folder"
                    && c.summary.label == "mRemoteNG: ops@CORP"));
        }
        assert!(
            h.state
                .store
                .for_user(ADA)
                .document()
                .unwrap()
                .credential_ids()
                .len()
                == 3
        );

        let (status, exported, disposition) = h.export().await;
        assert_eq!(status, StatusCode::OK);
        assert!(disposition.starts_with("attachment;"));
        assert_eq!(exported["format"], "remota-sidios");
        let text = exported.to_string();
        for marker in [
            "credential_id",
            "password",
            "private_key",
            "passphrase",
            "not-a-secret",
        ] {
            assert!(!text.contains(marker), "export contains {marker}");
        }
        assert_eq!(
            h.audits(),
            [("remota.import", "imported"), ("remota.export", "exported")]
        );

        // Re-import into an empty tree: same structure, new IDs, no secrets.
        let fresh = Harness::new();
        let file = serde_json::to_vec(&exported).unwrap();
        let (status, body) = fresh
            .upload("/api/import/remota", "remota-export.json", &file, None)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["report"]["connections"], 4);
        let reimported = &body["document"]["nodes"][0];
        assert_eq!(reimported["name"], "confCons");
        assert_ne!(reimported["id"], exported["nodes"][0]["id"]);
    }

    #[tokio::test]
    async fn imports_nothing_with_a_wrong_or_missing_master_password() {
        let h = Harness::new();
        for (master, code) in [
            (Some("wrong"), "wrong_master_password"),
            (None, "master_password_required"),
        ] {
            let (status, body) = h
                .upload(
                    "/api/import/mremoteng",
                    "confCons.xml",
                    &fixture("gcm-custom"),
                    master,
                )
                .await;
            assert_eq!(
                (status, body),
                (StatusCode::UNPROCESSABLE_ENTITY, json!({ "code": code }))
            );
        }
        assert!(h.webos.credentials().is_empty());
        assert!(h
            .state
            .store
            .for_user(ADA)
            .document()
            .unwrap()
            .nodes
            .is_empty());
        assert_eq!(
            h.audits(),
            [("remota.import", "failed"), ("remota.import", "failed")]
        );
    }

    #[tokio::test]
    async fn refuses_large_invalid_and_secret_carrying_files() {
        let h = Harness::new();
        let big = vec![b' '; MAX_FILE_BYTES + 1];
        let (status, _) = h
            .upload("/api/import/mremoteng", "big.xml", &big, None)
            .await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        let (status, body) = h
            .upload("/api/import/mremoteng", "x.xml", b"<html/>", None)
            .await;
        assert_eq!(
            (status, body),
            (StatusCode::BAD_REQUEST, json!({ "code": "invalid_file" }))
        );
        let (status, _) = h
            .upload(
                "/api/import/remota",
                "x.json",
                b"{\"format\":\"other\",\"nodes\":[]}",
                None,
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // Secrets and foreign credential IDs in a JSON file are dropped, never sealed or kept.
        let carrying = json!({
            "nodes": [{
                "type": "connection", "id": "c1", "name": "web",
                "conn": { "protocol": "ssh", "host": "10.0.0.5",
                          "credentials": { "credential_id": "someone-elses", "password": "pw" } }
            }]
        });
        let (status, body) = h
            .upload(
                "/api/import/remota",
                "x.json",
                &serde_json::to_vec(&carrying).unwrap(),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        assert!(!body.to_string().contains("someone-elses"));
        assert!(h.webos.credentials().is_empty());
        assert!(h
            .state
            .store
            .for_user(ADA)
            .document()
            .unwrap()
            .credential_ids()
            .is_empty());
        assert!(h.state.store.for_user(ADA).document().unwrap().nodes.len() == 1);
    }

    #[test]
    fn names_the_folder_after_the_file() {
        assert_eq!(folder_name("C:\\Users\\me\\confCons.xml"), "confCons");
        assert_eq!(folder_name("work.backup.xml"), "work.backup");
        assert_eq!(folder_name(""), "mRemoteNG import");
    }
}
