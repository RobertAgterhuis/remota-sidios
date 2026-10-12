//! The SidiOS side of Remota: webOS's private API on the internal `remota-control` network
//! (SidiOS `specs/015-remota/contracts/vault-and-identity.md`). webOS keeps every secret, issues
//! session tickets, and holds the administrator's policy; Remota names users by their gateway key.

use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use reqwest::StatusCode;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Debug, PartialEq, Eq)]
pub enum WebosError {
    /// webOS refused the request for this user or input (4xx), with its code.
    Refused(StatusCode, String),
    /// webOS could not be reached or answered something unexpected.
    Unavailable,
}

pub type WebosResult<T> = Result<T, WebosError>;

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct CredentialSummary {
    pub id: String,
    pub kind: String,
    pub label: String,
    pub username: Option<String>,
}

/// A secret to seal; `id` replaces the user's own credential with that ID.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NewCredential {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub kind: String,
    pub label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    pub secret: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub passphrase: Option<String>,
}

/// What a session ticket covers, as Remota asks webOS to issue it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TicketRequest {
    pub connection_id: String,
    pub credential_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jump: Option<String>,
    pub protocol: String,
    pub target: String,
}

/// An opened credential, returned only when a ticket is consumed.
#[derive(Clone, Deserialize, PartialEq, Eq)]
pub struct OpenedCredential {
    pub id: String,
    pub kind: String,
    pub username: Option<String>,
    pub secret: String,
    pub passphrase: Option<String>,
}

impl std::fmt::Debug for OpenedCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print a secret, even in a test failure or a log line.
        f.debug_struct("OpenedCredential")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Grant {
    pub connection_id: String,
    pub protocol: String,
    pub target: String,
    pub jump: Option<String>,
    pub credentials: Vec<OpenedCredential>,
}

/// One audit event; webOS checks the name and fields against an allowlist.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AuditEvent {
    pub event: &'static str,
    pub outcome: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}

#[async_trait]
pub trait Webos: Send + Sync {
    async fn list_credentials(&self, user: &str) -> WebosResult<Vec<CredentialSummary>>;
    async fn save_credential(&self, user: &str, credential: NewCredential) -> WebosResult<String>;
    async fn delete_credential(&self, user: &str, id: &str) -> WebosResult<()>;
    /// The policy, or `None` while `known_revision` is current.
    async fn policy(&self, known_revision: u64) -> WebosResult<Option<crate::policy::Policy>>;
    async fn issue_ticket(&self, user: &str, request: TicketRequest) -> WebosResult<String>;
    async fn consume_ticket(&self, user: &str, ticket: &str) -> WebosResult<Grant>;
    /// The IDs of running sessions that must end; an error means "end them all".
    async fn check_sessions(&self, sessions: &[(String, String)]) -> WebosResult<Vec<String>>;
    /// Best effort: an audit failure never blocks or ends a session.
    async fn audit(&self, user: &str, event: AuditEvent);
}

pub type SharedWebos = Arc<dyn Webos>;

/// webOS over HTTP with the shared service token.
pub struct HttpWebos {
    base: String,
    client: reqwest::Client,
    token: String,
}

impl HttpWebos {
    pub fn new(base: &str, token: String) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("HTTP client");
        Self {
            base: base.trim_end_matches('/').to_owned(),
            client,
            token,
        }
    }

    pub(crate) async fn post(&self, path: &str, body: Value) -> WebosResult<(StatusCode, Value)> {
        let response = self
            .client
            .post(format!("{}/api/internal/remota/{path}", self.base))
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await
            .map_err(|_| WebosError::Unavailable)?;
        let status = response.status();
        let body = if status == StatusCode::NO_CONTENT || status == StatusCode::NOT_MODIFIED {
            Value::Null
        } else {
            response.json().await.map_err(|_| WebosError::Unavailable)?
        };
        if status.is_client_error() {
            let code = body["code"].as_str().unwrap_or("refused").to_owned();
            return Err(WebosError::Refused(status, code));
        }
        if !status.is_success() && status != StatusCode::NOT_MODIFIED {
            return Err(WebosError::Unavailable);
        }
        Ok((status, body))
    }

    pub(crate) async fn post_as<T: DeserializeOwned>(
        &self,
        path: &str,
        body: Value,
    ) -> WebosResult<T> {
        let (_, value) = self.post(path, body).await?;
        serde_json::from_value(value).map_err(|_| WebosError::Unavailable)
    }
}

#[async_trait]
impl Webos for HttpWebos {
    async fn list_credentials(&self, user: &str) -> WebosResult<Vec<CredentialSummary>> {
        #[derive(Deserialize)]
        struct Listing {
            credentials: Vec<CredentialSummary>,
        }
        let listing: Listing = self
            .post_as("credentials/list", json!({ "userId": user }))
            .await?;
        Ok(listing.credentials)
    }

    async fn save_credential(&self, user: &str, credential: NewCredential) -> WebosResult<String> {
        #[derive(Deserialize)]
        struct Saved {
            id: String,
        }
        let mut body = serde_json::to_value(credential).map_err(|_| WebosError::Unavailable)?;
        body["userId"] = json!(user);
        let saved: Saved = self.post_as("credentials/save", body).await?;
        Ok(saved.id)
    }

    async fn delete_credential(&self, user: &str, id: &str) -> WebosResult<()> {
        self.post("credentials/delete", json!({ "userId": user, "id": id }))
            .await
            .map(|_| ())
    }
    async fn policy(&self, known_revision: u64) -> WebosResult<Option<crate::policy::Policy>> {
        let (status, body) = self
            .post("policy", json!({ "knownRevision": known_revision }))
            .await?;
        if status == StatusCode::NOT_MODIFIED {
            return Ok(None);
        }
        serde_json::from_value(body)
            .map(Some)
            .map_err(|_| WebosError::Unavailable)
    }

    async fn issue_ticket(&self, user: &str, request: TicketRequest) -> WebosResult<String> {
        #[derive(Deserialize)]
        struct Issued {
            ticket: String,
        }
        let mut body = serde_json::to_value(request).map_err(|_| WebosError::Unavailable)?;
        body["userId"] = json!(user);
        let issued: Issued = self.post_as("tickets", body).await?;
        Ok(issued.ticket)
    }

    async fn consume_ticket(&self, user: &str, ticket: &str) -> WebosResult<Grant> {
        self.post_as(
            "tickets/consume",
            json!({ "userId": user, "ticket": ticket }),
        )
        .await
    }

    async fn check_sessions(&self, sessions: &[(String, String)]) -> WebosResult<Vec<String>> {
        #[derive(Deserialize)]
        struct Ending {
            end: Vec<String>,
        }
        let sessions: Vec<Value> = sessions
            .iter()
            .map(|(user, id)| json!({ "userId": user, "sessionId": id }))
            .collect();
        let ending: Ending = self
            .post_as("sessions/check", json!({ "sessions": sessions }))
            .await?;
        Ok(ending.end)
    }

    async fn audit(&self, user: &str, event: AuditEvent) {
        let Ok(mut body) = serde_json::to_value(event) else {
            return;
        };
        body["userId"] = json!(user);
        let _ = self.post("audit", body).await;
    }
}

#[cfg(test)]
pub mod fake {
    //! An in-memory webOS for tests: credentials per user, secrets kept to assert on.

    use std::{
        collections::BTreeMap,
        sync::{Mutex, MutexGuard},
    };

    use super::*;

    #[derive(Clone, Debug)]
    pub struct StoredCredential {
        pub user: String,
        pub summary: CredentialSummary,
        pub secret: String,
        pub passphrase: Option<String>,
    }

    #[derive(Default)]
    pub struct FakeWebos {
        pub credentials: Mutex<BTreeMap<String, StoredCredential>>,
        next: Mutex<u32>,
        pub policy: Mutex<Option<crate::policy::Policy>>,
        /// ticket → (user, request)
        pub tickets: Mutex<BTreeMap<String, (String, TicketRequest)>>,
        pub inactive: Mutex<Vec<String>>,
        pub audits: Mutex<Vec<(String, AuditEvent)>>,
    }

    impl FakeWebos {
        pub fn credentials(&self) -> MutexGuard<'_, BTreeMap<String, StoredCredential>> {
            self.credentials.lock().unwrap()
        }
    }

    #[async_trait]
    impl Webos for FakeWebos {
        async fn list_credentials(&self, user: &str) -> WebosResult<Vec<CredentialSummary>> {
            Ok(self
                .credentials()
                .values()
                .filter(|stored| stored.user == user)
                .map(|stored| stored.summary.clone())
                .collect())
        }

        async fn save_credential(
            &self,
            user: &str,
            credential: NewCredential,
        ) -> WebosResult<String> {
            let id = match credential.id {
                Some(id) => id,
                None => {
                    let mut next = self.next.lock().unwrap();
                    *next += 1;
                    format!("00000000-0000-4000-8000-{:012}", *next)
                }
            };
            let mut credentials = self.credentials();
            if credentials
                .get(&id)
                .is_some_and(|stored| stored.user != user)
            {
                return Err(WebosError::Refused(
                    StatusCode::NOT_FOUND,
                    "not_found".into(),
                ));
            }
            credentials.insert(
                id.clone(),
                StoredCredential {
                    user: user.to_owned(),
                    summary: CredentialSummary {
                        id: id.clone(),
                        kind: credential.kind,
                        label: credential.label,
                        username: credential.username,
                    },
                    secret: credential.secret,
                    passphrase: credential.passphrase,
                },
            );
            Ok(id)
        }

        async fn delete_credential(&self, user: &str, id: &str) -> WebosResult<()> {
            let mut credentials = self.credentials();
            match credentials.get(id) {
                Some(stored) if stored.user == user => {
                    credentials.remove(id);
                    Ok(())
                }
                _ => Err(WebosError::Refused(
                    StatusCode::NOT_FOUND,
                    "not_found".into(),
                )),
            }
        }
        async fn policy(&self, known_revision: u64) -> WebosResult<Option<crate::policy::Policy>> {
            match self.policy.lock().unwrap().clone() {
                Some(policy) if policy.revision == known_revision => Ok(None),
                Some(policy) => Ok(Some(policy)),
                None => Err(WebosError::Unavailable),
            }
        }

        async fn issue_ticket(&self, user: &str, request: TicketRequest) -> WebosResult<String> {
            let owned = request.credential_ids.iter().all(|id| {
                self.credentials()
                    .get(id)
                    .is_some_and(|stored| stored.user == user)
            });
            if !owned {
                return Err(WebosError::Refused(
                    StatusCode::FORBIDDEN,
                    "forbidden".into(),
                ));
            }
            let ticket = format!("ticket-{}", uuid::Uuid::new_v4());
            self.tickets
                .lock()
                .unwrap()
                .insert(ticket.clone(), (user.to_owned(), request));
            Ok(ticket)
        }

        async fn consume_ticket(&self, user: &str, ticket: &str) -> WebosResult<Grant> {
            let mut tickets = self.tickets.lock().unwrap();
            match tickets.get(ticket) {
                Some((owner, _)) if owner == user => {}
                _ => {
                    return Err(WebosError::Refused(
                        StatusCode::GONE,
                        "ticket_invalid".into(),
                    ))
                }
            }
            let (_, request) = tickets.remove(ticket).expect("present");
            let credentials = self.credentials();
            Ok(Grant {
                connection_id: request.connection_id,
                protocol: request.protocol,
                target: request.target,
                jump: request.jump,
                credentials: request
                    .credential_ids
                    .iter()
                    .filter_map(|id| credentials.get(id))
                    .map(|stored| OpenedCredential {
                        id: stored.summary.id.clone(),
                        kind: stored.summary.kind.clone(),
                        username: stored.summary.username.clone(),
                        secret: stored.secret.clone(),
                        passphrase: stored.passphrase.clone(),
                    })
                    .collect(),
            })
        }

        async fn check_sessions(&self, sessions: &[(String, String)]) -> WebosResult<Vec<String>> {
            let inactive = self.inactive.lock().unwrap();
            Ok(sessions
                .iter()
                .filter(|(user, _)| inactive.contains(user))
                .map(|(_, id)| id.clone())
                .collect())
        }

        async fn audit(&self, user: &str, event: AuditEvent) {
            self.audits.lock().unwrap().push((user.to_owned(), event));
        }
    }
}
