//! Who is asking: SidiOS's gateway (Caddy `forward_auth`) removes every `X-Webos-*` header a
//! client sends and sets its own, so these headers are the only identity Remota knows. There is no
//! Remota sign-in. A request without a well-formed `X-Webos-User` never reaches a handler.

use axum::{
    extract::{FromRequestParts, Request},
    http::{request::Parts, HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

/// The signed-in SidiOS user, as named by the gateway.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebosUser {
    /// Stable, opaque per-user key (24 lowercase hex). Every stored row is keyed by it.
    pub key: String,
    /// Login name, for display only.
    pub login: String,
    /// Display name, for display only.
    pub name: String,
}

impl WebosUser {
    pub fn from_headers(headers: &HeaderMap) -> Option<Self> {
        let key = header(headers, "x-webos-user")?;
        if !valid_key(&key) {
            return None;
        }
        Some(Self {
            login: header(headers, "x-webos-login").unwrap_or_default(),
            name: header(headers, "x-webos-name").unwrap_or_default(),
            key,
        })
    }
}

fn header(headers: &HeaderMap, name: &str) -> Option<String> {
    let values: Vec<_> = headers.get_all(name).iter().collect();
    // A repeated identity header is never trusted.
    match values.as_slice() {
        [value] => value.to_str().ok().map(str::to_owned),
        _ => None,
    }
}

fn valid_key(key: &str) -> bool {
    key.len() == 24
        && key
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({ "code": "unauthorized" })),
    )
        .into_response()
}

/// Middleware: refuses any request without a valid identity and hands the user to handlers.
pub async fn require_identity(mut request: Request, next: Next) -> Response {
    match WebosUser::from_headers(request.headers()) {
        Some(user) => {
            request.extensions_mut().insert(user);
            next.run(request).await
        }
        None => unauthorized(),
    }
}

impl<S: Send + Sync> FromRequestParts<S> for WebosUser {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<WebosUser>()
            .cloned()
            .ok_or_else(unauthorized)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(*name, HeaderValue::from_static(value));
        }
        map
    }

    #[test]
    fn reads_the_gateway_identity() {
        let user = WebosUser::from_headers(&headers(&[
            ("x-webos-user", "0123456789abcdef01234567"),
            ("x-webos-login", "u-0123456789ab"),
            ("x-webos-name", "Ada Lovelace"),
        ]))
        .unwrap();
        assert_eq!(user.key, "0123456789abcdef01234567");
        assert_eq!(user.login, "u-0123456789ab");
        assert_eq!(user.name, "Ada Lovelace");
    }

    #[test]
    fn refuses_missing_malformed_or_repeated_keys() {
        for bad in [
            vec![],
            vec![("x-webos-user", "")],
            vec![("x-webos-user", "0123456789ABCDEF01234567")],
            vec![("x-webos-user", "0123456789abcdef0123456")],
            vec![("x-webos-user", "0123456789abcdef012345678")],
            vec![("x-webos-user", "../../etc/passwd/xxxxxxxx")],
            vec![
                ("x-webos-user", "0123456789abcdef01234567"),
                ("x-webos-user", "76543210fedcba9876543210"),
            ],
        ] {
            assert_eq!(WebosUser::from_headers(&headers(&bad)), None, "{bad:?}");
        }
    }
}
