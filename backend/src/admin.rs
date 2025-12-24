use std::sync::Arc;

use rocket::{
    Request,
    http::Status,
    request::{self, FromRequest},
};

use crate::auth::{OidcClient, SessionClaims, validate_session_jwt};

/// Errors that can occur during authentication
#[derive(Debug)]
#[allow(dead_code)]
pub enum AuthError {
    /// No session cookie present
    Missing,
    /// Session JWT is invalid or malformed
    Invalid(String),
    /// Session has expired
    Expired,
    /// User lacks required group membership
    Forbidden,
    /// OIDC client not configured
    NotConfigured,
}

const SESSION_COOKIE_NAME: &str = "session";

/// Trait for defining permission requirements
pub trait PermissionLevel: Send + Sync {
    /// Check if the user's groups satisfy this permission level
    fn is_authorized(claims: &SessionClaims, oidc: &OidcClient) -> bool;

    /// Debug mode username
    fn debug_username() -> &'static str;

    /// Debug mode groups
    fn debug_groups() -> Vec<String>;
}

pub struct Staff;

impl PermissionLevel for Staff {
    fn is_authorized(claims: &SessionClaims, oidc: &OidcClient) -> bool {
        claims.groups.contains(&oidc.config.staff_group)
    }

    fn debug_username() -> &'static str {
        "StaffBot"
    }

    fn debug_groups() -> Vec<String> {
        vec!["staff".to_string()]
    }
}

#[allow(dead_code)]
pub struct Management;

impl PermissionLevel for Management {
    fn is_authorized(claims: &SessionClaims, oidc: &OidcClient) -> bool {
        claims.groups.contains(&oidc.config.staff_group)
            && claims.groups.contains(&oidc.config.management_group)
    }

    fn debug_username() -> &'static str {
        "ManagementBot"
    }

    fn debug_groups() -> Vec<String> {
        vec!["management".to_string(), "staff".to_string()]
    }
}

/// Generic authenticated user with permission level
#[allow(dead_code)]
pub struct AuthenticatedUser<P: PermissionLevel> {
    pub username: String,
    pub ckey: String,
    pub email: String,
    pub groups: Vec<String>,
    _permission: std::marker::PhantomData<P>,
}

impl<P: PermissionLevel> AuthenticatedUser<P> {
    fn new(username: String, ckey: String, email: String, groups: Vec<String>) -> Self {
        Self {
            username,
            ckey,
            email,
            groups,
            _permission: std::marker::PhantomData,
        }
    }
}

#[rocket::async_trait]
impl<'r, P: PermissionLevel + 'static> FromRequest<'r> for AuthenticatedUser<P> {
    type Error = AuthError;

    async fn from_request(req: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        // Debug mode: return fake user
        if cfg!(debug_assertions) {
            return request::Outcome::Success(AuthenticatedUser::new(
                P::debug_username().to_string(),
                P::debug_username().to_lowercase(),
                format!("{}@debug.local", P::debug_username().to_lowercase()),
                P::debug_groups(),
            ));
        }

        // Get OIDC client from managed state
        let oidc = match req.rocket().state::<Arc<OidcClient>>() {
            Some(oidc) => oidc,
            None => {
                return request::Outcome::Error((
                    Status::InternalServerError,
                    AuthError::NotConfigured,
                ));
            }
        };

        // Get session cookie
        let session_cookie = match req.cookies().get(SESSION_COOKIE_NAME) {
            Some(cookie) => cookie,
            None => return request::Outcome::Error((Status::Unauthorized, AuthError::Missing)),
        };

        // Validate session JWT
        let claims = match validate_session_jwt(session_cookie.value(), &oidc.config.session_secret)
        {
            Ok(claims) => claims,
            Err(e) => {
                if e.contains("ExpiredSignature") {
                    return request::Outcome::Error((Status::Unauthorized, AuthError::Expired));
                }
                return request::Outcome::Error((Status::Unauthorized, AuthError::Invalid(e)));
            }
        };

        // Check permission level
        if !P::is_authorized(&claims, oidc) {
            return request::Outcome::Error((Status::Forbidden, AuthError::Forbidden));
        }

        request::Outcome::Success(AuthenticatedUser::new(
            claims.username,
            claims.ckey,
            claims.email,
            claims.groups,
        ))
    }
}
