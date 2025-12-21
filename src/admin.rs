use std::sync::Arc;

use rocket::{
    http::Status,
    request::{self, FromRequest},
    Request,
};

use crate::auth::{validate_session_jwt, OidcClient};

/// Authenticated user extracted from session JWT
#[allow(dead_code)]
pub struct AuthenticatedUser {
    pub username: String,
    pub email: String,
    pub groups: Vec<String>,
}

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

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AuthenticatedUser {
    type Error = AuthError;

    async fn from_request(req: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        // Debug mode: return fake admin user
        if cfg!(debug_assertions) {
            return request::Outcome::Success(AuthenticatedUser {
                username: "AdminBot".to_string(),
                email: "admin@debug.local".to_string(),
                groups: vec!["admin".to_string()],
            });
        }

        // Get OIDC client from managed state
        let oidc = match req.rocket().state::<Arc<OidcClient>>() {
            Some(oidc) => oidc,
            None => {
                return request::Outcome::Error((
                    Status::InternalServerError,
                    AuthError::NotConfigured,
                ))
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

        // Check if user has required admin group
        if !claims.groups.contains(&oidc.config.admin_group) {
            return request::Outcome::Error((Status::Forbidden, AuthError::Forbidden));
        }

        request::Outcome::Success(AuthenticatedUser {
            username: claims.username,
            email: claims.email,
            groups: claims.groups,
        })
    }
}

// Keep the old Admin type as an alias for backward compatibility
pub type Admin = AuthenticatedUser;

/// Management user - requires either admin or management group membership
#[allow(dead_code)]
pub struct ManagementUser {
    pub username: String,
    pub email: String,
    pub groups: Vec<String>,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for ManagementUser {
    type Error = AuthError;

    async fn from_request(req: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        // Debug mode: return fake management user
        if cfg!(debug_assertions) {
            return request::Outcome::Success(ManagementUser {
                username: "ManagementBot".to_string(),
                email: "management@debug.local".to_string(),
                groups: vec!["management".to_string(), "admin".to_string()],
            });
        }

        // Get OIDC client from managed state
        let oidc = match req.rocket().state::<Arc<OidcClient>>() {
            Some(oidc) => oidc,
            None => {
                return request::Outcome::Error((
                    Status::InternalServerError,
                    AuthError::NotConfigured,
                ))
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

        // Check if user has required admin or management group
        let has_admin = claims.groups.contains(&oidc.config.admin_group);
        let has_management = claims.groups.contains(&oidc.config.management_group);

        if !has_admin || !has_management {
            return request::Outcome::Error((Status::Forbidden, AuthError::Forbidden));
        }

        request::Outcome::Success(ManagementUser {
            username: claims.username,
            email: claims.email,
            groups: claims.groups,
        })
    }
}
