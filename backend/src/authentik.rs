use std::collections::HashMap;

use rocket::{State, http::Status, serde::json::Json};
use rocket_db_pools::Connection;
use sqlx::{query_as, FromRow, Row};
use serde::{Deserialize, Serialize};
use serde_json::Map;
use serenity::all::{GuildId, Http, RoleId, UserId};

use crate::{
    Cmdb, Config, DiscordBotConfig, ServerRoleConfig,
    admin::{AuthenticatedUser, Management, Player, Staff},
    byond::refresh_admins,
    discord::{get_whitelist_status_by_ckey, resolve_whitelist_roles},
    logging::log_external,
    player::{AuthorizationHeader, query_total_playtime_minutes},
};

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct DiscourseConfig {
    /// base URL for the Discourse instance (e.g., "https://forum.example.com")
    pub base_url: String,
    /// API key for Discourse
    pub api_key: String,
    /// API username for Discourse (typically "system")
    pub api_username: String,
    /// the identity provider name as configured in Discourse (e.g., "oidc", "oauth2_basic")
    pub provider_name: String,
    /// optional webhook secret for authenticating incoming Authentik webhooks
    pub webhook_secret: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AuthentikConfig {
    pub token: String,
    pub base_url: String,
    /// OIDC issuer URL for validating access tokens (e.g., "https://auth.example.com/application/o/myapp/")
    /// Used to construct the userinfo endpoint for token validation
    pub oidc_issuer_url: Option<String>,
    /// mapping of permission role names to the Authentik groups they can manage, eg:
    /// [authentik.group_permissions]
    /// staff_management = [ "admins", "moderators" ]
    /// mentor_overseer = [ "mentors" ]
    /// users who are members of a permission role can manage all groups listed for that role
    #[serde(default)]
    pub group_permissions: HashMap<String, Vec<String>>,
    /// list of allowed admin_ranks values that can be toggled on groups
    /// eg: allowed_admin_ranks = ["R_ADMIN", "R_MOD", "R_EVENT"]
    #[serde(default)]
    pub allowed_admin_ranks: Vec<String>,
    /// list of allowed instance names for admin_ranks configuration
    /// eg: allowed_instances = ["cm13-live", "cm13-rp"]
    #[serde(default)]
    pub allowed_instances: Vec<String>,
    /// discourse integration configuration for looking up forum user IDs
    pub discourse: Option<DiscourseConfig>,
    /// webhook secret for authenticating incoming Authentik webhooks (user unlink events, etc.)
    pub webhook_secret: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct UserGroupRequest {
    pub ckey: String,
    pub group_name: String,
}

#[derive(Debug, Deserialize)]
pub struct AuthentikUserSearchResponse {
    pub results: Vec<AuthentikUser>,
}

#[derive(Debug, Deserialize)]
struct AuthentikPagination {
    total_pages: i32,
}

#[derive(Debug, Deserialize)]
struct AuthentikGroupSearchResponse {
    pagination: AuthentikPagination,
    results: Vec<AuthentikGroup>,
}

#[derive(Debug, Deserialize, Clone)]
struct AuthentikGroup {
    pk: String,
    name: String,
    #[serde(default)]
    attributes: serde_json::Value,
    #[serde(rename = "users_obj")]
    users: Vec<AuthentikUser>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AuthentikUser {
    pub pk: i64,
    pub uid: String,
    pub uuid: Option<String>,
    pub name: String,
    pub username: String,
    #[serde(default)]
    pub attributes: serde_json::Value,
}

/// Minimal group info from groups_obj in user response
#[derive(Debug, Deserialize, Clone)]
pub struct AuthentikGroupObj {
    pub name: String,
}

/// Detailed Authentik user response with all fields from the API
#[derive(Debug, Deserialize, Clone)]
pub struct AuthentikUserDetailed {
    pub pk: i64,
    pub uid: String,
    pub uuid: Option<String>,
    pub name: String,
    pub username: String,
    pub email: Option<String>,
    pub is_active: bool,
    pub last_login: Option<String>,
    #[serde(default)]
    pub attributes: serde_json::Value,
    #[serde(default)]
    pub groups_obj: Vec<AuthentikGroupObj>,
}

impl AuthentikUserDetailed {
    pub fn group_names(&self) -> Vec<String> {
        self.groups_obj.iter().map(|g| g.name.clone()).collect()
    }
}

#[derive(Debug, Deserialize)]
pub struct AuthentikUserDetailedSearchResponse {
    pub results: Vec<AuthentikUserDetailed>,
}

#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)]
pub struct OAuthSource {
    pub pk: String,
    pub name: String,
    pub slug: String,
    pub icon: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OAuthSourcesResponse {
    pub results: Vec<OAuthSource>,
}

#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)]
pub struct UserOAuthSourceConnection {
    pub pk: i64,
    pub user: i64,
    #[serde(rename = "source_obj")]
    pub source: OAuthSource,
    pub identifier: String,
}

#[derive(Debug, Deserialize)]
struct UserOAuthSourceConnectionsResponse {
    pub results: Vec<UserOAuthSourceConnection>,
}

#[derive(Debug, Serialize)]
#[serde(crate = "rocket::serde", rename_all = "camelCase")]
pub struct GroupMember {
    pub pk: i64,
    pub username: String,
    pub ckey: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(crate = "rocket::serde", rename_all = "camelCase")]
pub struct GroupMembersResponse {
    pub group_name: String,
    pub members: Vec<GroupMember>,
}

#[derive(Debug, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct AuthentikError {
    pub error: String,
    pub message: String,
}

#[derive(Debug, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct AuthentikSuccess {
    pub message: String,
}

#[derive(Debug, Serialize)]
#[serde(crate = "rocket::serde", rename_all = "camelCase")]
pub struct GroupAdminRanksResponse {
    pub group_name: String,
    pub admin_ranks: Vec<String>,
    pub allowed_ranks: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(crate = "rocket::serde", rename_all = "camelCase")]
pub struct UpdateAdminRanksRequest {
    pub group_name: String,
    pub admin_ranks: Vec<String>,
    pub instance_name: String,
}

#[derive(Debug, Serialize)]
#[serde(crate = "rocket::serde", rename_all = "camelCase")]
pub struct GroupDisplayNameResponse {
    pub group_name: String,
    pub display_name: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(crate = "rocket::serde", rename_all = "camelCase")]
pub struct UpdateDisplayNameRequest {
    pub group_name: String,
    pub display_name: String,
}

#[derive(Debug, Serialize)]
#[serde(crate = "rocket::serde", rename_all = "camelCase")]
pub struct UserAdditionalTitlesResponse {
    pub ckey: String,
    pub additional_titles: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(crate = "rocket::serde", rename_all = "camelCase")]
pub struct UpdateAdditionalTitlesRequest {
    pub ckey: String,
    pub additional_titles: String,
}

/// User info for the admin ranks export endpoint
#[derive(Debug, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct AdminRanksUser {
    pub ckey: String,
    pub groups: Vec<String>,
    pub display_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_title: Option<String>,
}

/// Response for the admin ranks export endpoint
#[derive(Debug, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct AdminRanksExportResponse {
    pub users: Vec<AdminRanksUser>,
    pub groups: HashMap<String, HashMap<String, Vec<String>>>,
}

/// Response for the Discourse user ID lookup endpoint
#[derive(Debug, Serialize)]
#[serde(crate = "rocket::serde", rename_all = "camelCase")]
pub struct DiscourseUserIdResponse {
    pub ckey: String,
    pub discourse_user_id: i64,
    pub discourse_username: String,
}

/// Full Authentik user response for UUID lookup
#[derive(Debug, Serialize)]
#[serde(crate = "rocket::serde", rename_all = "camelCase")]
pub struct AuthentikUserFullResponse {
    pub pk: i64,
    pub uuid: Option<String>,
    pub uid: String,
    pub username: String,
    pub name: String,
    pub is_active: bool,
    pub last_login: Option<String>,
    pub attributes: serde_json::Value,
    pub groups: Vec<String>,
}

/// Simplified Authentik user for search results
#[derive(Debug, Serialize)]
#[serde(crate = "rocket::serde", rename_all = "camelCase")]
pub struct AuthentikUserSearchResult {
    pub pk: i64,
    pub uuid: Option<String>,
    pub username: String,
    pub name: String,
    pub is_active: bool,
}

/// User profile response for self-service account management
#[derive(Debug, Serialize)]
#[serde(crate = "rocket::serde", rename_all = "camelCase")]
pub struct UserProfileResponse {
    pub pk: i64,
    pub uuid: String,
    pub username: String,
    pub name: String,
    pub email: Option<String>,
    pub linked_sources: Vec<LinkedOAuthSource>,
    pub available_sources: Vec<AvailableOAuthSource>,
    pub authentik_base_url: String,
}

/// Linked OAuth source information
#[derive(Debug, Serialize)]
#[serde(crate = "rocket::serde", rename_all = "camelCase")]
pub struct LinkedOAuthSource {
    pub connection_pk: i64,
    pub name: String,
    pub slug: String,
    pub icon: Option<String>,
    pub identifier: String,
    pub parsed_id: Option<String>,
}

/// Available OAuth source for linking
#[derive(Debug, Serialize)]
#[serde(crate = "rocket::serde", rename_all = "camelCase")]
pub struct AvailableOAuthSource {
    pub slug: String,
    pub name: String,
    pub icon: Option<String>,
}

/// Self-service player info response (limited data for the user's own record)
#[derive(Debug, Serialize)]
#[serde(crate = "rocket::serde", rename_all = "camelCase")]
pub struct MyPlayerInfoResponse {
    pub ckey: String,
    pub display_name: String,
    pub notes: Vec<PublicNote>,
    pub job_bans: Vec<PublicJobBan>,
}

/// Non-confidential note visible to the player
#[derive(Debug, Serialize)]
#[serde(crate = "rocket::serde", rename_all = "camelCase")]
pub struct PublicNote {
    pub id: i64,
    pub text: Option<String>,
    pub date: String,
    pub is_ban: bool,
    pub ban_time: Option<i64>,
    pub admin_rank: String,
    pub note_category: Option<i32>,
    pub round_id: Option<i32>,
}

/// Active job ban visible to the player
#[derive(Debug, Serialize)]
#[serde(crate = "rocket::serde", rename_all = "camelCase")]
pub struct PublicJobBan {
    pub id: i64,
    pub text: String,
    pub date: Option<String>,
    pub ban_time: Option<i64>,
    pub expiration: Option<i64>,
    pub role: String,
}

/// Request to update user profile fields
#[derive(Debug, Deserialize)]
#[serde(crate = "rocket::serde", rename_all = "camelCase")]
pub struct UpdateProfileRequest {
    pub name: Option<String>,
    // Email changes require verification via Authentik flow, not direct update
}

#[derive(Debug, Clone)]
struct GroupWithPriority {
    name: String,
    #[allow(dead_code)]
    pk: String,
    priority: i64,
    admin_ranks: HashMap<String, Vec<String>>,
    display_name: Option<String>,
    users: Vec<AuthentikUser>,
}

/// get the list of Authentik groups that a user can manage based on their group memberships
fn get_manageable_groups(config: &AuthentikConfig, user_groups: &[String]) -> Vec<String> {
    let mut manageable = Vec::new();
    for (permission_role, allowed_groups) in &config.group_permissions {
        if user_groups.contains(permission_role) {
            for group in allowed_groups {
                if !manageable.contains(group) {
                    manageable.push(group.clone());
                }
            }
        }
    }
    manageable
}

/// check if a user can manage a specific group based on their group memberships
fn validate_group_allowed(
    config: &AuthentikConfig,
    user_groups: &[String],
    group_name: &str,
) -> Result<(), String> {
    if config.group_permissions.is_empty() {
        return Err(
            "No group permissions are configured. Add group_permissions to the Authentik config."
                .to_string(),
        );
    }

    let manageable = get_manageable_groups(config, user_groups);

    if manageable.is_empty() {
        return Err("You do not have permission to manage any groups.".to_string());
    }

    if !manageable.contains(&group_name.to_string()) {
        return Err(format!(
            "You do not have permission to manage group '{}'. You can manage: {:?}",
            group_name, manageable
        ));
    }

    Ok(())
}

/// GET /Authentik/AllowedGroups - get the list of groups the current user can manage
#[get("/AllowedGroups")]
pub async fn get_allowed_groups(
    user: AuthenticatedUser<Staff>,
    config: &State<Config>,
) -> Result<Json<Vec<String>>, (Status, Json<AuthentikError>)> {
    let authentik_config = config.authentik.as_ref().ok_or_else(|| {
        (
            Status::InternalServerError,
            Json(AuthentikError {
                error: "not_configured".to_string(),
                message: "Authentik is not configured".to_string(),
            }),
        )
    })?;

    let manageable = get_manageable_groups(authentik_config, &user.groups);
    Ok(Json(manageable))
}

/// GET /Authentik/AllowedInstances - get the list of configured instance names
#[get("/AllowedInstances")]
pub async fn get_allowed_instances(
    _user: AuthenticatedUser<Management>,
    config: &State<Config>,
) -> Result<Json<Vec<String>>, (Status, Json<AuthentikError>)> {
    let authentik_config = config.authentik.as_ref().ok_or_else(|| {
        (
            Status::InternalServerError,
            Json(AuthentikError {
                error: "not_configured".to_string(),
                message: "Authentik is not configured".to_string(),
            }),
        )
    })?;

    Ok(Json(authentik_config.allowed_instances.clone()))
}

/// POST /Authentik/AddUserToGroup - add a user to an Authentik group by ckey
#[post("/AddUserToGroup", format = "json", data = "<request>")]
pub async fn add_user_to_group(
    user: AuthenticatedUser<Staff>,
    config: &State<Config>,
    request: Json<UserGroupRequest>,
) -> Result<Json<AuthentikSuccess>, (Status, Json<AuthentikError>)> {
    let authentik_config = config.authentik.as_ref().ok_or_else(|| {
        (
            Status::InternalServerError,
            Json(AuthentikError {
                error: "not_configured".to_string(),
                message: "Authentik is not configured".to_string(),
            }),
        )
    })?;

    validate_group_allowed(authentik_config, &user.groups, &request.group_name).map_err(|e| {
        (
            Status::Forbidden,
            Json(AuthentikError {
                error: "group_not_allowed".to_string(),
                message: e,
            }),
        )
    })?;

    let http_client = reqwest::Client::new();

    let group = get_group_by_name(&http_client, authentik_config, &request.group_name)
        .await
        .map_err(|e| {
            (
                Status::BadRequest,
                Json(AuthentikError {
                    error: "group_not_found".to_string(),
                    message: e,
                }),
            )
        })?;

    let authentik_user = get_user_by_ckey(&http_client, authentik_config, &request.ckey)
        .await
        .map_err(|e| {
            (
                Status::BadRequest,
                Json(AuthentikError {
                    error: "user_not_found".to_string(),
                    message: e,
                }),
            )
        })?;

    add_user_to_authentik_group(&http_client, authentik_config, authentik_user.pk, &group.pk)
        .await
        .map_err(|e| {
            (
                Status::InternalServerError,
                Json(AuthentikError {
                    error: "add_to_group_failed".to_string(),
                    message: e,
                }),
            )
        })?;

    if let Some(discourse_config) = &authentik_config.discourse {
        // Get the Discourse user by their Authentik uid
        let discourse_user = get_discourse_user_by_external_id(
            &http_client,
            discourse_config,
            &authentik_user.uid.to_string(),
        )
        .await
        .map_err(|e| {
            (
                Status::BadRequest,
                Json(AuthentikError {
                    error: "discourse_user_not_found".to_string(),
                    message: e,
                }),
            )
        })?;

        let discourse_group =
            get_discourse_group_by_name(&http_client, discourse_config, &request.group_name)
                .await
                .map_err(|e| {
                    (
                        Status::BadRequest,
                        Json(AuthentikError {
                            error: "discourse_group_not_found".to_string(),
                            message: e,
                        }),
                    )
                })?;

        add_user_to_discourse_group(
            &http_client,
            discourse_config,
            discourse_group.id,
            &discourse_user.username,
        )
        .await
        .map_err(|e| {
            (
                Status::InternalServerError,
                Json(AuthentikError {
                    error: "discourse_add_to_group_failed".to_string(),
                    message: e,
                }),
            )
        })?;
    }

    let _ = log_external(
        config,
        "User Manager: User Added to Group".to_string(),
        format!(
            "{} added ckey '{}' to group '{}'",
            user.username, request.ckey, request.group_name
        ),
        true,
    )
    .await;

    let _ = refresh_admins(config);

    Ok(Json(AuthentikSuccess {
        message: format!(
            "Successfully added user with ckey '{}' to group '{}'",
            request.ckey, request.group_name
        ),
    }))
}

/// find an Authentik user by their pk (primary key / ID)
#[allow(dead_code)]
async fn get_user_by_pk(
    client: &reqwest::Client,
    config: &AuthentikConfig,
    pk: i64,
) -> Result<AuthentikUser, String> {
    let url = format!(
        "{}/api/v3/core/users/{}/",
        config.base_url.trim_end_matches('/'),
        pk
    );

    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", config.token))
        .send()
        .await
        .map_err(|e| format!("Failed to query Authentik API: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("Authentik API returned error {}: {}", status, body));
    }

    let user: AuthentikUser = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse Authentik response: {}", e))?;

    Ok(user)
}

/// Generic helper to query Authentik users API and expect exactly one result
async fn query_single_user(
    client: &reqwest::Client,
    config: &AuthentikConfig,
    url: &str,
    field_name: &str,
    field_value: &str,
) -> Result<AuthentikUserDetailed, String> {
    let response = client
        .get(url)
        .header("Authorization", format!("Bearer {}", config.token))
        .send()
        .await
        .map_err(|e| format!("Failed to query Authentik API: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("Authentik API returned error {}: {}", status, body));
    }

    let search_response: AuthentikUserDetailedSearchResponse = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse Authentik response: {}", e))?;

    match search_response.results.len() {
        0 => Err(format!("No user found with {} '{}'", field_name, field_value)),
        1 => Ok(search_response.results.into_iter().next().unwrap()),
        _ => Err(format!(
            "Multiple users found with {} '{}', expected exactly one",
            field_name, field_value
        )),
    }
}

/// find an Authentik user by their ckey attribute
async fn get_user_by_ckey(
    client: &reqwest::Client,
    config: &AuthentikConfig,
    ckey: &str,
) -> Result<AuthentikUserDetailed, String> {
    get_user_by_attribute(client, config, "ckey", ckey).await
}

/// find an Authentik user by a specific attribute key and value
pub async fn get_user_by_attribute(
    client: &reqwest::Client,
    config: &AuthentikConfig,
    attribute_key: &str,
    attribute_value: &str,
) -> Result<AuthentikUserDetailed, String> {
    let url = format!(
        "{}/api/v3/core/users/?attributes={{\"{}\": \"{}\"}}",
        config.base_url.trim_end_matches('/'),
        attribute_key,
        attribute_value
    );
    query_single_user(client, config, &url, attribute_key, attribute_value).await
}

/// find an Authentik user by their UUID (normalizes UUID format)
pub async fn get_user_by_uuid(
    client: &reqwest::Client,
    config: &AuthentikConfig,
    uuid: &str,
) -> Result<AuthentikUserDetailed, String> {
    let uuid = crate::utils::normalize_uuid(uuid)
        .ok_or_else(|| format!("Invalid UUID format: '{}'", uuid))?;
    let url = format!(
        "{}/api/v3/core/users/?uuid={}",
        config.base_url.trim_end_matches('/'),
        uuid
    );
    query_single_user(client, config, &url, "UUID", &uuid).await
}

/// Update user fields (name, email) on Authentik
async fn update_user_fields(
    client: &reqwest::Client,
    config: &AuthentikConfig,
    user_pk: i64,
    name: Option<&str>,
    email: Option<&str>,
) -> Result<(), String> {
    let url = format!(
        "{}/api/v3/core/users/{}/",
        config.base_url.trim_end_matches('/'),
        user_pk
    );

    let mut body = serde_json::Map::new();
    if let Some(n) = name {
        body.insert("name".to_string(), serde_json::json!(n));
    }
    if let Some(e) = email {
        body.insert("email".to_string(), serde_json::json!(e));
    }

    if body.is_empty() {
        return Ok(());
    }

    let response = client
        .patch(&url)
        .header("Authorization", format!("Bearer {}", config.token))
        .header("Content-Type", "application/json")
        .json(&serde_json::Value::Object(body))
        .send()
        .await
        .map_err(|e| format!("Failed to update user: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!(
            "Failed to update user fields (status {}): {}",
            status, body
        ));
    }

    Ok(())
}

/// Parse a Steam ID from an OpenID URL identifier
/// Example: "https://steamcommunity.com/openid/id/76561198012345678" -> "76561198012345678"
pub fn parse_steam_id(identifier: &str) -> Option<String> {
    if identifier.starts_with("https://steamcommunity.com/openid/id/") {
        identifier
            .strip_prefix("https://steamcommunity.com/openid/id/")
            .map(|s| s.to_string())
    } else {
        None
    }
}

/// fetch group names for a user by their pk
#[allow(dead_code)]
async fn fetch_user_groups(
    client: &reqwest::Client,
    config: &AuthentikConfig,
    user_pk: i64,
) -> Result<Vec<String>, String> {
    let url = format!(
        "{}/api/v3/core/groups/?members_by_pk={}",
        config.base_url.trim_end_matches('/'),
        user_pk
    );

    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", config.token))
        .send()
        .await
        .map_err(|e| format!("Failed to query Authentik API: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("Authentik API returned error {}: {}", status, body));
    }

    let search_response: AuthentikGroupSearchResponse = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse Authentik response: {}", e))?;

    Ok(search_response
        .results
        .into_iter()
        .map(|g| g.name)
        .collect())
}

/// update the attributes on an Authentik user
async fn update_user_attributes(
    client: &reqwest::Client,
    config: &AuthentikConfig,
    user_pk: i64,
    attributes: serde_json::Value,
) -> Result<(), String> {
    let url = format!(
        "{}/api/v3/core/users/{}/",
        config.base_url.trim_end_matches('/'),
        user_pk
    );

    let response = client
        .patch(&url)
        .header("Authorization", format!("Bearer {}", config.token))
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({ "attributes": attributes }))
        .send()
        .await
        .map_err(|e| format!("Failed to update user: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!(
            "Failed to update user attributes (status {}): {}",
            status, body
        ));
    }

    Ok(())
}

pub async fn create_user_with_steam_id(
    client: &reqwest::Client,
    config: &AuthentikConfig,
    username: &str,
    steam_id: &str,
) -> Result<AuthentikUser, String> {
    let url = format!(
        "{}/api/v3/core/users/",
        config.base_url.trim_end_matches('/')
    );

    let unique_username = format!(
        "{}_{}",
        username,
        &steam_id[steam_id.len().saturating_sub(4)..]
    );

    let response = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", config.token))
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({
            "username": unique_username,
            "name": username,
            "is_active": true,
            "attributes": {
                "steam_id": steam_id
            }
        }))
        .send()
        .await
        .map_err(|e| format!("Failed to create user: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!(
            "Failed to create user (status {}): {}",
            status, body
        ));
    }

    let user: AuthentikUser = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse user creation response: {}", e))?;

    let source_url = format!(
        "{}/api/v3/sources/oauth/steam/",
        config.base_url.trim_end_matches('/')
    );

    let source_response = client
        .get(&source_url)
        .header("Authorization", format!("Bearer {}", config.token))
        .send()
        .await
        .map_err(|e| format!("Failed to fetch Steam source: {}", e))?;

    if !source_response.status().is_success() {
        let status = source_response.status();
        let body = source_response.text().await.unwrap_or_default();
        return Err(format!(
            "Failed to fetch Steam source (status {}): {}",
            status, body
        ));
    }

    let steam_source: OAuthSource = source_response
        .json()
        .await
        .map_err(|e| format!("Failed to parse Steam source response: {}", e))?;

    let source_connection_url = format!(
        "{}/api/v3/sources/user_connections/oauth/",
        config.base_url.trim_end_matches('/')
    );

    let connection_response = client
        .post(&source_connection_url)
        .header("Authorization", format!("Bearer {}", config.token))
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({
            "user": user.pk,
            "source": steam_source.pk,
            "identifier": format!("https://steamcommunity.com/openid/id/{}", steam_id)
        }))
        .send()
        .await
        .map_err(|e| format!("Failed to create source connection: {}", e))?;

    if !connection_response.status().is_success() {
        let status = connection_response.status();
        let body = connection_response.text().await.unwrap_or_default();
        return Err(format!(
            "Failed to create Steam source connection (status {}): {}",
            status, body
        ));
    }

    Ok(user)
}

/// Get a user's connected OAuth sources from Authentik
pub async fn get_user_oauth_sources(
    client: &reqwest::Client,
    config: &AuthentikConfig,
    user_pk: i64,
) -> Result<Vec<UserOAuthSourceConnection>, String> {
    let url = format!(
        "{}/api/v3/sources/user_connections/oauth/?user={}",
        config.base_url.trim_end_matches('/'),
        user_pk
    );

    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", config.token))
        .send()
        .await
        .map_err(|e| format!("Failed to query Authentik API: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("Authentik API returned error {}: {}", status, body));
    }

    let connections_response: UserOAuthSourceConnectionsResponse = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse Authentik response: {}", e))?;

    Ok(connections_response.results)
}

/// Get all available OAuth sources from Authentik
pub async fn get_all_oauth_sources(
    client: &reqwest::Client,
    config: &AuthentikConfig,
) -> Result<Vec<OAuthSource>, String> {
    let url = format!(
        "{}/api/v3/sources/oauth/",
        config.base_url.trim_end_matches('/')
    );

    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", config.token))
        .send()
        .await
        .map_err(|e| format!("Failed to query Authentik API: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("Authentik API returned error {}: {}", status, body));
    }

    let sources_response: OAuthSourcesResponse = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse Authentik response: {}", e))?;

    Ok(sources_response.results)
}

/// Unlink an OAuth source connection
async fn unlink_oauth_source(
    client: &reqwest::Client,
    config: &AuthentikConfig,
    connection_pk: i64,
) -> Result<(), String> {
    let url = format!(
        "{}/api/v3/sources/user_connections/oauth/{}/",
        config.base_url.trim_end_matches('/'),
        connection_pk
    );

    let response = client
        .delete(&url)
        .header("Authorization", format!("Bearer {}", config.token))
        .send()
        .await
        .map_err(|e| format!("Failed to unlink source: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("Failed to unlink source (status {}): {}", status, body));
    }

    Ok(())
}

/// find an Authentik group by name and return its UUID
async fn get_group_by_name(
    client: &reqwest::Client,
    config: &AuthentikConfig,
    group_name: &str,
) -> Result<AuthentikGroup, String> {
    let url = format!(
        "{}/api/v3/core/groups/?name={}",
        config.base_url.trim_end_matches('/'),
        urlencoding::encode(group_name)
    );

    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", config.token))
        .send()
        .await
        .map_err(|e| format!("Failed to query Authentik API: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("Authentik API returned error {}: {}", status, body));
    }

    let search_response: AuthentikGroupSearchResponse = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse Authentik response: {}", e))?;

    if search_response.results.is_empty() {
        return Err(format!("No group found with name '{}'", group_name));
    }

    if search_response.results.len() > 1 {
        return Err(format!(
            "Multiple groups found with name '{}', expected exactly one",
            group_name
        ));
    }

    Ok(search_response.results[0].clone())
}

/// add a user to an Authentik group
async fn add_user_to_authentik_group(
    client: &reqwest::Client,
    config: &AuthentikConfig,
    user_pk: i64,
    group_id: &str,
) -> Result<(), String> {
    let url = format!(
        "{}/api/v3/core/groups/{}/add_user/",
        config.base_url.trim_end_matches('/'),
        group_id
    );

    let response = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", config.token))
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({ "pk": user_pk }))
        .send()
        .await
        .map_err(|e| format!("Failed to add user to group: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!(
            "Failed to add user to group (status {}): {}",
            status, body
        ));
    }

    Ok(())
}

/// POST /Authentik/RemoveUserFromGroup - remove a user from an Authentik group by ckey
#[post("/RemoveUserFromGroup", format = "json", data = "<request>")]
pub async fn remove_user_from_group(
    user: AuthenticatedUser<Staff>,
    config: &State<Config>,
    request: Json<UserGroupRequest>,
) -> Result<Json<AuthentikSuccess>, (Status, Json<AuthentikError>)> {
    let authentik_config = config.authentik.as_ref().ok_or_else(|| {
        (
            Status::InternalServerError,
            Json(AuthentikError {
                error: "not_configured".to_string(),
                message: "Authentik is not configured".to_string(),
            }),
        )
    })?;

    validate_group_allowed(authentik_config, &user.groups, &request.group_name).map_err(|e| {
        (
            Status::Forbidden,
            Json(AuthentikError {
                error: "group_not_allowed".to_string(),
                message: e,
            }),
        )
    })?;

    let http_client = reqwest::Client::new();

    let group = get_group_by_name(&http_client, authentik_config, &request.group_name)
        .await
        .map_err(|e| {
            (
                Status::BadRequest,
                Json(AuthentikError {
                    error: "group_not_found".to_string(),
                    message: e,
                }),
            )
        })?;

    let authentik_user = get_user_by_ckey(&http_client, authentik_config, &request.ckey)
        .await
        .map_err(|e| {
            (
                Status::BadRequest,
                Json(AuthentikError {
                    error: "user_not_found".to_string(),
                    message: e,
                }),
            )
        })?;

    remove_user_from_authentik_group(&http_client, authentik_config, authentik_user.pk, &group.pk)
        .await
        .map_err(|e| {
            (
                Status::InternalServerError,
                Json(AuthentikError {
                    error: "remove_from_group_failed".to_string(),
                    message: e,
                }),
            )
        })?;

    if let Some(discourse_config) = &authentik_config.discourse {
        let discourse_user = get_discourse_user_by_external_id(
            &http_client,
            discourse_config,
            &authentik_user.uid.to_string(),
        )
        .await
        .map_err(|e| {
            (
                Status::BadRequest,
                Json(AuthentikError {
                    error: "discourse_user_not_found".to_string(),
                    message: e,
                }),
            )
        })?;

        let discourse_group =
            get_discourse_group_by_name(&http_client, discourse_config, &request.group_name)
                .await
                .map_err(|e| {
                    (
                        Status::BadRequest,
                        Json(AuthentikError {
                            error: "discourse_group_not_found".to_string(),
                            message: e,
                        }),
                    )
                })?;

        remove_user_from_discourse_group(
            &http_client,
            discourse_config,
            discourse_group.id,
            &discourse_user.username,
        )
        .await
        .map_err(|e| {
            (
                Status::InternalServerError,
                Json(AuthentikError {
                    error: "discourse_remove_from_group_failed".to_string(),
                    message: e,
                }),
            )
        })?;
    }

    let _ = log_external(
        config,
        "User Manager: User Removed from Group".to_string(),
        format!(
            "{} removed ckey '{}' from group '{}'",
            user.username, request.ckey, request.group_name
        ),
        true,
    )
    .await;

    let _ = refresh_admins(config);

    Ok(Json(AuthentikSuccess {
        message: format!(
            "Successfully removed user with ckey '{}' from group '{}'",
            request.ckey, request.group_name
        ),
    }))
}

/// remove a user from an Authentik group
async fn remove_user_from_authentik_group(
    client: &reqwest::Client,
    config: &AuthentikConfig,
    user_pk: i64,
    group_id: &str,
) -> Result<(), String> {
    let url = format!(
        "{}/api/v3/core/groups/{}/remove_user/",
        config.base_url.trim_end_matches('/'),
        group_id
    );

    let response = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", config.token))
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({ "pk": user_pk }))
        .send()
        .await
        .map_err(|e| format!("Failed to remove user from group: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!(
            "Failed to remove user from group (status {}): {}",
            status, body
        ));
    }

    Ok(())
}

/// GET /Authentik/GroupMembers/<group_name> - get all users in an Authentik group
#[get("/GroupMembers/<group_name>")]
pub async fn get_group_members(
    user: AuthenticatedUser<Staff>,
    config: &State<Config>,
    group_name: String,
) -> Result<Json<GroupMembersResponse>, (Status, Json<AuthentikError>)> {
    let authentik_config = config.authentik.as_ref().ok_or_else(|| {
        (
            Status::InternalServerError,
            Json(AuthentikError {
                error: "not_configured".to_string(),
                message: "Authentik is not configured".to_string(),
            }),
        )
    })?;

    validate_group_allowed(authentik_config, &user.groups, &group_name).map_err(|e| {
        (
            Status::Forbidden,
            Json(AuthentikError {
                error: "group_not_allowed".to_string(),
                message: e,
            }),
        )
    })?;

    let http_client = reqwest::Client::new();

    let group = get_group_by_name(&http_client, authentik_config, &group_name)
        .await
        .map_err(|e| {
            (
                Status::BadRequest,
                Json(AuthentikError {
                    error: "group_not_found".to_string(),
                    message: e,
                }),
            )
        })?;

    let members = fetch_group_members(&http_client, authentik_config, &group.pk)
        .await
        .map_err(|e| {
            (
                Status::InternalServerError,
                Json(AuthentikError {
                    error: "fetch_members_failed".to_string(),
                    message: e,
                }),
            )
        })?;

    Ok(Json(GroupMembersResponse {
        group_name,
        members,
    }))
}

/// fetch all members of an Authentik group
async fn fetch_group_members(
    client: &reqwest::Client,
    config: &AuthentikConfig,
    group_id: &str,
) -> Result<Vec<GroupMember>, String> {
    let url = format!(
        "{}/api/v3/core/users/?groups_by_pk={}",
        config.base_url.trim_end_matches('/'),
        group_id
    );

    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", config.token))
        .send()
        .await
        .map_err(|e| format!("Failed to query Authentik API: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("Authentik API returned error {}: {}", status, body));
    }

    let search_response: AuthentikUserSearchResponse = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse Authentik response: {}", e))?;

    let members = search_response
        .results
        .into_iter()
        .map(|user| {
            let ckey = user
                .attributes
                .get("ckey")
                .and_then(|v| v.as_str())
                .map(String::from);
            GroupMember {
                pk: user.pk,
                username: user.username,
                ckey,
            }
        })
        .collect();

    Ok(members)
}

/// update the attributes on an Authentik group
async fn update_group_attributes(
    client: &reqwest::Client,
    config: &AuthentikConfig,
    group_pk: &str,
    attributes: serde_json::Value,
) -> Result<(), String> {
    let url = format!(
        "{}/api/v3/core/groups/{}/",
        config.base_url.trim_end_matches('/'),
        group_pk
    );

    let response = client
        .patch(&url)
        .header("Authorization", format!("Bearer {}", config.token))
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({ "attributes": attributes }))
        .send()
        .await
        .map_err(|e| format!("Failed to update group: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!(
            "Failed to update group attributes (status {}): {}",
            status, body
        ));
    }

    Ok(())
}

/// GET /Authentik/GroupAdminRanks/<group_name>/<instance> - get the admin_ranks attribute for a group
#[get("/GroupAdminRanks/<group_name>/<instance>")]
pub async fn get_group_admin_ranks(
    user: AuthenticatedUser<Management>,
    config: &State<Config>,
    group_name: String,
    instance: String,
) -> Result<Json<GroupAdminRanksResponse>, (Status, Json<AuthentikError>)> {
    let authentik_config = config.authentik.as_ref().ok_or_else(|| {
        (
            Status::InternalServerError,
            Json(AuthentikError {
                error: "not_configured".to_string(),
                message: "Authentik is not configured".to_string(),
            }),
        )
    })?;

    validate_group_allowed(authentik_config, &user.groups, &group_name).map_err(|e| {
        (
            Status::Forbidden,
            Json(AuthentikError {
                error: "group_not_allowed".to_string(),
                message: e,
            }),
        )
    })?;

    if !authentik_config.allowed_instances.contains(&instance) {
        return Err((
            Status::BadRequest,
            Json(AuthentikError {
                error: "invalid_instance".to_string(),
                message: format!(
                    "Invalid instance '{}'. Allowed instances are: {:?}",
                    instance, authentik_config.allowed_instances
                ),
            }),
        ));
    }

    let http_client = reqwest::Client::new();

    let group = get_group_by_name(&http_client, authentik_config, &group_name)
        .await
        .map_err(|e| {
            (
                Status::BadRequest,
                Json(AuthentikError {
                    error: "group_not_found".to_string(),
                    message: e,
                }),
            )
        })?;

    #[derive(Deserialize, Default)]
    struct AdminRanksResponse {
        admin_ranks: HashMap<String, Vec<String>>,
    }

    let ranks_response: AdminRanksResponse = serde_json::from_value(group.attributes)
        .map_err(|e| {
            (
                Status::InternalServerError,
                Json(AuthentikError {
                    error: "could_not_deserialize".to_string(),
                    message: e.to_string(),
                }),
            )
        })
        .unwrap_or_default();

    let ranks = match ranks_response.admin_ranks.get(&instance) {
        Some(ranks) => ranks,
        None => &Vec::new(),
    };

    Ok(Json(GroupAdminRanksResponse {
        group_name,
        admin_ranks: ranks.clone(),
        allowed_ranks: authentik_config.allowed_admin_ranks.clone(),
    }))
}

/// GET /Authentik/GroupDisplayName/<group_name> - get the display_name attribute for a group
#[get("/GroupDisplayName/<group_name>")]
pub async fn get_group_display_name(
    user: AuthenticatedUser<Staff>,
    config: &State<Config>,
    group_name: String,
) -> Result<Json<GroupDisplayNameResponse>, (Status, Json<AuthentikError>)> {
    let authentik_config = config.authentik.as_ref().ok_or_else(|| {
        (
            Status::InternalServerError,
            Json(AuthentikError {
                error: "not_configured".to_string(),
                message: "Authentik is not configured".to_string(),
            }),
        )
    })?;

    validate_group_allowed(authentik_config, &user.groups, &group_name).map_err(|e| {
        (
            Status::Forbidden,
            Json(AuthentikError {
                error: "group_not_allowed".to_string(),
                message: e,
            }),
        )
    })?;

    let http_client = reqwest::Client::new();

    let group = get_group_by_name(&http_client, authentik_config, &group_name)
        .await
        .map_err(|e| {
            (
                Status::BadRequest,
                Json(AuthentikError {
                    error: "group_not_found".to_string(),
                    message: e,
                }),
            )
        })?;

    let display_name = group
        .attributes
        .get("display_name")
        .and_then(|v| v.as_str())
        .map(String::from);

    Ok(Json(GroupDisplayNameResponse {
        group_name,
        display_name,
    }))
}

/// POST /Authentik/GroupDisplayName - update the display_name attribute for a group
#[post("/GroupDisplayName", format = "json", data = "<request>")]
pub async fn update_group_display_name(
    user: AuthenticatedUser<Staff>,
    config: &State<Config>,
    request: Json<UpdateDisplayNameRequest>,
) -> Result<Json<AuthentikSuccess>, (Status, Json<AuthentikError>)> {
    let authentik_config = config.authentik.as_ref().ok_or_else(|| {
        (
            Status::InternalServerError,
            Json(AuthentikError {
                error: "not_configured".to_string(),
                message: "Authentik is not configured".to_string(),
            }),
        )
    })?;

    validate_group_allowed(authentik_config, &user.groups, &request.group_name).map_err(|e| {
        (
            Status::Forbidden,
            Json(AuthentikError {
                error: "group_not_allowed".to_string(),
                message: e,
            }),
        )
    })?;

    let http_client = reqwest::Client::new();

    let group = get_group_by_name(&http_client, authentik_config, &request.group_name)
        .await
        .map_err(|e| {
            (
                Status::BadRequest,
                Json(AuthentikError {
                    error: "group_not_found".to_string(),
                    message: e,
                }),
            )
        })?;

    let mut attributes = group.attributes.clone();
    if let Some(obj) = attributes.as_object_mut() {
        obj.insert(
            "display_name".to_string(),
            serde_json::json!(request.display_name),
        );
    } else {
        let mut map = Map::new();
        map.insert(
            "display_name".to_string(),
            serde_json::json!(request.display_name),
        );
        attributes = serde_json::Value::Object(map);
    }

    update_group_attributes(&http_client, authentik_config, &group.pk, attributes)
        .await
        .map_err(|e| {
            (
                Status::InternalServerError,
                Json(AuthentikError {
                    error: "update_failed".to_string(),
                    message: e,
                }),
            )
        })?;

    let _ = log_external(
        config,
        "User Manager: Group Display Name Updated".to_string(),
        format!(
            "{} updated display_name for group '{}' to: '{}'",
            user.username, request.group_name, request.display_name
        ),
        true,
    )
    .await;

    let _ = refresh_admins(config);

    Ok(Json(AuthentikSuccess {
        message: format!(
            "Successfully updated display_name for group '{}'",
            request.group_name
        ),
    }))
}

/// GET /Authentik/UserAdditionalTitles/<ckey> - get the additional_titles attribute for a user
#[get("/UserAdditionalTitles/<ckey>")]
pub async fn get_user_additional_titles(
    _user: AuthenticatedUser<Staff>,
    config: &State<Config>,
    ckey: String,
) -> Result<Json<UserAdditionalTitlesResponse>, (Status, Json<AuthentikError>)> {
    let authentik_config = config.authentik.as_ref().ok_or_else(|| {
        (
            Status::InternalServerError,
            Json(AuthentikError {
                error: "not_configured".to_string(),
                message: "Authentik is not configured".to_string(),
            }),
        )
    })?;

    let http_client = reqwest::Client::new();

    let user = get_user_by_ckey(&http_client, authentik_config, &ckey)
        .await
        .map_err(|e| {
            (
                Status::BadRequest,
                Json(AuthentikError {
                    error: "user_not_found".to_string(),
                    message: e,
                }),
            )
        })?;

    let additional_titles = user
        .attributes
        .get("additional_titles")
        .and_then(|v| v.as_str())
        .map(String::from);

    Ok(Json(UserAdditionalTitlesResponse {
        ckey,
        additional_titles,
    }))
}

/// POST /Authentik/UserAdditionalTitles - update the additional_titles attribute for a user
#[post("/UserAdditionalTitles", format = "json", data = "<request>")]
pub async fn update_user_additional_titles(
    user: AuthenticatedUser<Management>,
    config: &State<Config>,
    request: Json<UpdateAdditionalTitlesRequest>,
) -> Result<Json<AuthentikSuccess>, (Status, Json<AuthentikError>)> {
    let authentik_config = config.authentik.as_ref().ok_or_else(|| {
        (
            Status::InternalServerError,
            Json(AuthentikError {
                error: "not_configured".to_string(),
                message: "Authentik is not configured".to_string(),
            }),
        )
    })?;

    let http_client = reqwest::Client::new();

    let target_user = get_user_by_ckey(&http_client, authentik_config, &request.ckey)
        .await
        .map_err(|e| {
            (
                Status::BadRequest,
                Json(AuthentikError {
                    error: "user_not_found".to_string(),
                    message: e,
                }),
            )
        })?;

    let mut attributes = target_user.attributes.clone();
    if let Some(obj) = attributes.as_object_mut() {
        if request.additional_titles.is_empty() {
            obj.remove("additional_titles");
        } else {
            obj.insert(
                "additional_titles".to_string(),
                serde_json::json!(request.additional_titles),
            );
        }
    } else {
        let mut map = Map::new();
        if !request.additional_titles.is_empty() {
            map.insert(
                "additional_titles".to_string(),
                serde_json::json!(request.additional_titles),
            );
        }
        attributes = serde_json::Value::Object(map);
    }

    update_user_attributes(&http_client, authentik_config, target_user.pk, attributes)
        .await
        .map_err(|e| {
            (
                Status::InternalServerError,
                Json(AuthentikError {
                    error: "update_failed".to_string(),
                    message: e,
                }),
            )
        })?;

    let _ = log_external(
        config,
        "User Manager: User Additional Titles Updated".to_string(),
        format!(
            "{} updated additional_titles for ckey '{}' to: '{}'",
            user.username, request.ckey, request.additional_titles
        ),
        true,
    )
    .await;

    let _ = refresh_admins(config);

    Ok(Json(AuthentikSuccess {
        message: format!(
            "Successfully updated additional_titles for user '{}'",
            request.ckey
        ),
    }))
}

/// POST /Authentik/GroupAdminRanks - update the admin_ranks attribute for a group (Management only)
#[post("/GroupAdminRanks", format = "json", data = "<request>")]
pub async fn update_group_admin_ranks(
    user: AuthenticatedUser<Management>,
    config: &State<Config>,
    request: Json<UpdateAdminRanksRequest>,
) -> Result<Json<AuthentikSuccess>, (Status, Json<AuthentikError>)> {
    let authentik_config = config.authentik.as_ref().ok_or_else(|| {
        (
            Status::InternalServerError,
            Json(AuthentikError {
                error: "not_configured".to_string(),
                message: "Authentik is not configured".to_string(),
            }),
        )
    })?;

    validate_group_allowed(authentik_config, &user.groups, &request.group_name).map_err(|e| {
        (
            Status::Forbidden,
            Json(AuthentikError {
                error: "group_not_allowed".to_string(),
                message: e,
            }),
        )
    })?;

    if !authentik_config
        .allowed_instances
        .contains(&request.instance_name)
    {
        return Err((
            Status::BadRequest,
            Json(AuthentikError {
                error: "invalid_instance".to_string(),
                message: format!(
                    "Invalid instance '{}'. Allowed instances are: {:?}",
                    request.instance_name, authentik_config.allowed_instances
                ),
            }),
        ));
    }

    // Validate that all provided ranks are in the allowed list
    if authentik_config.allowed_admin_ranks.is_empty() {
        return Err((
            Status::BadRequest,
            Json(AuthentikError {
                error: "not_configured".to_string(),
                message: "No allowed_admin_ranks are configured".to_string(),
            }),
        ));
    }

    let invalid_ranks: Vec<_> = request
        .admin_ranks
        .iter()
        .filter(|rank| !authentik_config.allowed_admin_ranks.contains(rank))
        .collect();

    if !invalid_ranks.is_empty() {
        return Err((
            Status::BadRequest,
            Json(AuthentikError {
                error: "invalid_ranks".to_string(),
                message: format!(
                    "Invalid admin ranks: {:?}. Allowed ranks are: {:?}",
                    invalid_ranks, authentik_config.allowed_admin_ranks
                ),
            }),
        ));
    }

    let http_client = reqwest::Client::new();

    let group = get_group_by_name(&http_client, authentik_config, &request.group_name)
        .await
        .map_err(|e| {
            (
                Status::BadRequest,
                Json(AuthentikError {
                    error: "group_not_found".to_string(),
                    message: e,
                }),
            )
        })?;

    let mut attributes = group.attributes.clone();
    if let Some(obj) = attributes.as_object_mut() {
        if let Some(ranks) = obj.get_mut("admin_ranks")
            && let Some(rank_obj) = ranks.as_object_mut()
        {
            rank_obj.insert(
                request.instance_name.clone(),
                serde_json::json!(request.admin_ranks),
            );
        }
    } else {
        let mut map = Map::new();
        map.insert(
            request.instance_name.clone(),
            serde_json::json!(request.admin_ranks),
        );

        attributes = serde_json::Value::Object(map);
    }

    update_group_attributes(&http_client, authentik_config, &group.pk, attributes)
        .await
        .map_err(|e| {
            (
                Status::InternalServerError,
                Json(AuthentikError {
                    error: "update_failed".to_string(),
                    message: e,
                }),
            )
        })?;

    let _ = log_external(
        config,
        "User Manager: Group Admin Ranks Updated".to_string(),
        format!(
            "{} updated admin_ranks for group '{}' on instance '{}' to: {:?}",
            user.username, request.group_name, request.instance_name, request.admin_ranks
        ),
        true,
    )
    .await;

    let _ = refresh_admins(config);

    Ok(Json(AuthentikSuccess {
        message: format!(
            "Successfully updated admin_ranks for group '{}'",
            request.group_name
        ),
    }))
}

/// fetch all groups that have admin_ranks attribute set
async fn fetch_groups_with_admin_ranks(
    client: &reqwest::Client,
    config: &AuthentikConfig,
) -> Result<Vec<GroupWithPriority>, String> {
    let mut all_groups = Vec::new();

    let mut page = 1;
    let mut max_pages: Option<i32> = None;
    let page_size = 100;

    loop {
        let url = format!(
            "{}/api/v3/core/groups/?page={}&page_size={}",
            config.base_url.trim_end_matches('/'),
            page,
            page_size
        );

        let response = client
            .get(&url)
            .header("Authorization", format!("Bearer {}", config.token))
            .send()
            .await
            .map_err(|e| format!("Failed to query Authentik API: {}", e))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(format!("Authentik API returned error {}: {}", status, body));
        }

        let search_response: AuthentikGroupSearchResponse = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse Authentik response: {}", e))?;

        if max_pages.is_none() {
            max_pages = Some(search_response.pagination.total_pages)
        }

        if search_response.results.is_empty() {
            break;
        }

        // Filter groups that have admin_ranks attribute set and non-empty
        for group in search_response.results {
            // admin_ranks is now a HashMap<String, Vec<String>> where keys are instance names
            let admin_ranks: HashMap<String, Vec<String>> = group
                .attributes
                .get("admin_ranks")
                .and_then(|v| v.as_object())
                .map(|obj| {
                    obj.iter()
                        .filter_map(|(instance, ranks)| {
                            ranks.as_array().map(|arr| {
                                let ranks_vec: Vec<String> = arr
                                    .iter()
                                    .filter_map(|v| v.as_str().map(String::from))
                                    .collect();
                                (instance.clone(), ranks_vec)
                            })
                        })
                        .filter(|(_, ranks)| !ranks.is_empty())
                        .collect()
                })
                .unwrap_or_default();

            if !admin_ranks.is_empty() {
                let priority = group
                    .attributes
                    .get("priority")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0);

                let display_name = group
                    .attributes
                    .get("display_name")
                    .and_then(|v| v.as_str())
                    .map(String::from);

                all_groups.push(GroupWithPriority {
                    name: group.name,
                    pk: group.pk,
                    users: group.users,
                    priority,
                    admin_ranks,
                    display_name,
                });
            }
        }

        if let Some(max_page) = max_pages
            && max_page == page
        {
            break;
        }

        page += 1;
    }

    Ok(all_groups)
}

/// Validates the Authorization header against the configured API auth token.
fn validate_auth_header(auth_header: &str, config: &Config) -> bool {
    let Some(api_auth) = &config.api_auth else {
        return false;
    };

    // Support both "Bearer <token>" and raw "<token>" formats
    let token = auth_header.strip_prefix("Bearer ").unwrap_or(auth_header);

    token == api_auth.token
}

/// GET /Authentik/Admins - export all users with admin ranks and their groups
#[get("/Admins")]
pub async fn get_admin_ranks_export(
    auth_header: AuthorizationHeader,
    config: &State<Config>,
) -> Result<Json<AdminRanksExportResponse>, (Status, Json<AuthentikError>)> {
    if !validate_auth_header(&auth_header.0, config) {
        return Err((
            Status::Unauthorized,
            Json(AuthentikError {
                error: "unauthorized".to_string(),
                message: "Invalid or missing authorization token".to_string(),
            }),
        ));
    }

    let authentik_config = config.authentik.as_ref().ok_or_else(|| {
        (
            Status::InternalServerError,
            Json(AuthentikError {
                error: "not_configured".to_string(),
                message: "Authentik is not configured".to_string(),
            }),
        )
    })?;

    let http_client = reqwest::Client::new();

    let groups_with_ranks = fetch_groups_with_admin_ranks(&http_client, authentik_config)
        .await
        .map_err(|e| {
            (
                Status::InternalServerError,
                Json(AuthentikError {
                    error: "fetch_groups_failed".to_string(),
                    message: e,
                }),
            )
        })?;

    let mut groups_map: HashMap<String, HashMap<String, Vec<String>>> = HashMap::new();
    for group in &groups_with_ranks {
        groups_map.insert(group.name.clone(), group.admin_ranks.clone());
    }

    // Collect all groups for each user, keyed by ckey
    let mut user_groups: HashMap<String, Vec<&GroupWithPriority>> = HashMap::new();
    let mut user_additional_titles: HashMap<String, Option<String>> = HashMap::new();

    for group in &groups_with_ranks {
        for user in &group.users {
            let Some(ckey) = user
                .attributes
                .get("ckey")
                .and_then(|v| v.as_str())
                .map(String::from)
            else {
                continue;
            };

            user_groups.entry(ckey.clone()).or_default().push(group);

            user_additional_titles.entry(ckey).or_insert_with(|| {
                user.attributes
                    .get("additional_titles")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                    .map(String::from)
            });
        }
    }

    let mut users: Vec<AdminRanksUser> = Vec::new();

    for (ckey, mut groups) in user_groups {
        groups.sort_by(|a, b| b.priority.cmp(&a.priority));

        let primary_group = groups[0];
        let group_names: Vec<String> = groups.iter().map(|g| g.name.clone()).collect();

        let secondary_titles: Vec<String> = groups
            .iter()
            .skip(1)
            .filter_map(|g| {
                g.display_name
                    .as_ref()
                    .filter(|s| !s.is_empty())
                    .cloned()
                    .or_else(|| Some(g.name.clone()))
            })
            .collect();

        let user_additional_title = user_additional_titles.get(&ckey).and_then(|v| v.clone());

        let display_name_opt = primary_group
            .display_name
            .as_ref()
            .filter(|s| !s.is_empty());

        let using_additional_title_as_display =
            display_name_opt.is_none() && user_additional_title.is_some();

        let display_name = match (display_name_opt, &user_additional_title) {
            (Some(dn), _) => dn.clone(),
            (None, Some(at)) => at.clone(),
            (None, None) => primary_group.name.clone(),
        };

        let additional_title = match (
            secondary_titles.is_empty(),
            &user_additional_title,
            using_additional_title_as_display,
        ) {
            (true, _, _) => None,
            (false, None, _) => Some(secondary_titles.join(" & ")),
            (false, Some(_), true) => Some(secondary_titles.join(" & ")),
            (false, Some(at), false) => Some(format!("{} & {}", secondary_titles.join(" & "), at)),
        };

        users.push(AdminRanksUser {
            ckey,
            groups: group_names,
            display_name,
            additional_title,
        });
    }

    Ok(Json(AdminRanksExportResponse {
        users,
        groups: groups_map,
    }))
}

#[derive(Debug, Deserialize)]
struct DiscourseUserResponse {
    user: DiscourseUser,
}

#[derive(Debug, Deserialize)]
struct DiscourseUser {
    id: i64,
    username: String,
}

/// look up a Discourse user by their identity provider external ID (Authentik uid)
async fn get_discourse_user_by_external_id(
    client: &reqwest::Client,
    config: &DiscourseConfig,
    external_id: &str,
) -> Result<DiscourseUser, String> {
    let url = format!(
        "{}/u/by-external/{}/{}.json",
        config.base_url.trim_end_matches('/'),
        urlencoding::encode(&config.provider_name),
        urlencoding::encode(external_id)
    );

    let response = client
        .get(&url)
        .header("Api-Key", &config.api_key)
        .header("Api-Username", &config.api_username)
        .send()
        .await
        .map_err(|e| format!("Failed to query Discourse API: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("Discourse API returned error {}: {}", status, body));
    }

    let user_response: DiscourseUserResponse = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse Discourse response: {}", e))?;

    Ok(user_response.user)
}

/// Response from the Discourse API when getting a group
#[derive(Debug, Deserialize)]
struct DiscourseGroupResponse {
    group: DiscourseGroup,
}

#[derive(Debug, Deserialize)]
struct DiscourseGroup {
    id: i64,
}

/// Get a Discourse group by name
async fn get_discourse_group_by_name(
    client: &reqwest::Client,
    config: &DiscourseConfig,
    group_name: &str,
) -> Result<DiscourseGroup, String> {
    let url = format!(
        "{}/groups/{}.json",
        config.base_url.trim_end_matches('/'),
        urlencoding::encode(group_name)
    );

    let response = client
        .get(&url)
        .header("Api-Key", &config.api_key)
        .header("Api-Username", &config.api_username)
        .send()
        .await
        .map_err(|e| format!("Failed to query Discourse API: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("Discourse API returned error {}: {}", status, body));
    }

    let group_response: DiscourseGroupResponse = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse Discourse response: {}", e))?;

    Ok(group_response.group)
}

/// Add a user to a Discourse group
async fn add_user_to_discourse_group(
    client: &reqwest::Client,
    config: &DiscourseConfig,
    group_id: i64,
    username: &str,
) -> Result<(), String> {
    let url = format!(
        "{}/groups/{}/members.json",
        config.base_url.trim_end_matches('/'),
        group_id
    );

    let response = client
        .put(&url)
        .header("Api-Key", &config.api_key)
        .header("Api-Username", &config.api_username)
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({ "usernames": username }))
        .send()
        .await
        .map_err(|e| format!("Failed to add user to Discourse group: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!(
            "Failed to add user to Discourse group (status {}): {}",
            status, body
        ));
    }

    Ok(())
}

/// Remove a user from a Discourse group
async fn remove_user_from_discourse_group(
    client: &reqwest::Client,
    config: &DiscourseConfig,
    group_id: i64,
    username: &str,
) -> Result<(), String> {
    let url = format!(
        "{}/groups/{}/members.json",
        config.base_url.trim_end_matches('/'),
        group_id
    );

    let response = client
        .delete(&url)
        .header("Api-Key", &config.api_key)
        .header("Api-Username", &config.api_username)
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({ "usernames": username }))
        .send()
        .await
        .map_err(|e| format!("Failed to remove user from Discourse group: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!(
            "Failed to remove user from Discourse group (status {}): {}",
            status, body
        ));
    }

    Ok(())
}

/// GET /Authentik/DiscourseUserId/<ckey> - get a user's Discourse user ID by their ckey
/// looks up the user in Authentik by ckey, then uses their uid to find them in Discourse
#[get("/DiscourseUser/<ckey>")]
pub async fn get_discourse_user_id(
    _user: AuthenticatedUser<Staff>,
    config: &State<Config>,
    ckey: String,
) -> Result<Json<DiscourseUserIdResponse>, (Status, Json<AuthentikError>)> {
    let authentik_config = config.authentik.as_ref().ok_or_else(|| {
        (
            Status::InternalServerError,
            Json(AuthentikError {
                error: "not_configured".to_string(),
                message: "Authentik is not configured".to_string(),
            }),
        )
    })?;

    let discourse_config = authentik_config.discourse.as_ref().ok_or_else(|| {
        (
            Status::InternalServerError,
            Json(AuthentikError {
                error: "not_configured".to_string(),
                message: "Discourse integration is not configured".to_string(),
            }),
        )
    })?;

    let http_client = reqwest::Client::new();

    let authentik_user = get_user_by_ckey(&http_client, authentik_config, &ckey)
        .await
        .map_err(|e| {
            (
                Status::BadRequest,
                Json(AuthentikError {
                    error: "user_not_found".to_string(),
                    message: e,
                }),
            )
        })?;

    let external_id = authentik_user.uid.to_string();

    let discourse_user =
        get_discourse_user_by_external_id(&http_client, discourse_config, &external_id)
            .await
            .map_err(|e| {
                (
                    Status::NotFound,
                    Json(AuthentikError {
                        error: "discourse_user_not_found".to_string(),
                        message: e,
                    }),
                )
            })?;

    Ok(Json(DiscourseUserIdResponse {
        ckey,
        discourse_user_id: discourse_user.id,
        discourse_username: discourse_user.username,
    }))
}

#[derive(Debug, Deserialize)]
#[serde(crate = "rocket::serde")]
#[allow(dead_code)]
pub struct UserUnlinkWebhook {
    pub action: String,
    pub unlinked: String,
    pub user_username: String,
    pub user_email: String,
    pub discord_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(crate = "rocket::serde")]
#[allow(dead_code)]
pub struct UserLinkWebhook {
    pub linked_sources: Vec<String>,
    pub username: String,
    pub pk: i64,
    pub uuid: Option<String>,
    pub ckey: Option<String>,
    pub discord_id: Option<String>,
}

/// Response for webhook endpoints
#[derive(Debug, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct WebhookResponse {
    pub success: bool,
    pub message: String,
}

pub struct WebhookSecretHeader(pub String);

#[rocket::async_trait]
impl<'r> rocket::request::FromRequest<'r> for WebhookSecretHeader {
    type Error = ();

    async fn from_request(
        request: &'r rocket::Request<'_>,
    ) -> rocket::request::Outcome<Self, Self::Error> {
        match request.headers().get_one("X-Webhook-Secret") {
            Some(value) => {
                rocket::request::Outcome::Success(WebhookSecretHeader(value.to_string()))
            }
            None => rocket::request::Outcome::Forward(Status::Unauthorized),
        }
    }
}

fn validate_webhook_secret(secret_header: &str, config: &AuthentikConfig) -> bool {
    match &config.webhook_secret {
        Some(configured_secret) => secret_header == configured_secret,
        None => false,
    }
}

#[derive(Debug, Default)]
pub struct VerificationEligibility {
    pub reason: Option<String>,
    pub ckey: Option<String>,
    pub discord_id: Option<String>,
    pub total_playtime_minutes: Option<i32>,
    pub server_eligibility: HashMap<String, bool>,
}

pub async fn check_verification_eligibility(
    db: &mut Connection<Cmdb>,
    linked_sources: &[String],
    ckey: Option<&str>,
    uuid: Option<&str>,
    discord_id: Option<&str>,
    discord_config: &DiscordBotConfig,
) -> VerificationEligibility {
    let mut result = VerificationEligibility::default();

    let has_byond = linked_sources.iter().any(|s| s == "byond");
    let has_discord = linked_sources.iter().any(|s| s == "discord");

    if !has_discord {
        result.reason = Some("Discord source is not linked".to_string());
        return result;
    }

    // Use ckey if BYOND is linked, otherwise fall back to UUID (with hyphens removed) as ckey
    let effective_ckey: String = if has_byond {
        match ckey {
            Some(c) if !c.is_empty() => c.to_string(),
            _ => {
                result.reason = Some("ckey attribute is missing or empty".to_string());
                return result;
            }
        }
    } else {
        // No BYOND linked - use UUID with hyphens removed as ckey
        match uuid {
            Some(u) if !u.is_empty() => u.replace('-', ""),
            _ => {
                result.reason = Some("Neither BYOND is linked nor UUID is available".to_string());
                return result;
            }
        }
    };
    result.ckey = Some(effective_ckey.clone());
    let ckey = effective_ckey.as_str();

    let discord_id = match discord_id {
        Some(d) if !d.is_empty() => d,
        _ => {
            result.reason = Some("discord_id attribute is missing or empty".to_string());
            return result;
        }
    };
    result.discord_id = Some(discord_id.to_string());

    result.total_playtime_minutes = query_total_playtime_minutes(db, ckey).await;

    let mut all_servers_eligible = true;
    let mut ineligible_servers: Vec<(String, i32, i32)> = Vec::new(); // (guild_id, required, user_playtime)

    for (guild_id, role_config) in &discord_config.link_role_changes {
        let eligibility_result = check_server_eligibility(&result, role_config);
        result
            .server_eligibility
            .insert(guild_id.clone(), eligibility_result.eligible);

        if !eligibility_result.eligible {
            all_servers_eligible = false;
            if let Some(required) = eligibility_result.required_playtime {
                ineligible_servers.push((
                    guild_id.clone(),
                    required,
                    eligibility_result.user_playtime,
                ));
            }
        }
    }

    if !all_servers_eligible {
        let server_details: Vec<String> = ineligible_servers
            .iter()
            .map(|(server, required, user_playtime)| {
                format!(
                    "{} (requires {} minutes, you have {})",
                    server, required, user_playtime
                )
            })
            .collect();
        let mut reason = format!(
            "Insufficient playtime for server(s): {}.",
            server_details.join(", ")
        );
        if !has_byond {
            reason.push_str(
                " You may have more playtime on your BYOND account - try linking it to cmAuth.",
            );
        }
        result.reason = Some(reason);
    }

    result
}

struct ServerEligibilityResult {
    eligible: bool,
    user_playtime: i32,
    required_playtime: Option<i32>,
}

fn check_server_eligibility(
    eligibility: &VerificationEligibility,
    role_config: &ServerRoleConfig,
) -> ServerEligibilityResult {
    let user_playtime = eligibility.total_playtime_minutes.unwrap_or(0);

    let Some(minimum_playtime) = role_config.minimum_playtime_minutes else {
        return ServerEligibilityResult {
            eligible: true,
            user_playtime,
            required_playtime: None,
        };
    };

    ServerEligibilityResult {
        eligible: user_playtime >= minimum_playtime,
        user_playtime,
        required_playtime: Some(minimum_playtime),
    }
}

#[derive(Debug, Default)]
pub struct RoleUpdateResult {
    pub roles_added: Vec<String>,
    pub roles_removed: Vec<String>,
}

async fn update_discord_roles_on_unlink(
    discord_config: &DiscordBotConfig,
    discord_id: &str,
) -> Result<RoleUpdateResult, String> {
    let http = Http::new(&discord_config.token);

    let user_id: u64 = discord_id
        .parse()
        .map_err(|e| format!("Invalid Discord user ID '{}': {}", discord_id, e))?;
    let user_id = UserId::new(user_id);

    let mut result = RoleUpdateResult::default();

    for (guild_id_str, role_config) in &discord_config.link_role_changes {
        let guild_id: u64 = match guild_id_str.parse() {
            Ok(id) => id,
            Err(e) => {
                eprintln!(
                    "Warning: Invalid guild ID '{}' in config: {}",
                    guild_id_str, e
                );
                continue;
            }
        };
        let guild_id = GuildId::new(guild_id);

        // Inverse logic: on unlink, remove roles that would be added on link
        for role_id_str in &role_config.roles_to_add {
            let role_id: u64 = match role_id_str.parse() {
                Ok(id) => id,
                Err(e) => {
                    eprintln!(
                        "Warning: Invalid role ID '{}' in config: {}",
                        role_id_str, e
                    );
                    continue;
                }
            };
            let role_id = RoleId::new(role_id);

            match http
                .remove_member_role(
                    guild_id,
                    user_id,
                    role_id,
                    Some("User unlinked account from Authentik"),
                )
                .await
            {
                Ok(()) => {
                    result
                        .roles_removed
                        .push(format!("{}:{}", guild_id_str, role_id_str));
                }
                Err(e) => {
                    eprintln!(
                        "Warning: Failed to remove role {} from user {} in guild {}: {}",
                        role_id_str, discord_id, guild_id_str, e
                    );
                }
            }
        }

        // Inverse logic: on unlink, add roles that would be removed on link
        for role_id_str in &role_config.roles_to_remove {
            let role_id: u64 = match role_id_str.parse() {
                Ok(id) => id,
                Err(e) => {
                    eprintln!(
                        "Warning: Invalid role ID '{}' in config: {}",
                        role_id_str, e
                    );
                    continue;
                }
            };
            let role_id = RoleId::new(role_id);

            match http
                .add_member_role(
                    guild_id,
                    user_id,
                    role_id,
                    Some("User unlinked account from Authentik"),
                )
                .await
            {
                Ok(()) => {
                    result
                        .roles_added
                        .push(format!("{}:{}", guild_id_str, role_id_str));
                }
                Err(e) => {
                    eprintln!(
                        "Warning: Failed to add role {} to user {} in guild {}: {}",
                        role_id_str, discord_id, guild_id_str, e
                    );
                }
            }
        }

        for role_ids in role_config.whitelist_roles.values() {
            for role_id_str in role_ids {
                let role_id: u64 = match role_id_str.parse() {
                    Ok(id) => id,
                    Err(e) => {
                        eprintln!(
                            "Warning: Invalid whitelist role ID '{}' in config: {}",
                            role_id_str, e
                        );
                        continue;
                    }
                };
                let role_id = RoleId::new(role_id);

                match http
                    .remove_member_role(
                        guild_id,
                        user_id,
                        role_id,
                        Some("User unlinked account - removing whitelist role"),
                    )
                    .await
                {
                    Ok(()) => {
                        result
                            .roles_removed
                            .push(format!("{}:{} (whitelist)", guild_id_str, role_id_str));
                    }
                    Err(e) => {
                        eprintln!(
                            "Warning: Failed to remove whitelist role {} from user {} in guild {}: {}",
                            role_id_str, discord_id, guild_id_str, e
                        );
                    }
                }
            }
        }
    }

    Ok(result)
}

async fn update_discord_roles_on_link(
    discord_config: &DiscordBotConfig,
    discord_id: &str,
    server_eligibility: &HashMap<String, bool>,
    whitelist_status: Option<&str>,
) -> Result<RoleUpdateResult, String> {
    let http = Http::new(&discord_config.token);

    let user_id: u64 = discord_id
        .parse()
        .map_err(|e| format!("Invalid Discord user ID '{}': {}", discord_id, e))?;
    let user_id = UserId::new(user_id);

    let mut result = RoleUpdateResult::default();

    for (guild_id_str, role_config) in &discord_config.link_role_changes {
        // Skip servers where user is not eligible
        if !server_eligibility
            .get(guild_id_str)
            .copied()
            .unwrap_or(false)
        {
            eprintln!(
                "Skipping role updates for guild {} - user not eligible",
                guild_id_str
            );
            continue;
        }

        let guild_id: u64 = match guild_id_str.parse() {
            Ok(id) => id,
            Err(e) => {
                eprintln!(
                    "Warning: Invalid guild ID '{}' in config: {}",
                    guild_id_str, e
                );
                continue;
            }
        };
        let guild_id = GuildId::new(guild_id);

        // Direct logic: on link, add roles_to_add
        for role_id_str in &role_config.roles_to_add {
            let role_id: u64 = match role_id_str.parse() {
                Ok(id) => id,
                Err(e) => {
                    eprintln!(
                        "Warning: Invalid role ID '{}' in config: {}",
                        role_id_str, e
                    );
                    continue;
                }
            };
            let role_id = RoleId::new(role_id);

            match http
                .add_member_role(
                    guild_id,
                    user_id,
                    role_id,
                    Some("User linked byond and discord accounts in Authentik"),
                )
                .await
            {
                Ok(()) => {
                    result
                        .roles_added
                        .push(format!("{}:{}", guild_id_str, role_id_str));
                }
                Err(e) => {
                    eprintln!(
                        "Warning: Failed to add role {} to user {} in guild {}: {}",
                        role_id_str, discord_id, guild_id_str, e
                    );
                }
            }
        }

        // Direct logic: on link, remove roles_to_remove
        for role_id_str in &role_config.roles_to_remove {
            let role_id: u64 = match role_id_str.parse() {
                Ok(id) => id,
                Err(e) => {
                    eprintln!(
                        "Warning: Invalid role ID '{}' in config: {}",
                        role_id_str, e
                    );
                    continue;
                }
            };
            let role_id = RoleId::new(role_id);

            match http
                .remove_member_role(
                    guild_id,
                    user_id,
                    role_id,
                    Some("User linked byond and discord accounts in Authentik"),
                )
                .await
            {
                Ok(()) => {
                    result
                        .roles_removed
                        .push(format!("{}:{}", guild_id_str, role_id_str));
                }
                Err(e) => {
                    eprintln!(
                        "Warning: Failed to remove role {} from user {} in guild {}: {}",
                        role_id_str, discord_id, guild_id_str, e
                    );
                }
            }
        }

        let whitelist_role_ids = resolve_whitelist_roles(whitelist_status, role_config);
        for role_id_str in &whitelist_role_ids {
            let role_id: u64 = match role_id_str.parse() {
                Ok(id) => id,
                Err(e) => {
                    eprintln!(
                        "Warning: Invalid whitelist role ID '{}' in config: {}",
                        role_id_str, e
                    );
                    continue;
                }
            };
            let role_id = RoleId::new(role_id);

            match http
                .add_member_role(
                    guild_id,
                    user_id,
                    role_id,
                    Some("User has whitelist status"),
                )
                .await
            {
                Ok(()) => {
                    result
                        .roles_added
                        .push(format!("{}:{} (whitelist)", guild_id_str, role_id_str));
                }
                Err(e) => {
                    eprintln!(
                        "Warning: Failed to add whitelist role {} to user {} in guild {}: {}",
                        role_id_str, discord_id, guild_id_str, e
                    );
                }
            }
        }
    }

    Ok(result)
}

#[post("/Webhook/UserUnlinked", format = "json", data = "<payload>")]
pub async fn webhook_user_unlinked(
    webhook_secret: WebhookSecretHeader,
    config: &State<Config>,
    payload: Json<UserUnlinkWebhook>,
) -> Result<Json<WebhookResponse>, (Status, Json<AuthentikError>)> {
    let authentik_config = config.authentik.as_ref().ok_or_else(|| {
        (
            Status::InternalServerError,
            Json(AuthentikError {
                error: "not_configured".to_string(),
                message: "Authentik is not configured".to_string(),
            }),
        )
    })?;

    if !validate_webhook_secret(&webhook_secret.0, authentik_config) {
        return Err((
            Status::Unauthorized,
            Json(AuthentikError {
                error: "unauthorized".to_string(),
                message: "Invalid webhook secret".to_string(),
            }),
        ));
    }

    if payload.action != "user-unlinked" {
        return Err((
            Status::BadRequest,
            Json(AuthentikError {
                error: "invalid_action".to_string(),
                message: format!("Unsupported action type: {}", payload.action),
            }),
        ));
    }

    let discord_config = config.discord_bot.as_ref().ok_or_else(|| {
        (
            Status::InternalServerError,
            Json(AuthentikError {
                error: "not_configured".to_string(),
                message: "Discord bot is not configured".to_string(),
            }),
        )
    })?;

    let role_changes = update_discord_roles_on_unlink(discord_config, &payload.discord_id)
        .await
        .map_err(|e| {
            (
                Status::InternalServerError,
                Json(AuthentikError {
                    error: "role_update_failed".to_string(),
                    message: e,
                }),
            )
        })?;

    let _ = refresh_admins(config);

    Ok(Json(WebhookResponse {
        success: true,
        message: format!(
            "Processed unlink event for user '{}'. Added {} role(s), removed {} role(s).",
            payload.user_username,
            role_changes.roles_added.len(),
            role_changes.roles_removed.len()
        ),
    }))
}

#[post("/Webhook/UserLinked", format = "json", data = "<payload>")]
pub async fn webhook_user_linked(
    webhook_secret: WebhookSecretHeader,
    config: &State<Config>,
    mut db: Connection<Cmdb>,
    payload: Json<UserLinkWebhook>,
) -> Result<Json<WebhookResponse>, (Status, Json<AuthentikError>)> {
    let authentik_config = config.authentik.as_ref().ok_or_else(|| {
        (
            Status::InternalServerError,
            Json(AuthentikError {
                error: "not_configured".to_string(),
                message: "Authentik is not configured".to_string(),
            }),
        )
    })?;

    if !validate_webhook_secret(&webhook_secret.0, authentik_config) {
        return Err((
            Status::Unauthorized,
            Json(AuthentikError {
                error: "unauthorized".to_string(),
                message: "Invalid webhook secret".to_string(),
            }),
        ));
    }

    let discord_config = config.discord_bot.as_ref().ok_or_else(|| {
        (
            Status::InternalServerError,
            Json(AuthentikError {
                error: "not_configured".to_string(),
                message: "Discord bot is not configured".to_string(),
            }),
        )
    })?;

    // Check user eligibility for verification
    let eligibility = check_verification_eligibility(
        &mut db,
        &payload.linked_sources,
        payload.ckey.as_deref(),
        payload.uuid.as_deref(),
        payload.discord_id.as_deref(),
        discord_config,
    )
    .await;

    // If no servers are eligible, return early with reason
    if eligibility.server_eligibility.values().all(|&v| !v) {
        return Ok(Json(WebhookResponse {
            success: true,
            message: format!(
                "User '{}' is not eligible for role updates: {}",
                payload.username,
                eligibility
                    .reason
                    .unwrap_or_else(|| "Unknown reason".to_string())
            ),
        }));
    }

    let discord_id = eligibility.discord_id.as_ref().ok_or_else(|| {
        (
            Status::BadRequest,
            Json(AuthentikError {
                error: "missing_discord_id".to_string(),
                message: "Discord ID is required when discord source is linked".to_string(),
            }),
        )
    })?;

    let whitelist_status = match eligibility.ckey.as_deref() {
        Some(ckey) => get_whitelist_status_by_ckey(&mut db, ckey).await,
        None => None,
    };

    let role_changes = update_discord_roles_on_link(
        discord_config,
        discord_id,
        &eligibility.server_eligibility,
        whitelist_status.as_deref(),
    )
    .await
    .map_err(|e| {
        (
            Status::InternalServerError,
            Json(AuthentikError {
                error: "role_update_failed".to_string(),
                message: e,
            }),
        )
    })?;

    let ineligible_servers: Vec<_> = eligibility
        .server_eligibility
        .iter()
        .filter(|(_, v)| !**v)
        .map(|(k, _)| k.as_str())
        .collect();

    let mut message = format!(
        "Processed link event for user '{}'. Added {} role(s), removed {} role(s).",
        payload.username,
        role_changes.roles_added.len(),
        role_changes.roles_removed.len()
    );

    if !ineligible_servers.is_empty() {
        message.push_str(&format!(
            " Skipped {} server(s) due to insufficient playtime: {}",
            ineligible_servers.len(),
            ineligible_servers.join(", ")
        ));
    }

    if let Some(playtime) = eligibility.total_playtime_minutes {
        message.push_str(&format!(" (playtime: {} minutes)", playtime));
    }

    let _ = refresh_admins(config);

    Ok(Json(WebhookResponse {
        success: true,
        message,
    }))
}

/// GET /Authentik/UserByDiscordId/<discord_id> - get full user details by Discord ID (Staff only)
#[get("/UserByDiscordId/<discord_id>")]
pub async fn get_user_by_discord_id(
    _user: AuthenticatedUser<Staff>,
    config: &State<Config>,
    discord_id: String,
) -> Result<Json<AuthentikUserFullResponse>, (Status, Json<AuthentikError>)> {
    let authentik_config = config.authentik.as_ref().ok_or_else(|| {
        (
            Status::InternalServerError,
            Json(AuthentikError {
                error: "not_configured".to_string(),
                message: "Authentik is not configured".to_string(),
            }),
        )
    })?;

    let http_client = reqwest::Client::new();

    let user = get_user_by_attribute(&http_client, authentik_config, "discord_id", &discord_id)
        .await
        .map_err(|e| {
            (
                Status::NotFound,
                Json(AuthentikError {
                    error: "user_not_found".to_string(),
                    message: e,
                }),
            )
        })?;

    let groups = user.group_names();

    Ok(Json(AuthentikUserFullResponse {
        pk: user.pk,
        uuid: user.uuid,
        uid: user.uid,
        username: user.username,
        name: user.name,
        is_active: user.is_active,
        last_login: user.last_login,
        attributes: user.attributes,
        groups,
    }))
}

/// GET /Authentik/UserByUuid/<uuid> - get full user details by UUID (Staff only)
#[get("/UserByUuid/<uuid>")]
pub async fn user_by_uuid_endpoint(
    _user: AuthenticatedUser<Staff>,
    config: &State<Config>,
    uuid: String,
) -> Result<Json<AuthentikUserFullResponse>, (Status, Json<AuthentikError>)> {
    let authentik_config = config.authentik.as_ref().ok_or_else(|| {
        (
            Status::InternalServerError,
            Json(AuthentikError {
                error: "not_configured".to_string(),
                message: "Authentik is not configured".to_string(),
            }),
        )
    })?;

    let http_client = reqwest::Client::new();

    let user = get_user_by_uuid(&http_client, authentik_config, &uuid)
        .await
        .map_err(|e| {
            (
                Status::NotFound,
                Json(AuthentikError {
                    error: "user_not_found".to_string(),
                    message: e,
                }),
            )
        })?;

    let groups = user.group_names();

    Ok(Json(AuthentikUserFullResponse {
        pk: user.pk,
        uuid: user.uuid,
        uid: user.uid,
        username: user.username,
        name: user.name,
        is_active: user.is_active,
        last_login: user.last_login,
        attributes: user.attributes,
        groups,
    }))
}

/// GET /Authentik/SearchUsers?query=<query> - search users by username or name (Staff only)
#[get("/SearchUsers?<query>")]
pub async fn search_users(
    _user: AuthenticatedUser<Staff>,
    config: &State<Config>,
    query: String,
) -> Result<Json<Vec<AuthentikUserSearchResult>>, (Status, Json<AuthentikError>)> {
    let authentik_config = config.authentik.as_ref().ok_or_else(|| {
        (
            Status::InternalServerError,
            Json(AuthentikError {
                error: "not_configured".to_string(),
                message: "Authentik is not configured".to_string(),
            }),
        )
    })?;

    let http_client = reqwest::Client::new();
    let base_url = authentik_config.base_url.trim_end_matches('/');
    let encoded_query = urlencoding::encode(&query);

    let main_search_url = format!("{}/api/v3/core/users/?search={}", base_url, encoded_query);

    let steam_id_url = format!(
        "{}/api/v3/core/users/?attributes={{\"steam_id\":\"{}\"}}",
        base_url, encoded_query
    );

    let ckey_url = format!(
        "{}/api/v3/core/users/?attributes={{\"ckey\":\"{}\"}}",
        base_url, encoded_query
    );

    let auth_header = format!("Bearer {}", authentik_config.token);
    let (main_result, steam_id_result, ckey_result) = tokio::join!(
        http_client
            .get(&main_search_url)
            .header("Authorization", &auth_header)
            .send(),
        http_client
            .get(&steam_id_url)
            .header("Authorization", &auth_header)
            .send(),
        http_client
            .get(&ckey_url)
            .header("Authorization", &auth_header)
            .send()
    );

    let mut all_users: Vec<AuthentikUserDetailed> = Vec::new();
    let mut main_request_error: Option<String> = None;

    match main_result {
        Ok(response) if response.status().is_success() => {
            if let Ok(search_response) =
                response.json::<AuthentikUserDetailedSearchResponse>().await
            {
                all_users.extend(search_response.results);
            }
        }
        Ok(response) => {
            main_request_error = Some(format!("HTTP {}", response.status()));
        }
        Err(e) => {
            main_request_error = Some(e.to_string());
        }
    }

    if let Ok(response) = steam_id_result
        && response.status().is_success()
        && let Ok(search_response) = response.json::<AuthentikUserDetailedSearchResponse>().await
    {
        all_users.extend(search_response.results);
    }

    if let Ok(response) = ckey_result
        && response.status().is_success()
        && let Ok(search_response) = response.json::<AuthentikUserDetailedSearchResponse>().await
    {
        all_users.extend(search_response.results);
    }

    if all_users.is_empty()
        && let Some(error) = main_request_error
    {
        return Err((
            Status::InternalServerError,
            Json(AuthentikError {
                error: "api_error".to_string(),
                message: format!("Failed to query Authentik API: {}", error),
            }),
        ));
    }

    let mut seen_pks = std::collections::HashSet::new();
    let results: Vec<AuthentikUserSearchResult> = all_users
        .into_iter()
        .filter(|u| seen_pks.insert(u.pk))
        .map(|u| AuthentikUserSearchResult {
            pk: u.pk,
            uuid: u.uuid,
            username: u.username,
            name: u.name,
            is_active: u.is_active,
        })
        .collect();

    Ok(Json(results))
}

/// GET /Authentik/MyProfile - get the current user's profile information
#[get("/MyProfile")]
pub async fn get_my_profile(
    user: AuthenticatedUser<Player>,
    config: &State<Config>,
) -> Result<Json<UserProfileResponse>, (Status, Json<AuthentikError>)> {
    let authentik_config = config.authentik.as_ref().ok_or_else(|| {
        (
            Status::InternalServerError,
            Json(AuthentikError {
                error: "not_configured".to_string(),
                message: "Authentik is not configured".to_string(),
            }),
        )
    })?;

    let http_client = reqwest::Client::new();

    let authentik_user = get_user_by_uuid(&http_client, authentik_config, &user.sub)
        .await
        .map_err(|e| {
            (
                Status::NotFound,
                Json(AuthentikError {
                    error: "user_not_found".to_string(),
                    message: e,
                }),
            )
        })?;

    // Fetch user's linked sources and all available sources in parallel
    let (user_sources_result, all_sources_result) = tokio::join!(
        get_user_oauth_sources(&http_client, authentik_config, authentik_user.pk),
        get_all_oauth_sources(&http_client, authentik_config)
    );

    let user_sources = user_sources_result.map_err(|e| {
        (
            Status::InternalServerError,
            Json(AuthentikError {
                error: "fetch_sources_failed".to_string(),
                message: e,
            }),
        )
    })?;

    let all_sources = all_sources_result.map_err(|e| {
        (
            Status::InternalServerError,
            Json(AuthentikError {
                error: "fetch_sources_failed".to_string(),
                message: e,
            }),
        )
    })?;

    // Build set of linked source slugs
    let linked_slugs: std::collections::HashSet<String> = user_sources
        .iter()
        .map(|s| s.source.slug.clone())
        .collect();

    let linked_sources: Vec<LinkedOAuthSource> = user_sources
        .into_iter()
        .map(|source| {
            let parsed_id = match source.source.slug.as_str() {
                "steam" => parse_steam_id(&source.identifier),
                "discord" => Some(source.identifier.clone()),
                "github" => Some(source.identifier.clone()),
                "byond" => Some(
                    source
                        .identifier
                        .strip_prefix("user:")
                        .unwrap_or(&source.identifier)
                        .to_string(),
                ),
                _ => None,
            };
            LinkedOAuthSource {
                connection_pk: source.pk,
                name: source.source.name,
                slug: source.source.slug.clone(),
                icon: source.source.icon,
                identifier: source.identifier,
                parsed_id,
            }
        })
        .collect();

    // Available sources are those not already linked
    let available_sources: Vec<AvailableOAuthSource> = all_sources
        .into_iter()
        .filter(|s| !linked_slugs.contains(&s.slug))
        .map(|s| AvailableOAuthSource {
            slug: s.slug,
            name: s.name,
            icon: s.icon,
        })
        .collect();

    Ok(Json(UserProfileResponse {
        pk: authentik_user.pk,
        uuid: authentik_user.uuid.unwrap_or_default(),
        username: authentik_user.username,
        name: authentik_user.name,
        email: authentik_user.email,
        linked_sources,
        available_sources,
        authentik_base_url: authentik_config.base_url.trim_end_matches('/').to_string(),
    }))
}

/// PATCH /Authentik/MyProfile - update the current user's profile information
#[patch("/MyProfile", format = "json", data = "<request>")]
pub async fn update_my_profile(
    user: AuthenticatedUser<Player>,
    config: &State<Config>,
    request: Json<UpdateProfileRequest>,
) -> Result<Json<AuthentikSuccess>, (Status, Json<AuthentikError>)> {
    let authentik_config = config.authentik.as_ref().ok_or_else(|| {
        (
            Status::InternalServerError,
            Json(AuthentikError {
                error: "not_configured".to_string(),
                message: "Authentik is not configured".to_string(),
            }),
        )
    })?;

    if request.name.is_none() {
        return Err((
            Status::BadRequest,
            Json(AuthentikError {
                error: "no_fields_to_update".to_string(),
                message: "Name field must be provided".to_string(),
            }),
        ));
    }

    let http_client = reqwest::Client::new();

    let authentik_user = get_user_by_uuid(&http_client, authentik_config, &user.sub)
        .await
        .map_err(|e| {
            (
                Status::NotFound,
                Json(AuthentikError {
                    error: "user_not_found".to_string(),
                    message: e,
                }),
            )
        })?;

    update_user_fields(
        &http_client,
        authentik_config,
        authentik_user.pk,
        request.name.as_deref(),
        None, // Email changes require verification via Authentik flow
    )
    .await
    .map_err(|e| {
        (
            Status::InternalServerError,
            Json(AuthentikError {
                error: "update_failed".to_string(),
                message: e,
            }),
        )
    })?;

    Ok(Json(AuthentikSuccess {
        message: "Successfully updated name".to_string(),
    }))
}

/// DELETE /Authentik/MyProfile/UnlinkSource/<connection_pk> - unlink an OAuth source
#[delete("/MyProfile/UnlinkSource/<connection_pk>")]
pub async fn unlink_my_source(
    user: AuthenticatedUser<Player>,
    config: &State<Config>,
    connection_pk: i64,
) -> Result<Json<AuthentikSuccess>, (Status, Json<AuthentikError>)> {
    let authentik_config = config.authentik.as_ref().ok_or_else(|| {
        (
            Status::InternalServerError,
            Json(AuthentikError {
                error: "not_configured".to_string(),
                message: "Authentik is not configured".to_string(),
            }),
        )
    })?;

    let http_client = reqwest::Client::new();

    // Verify the user owns this connection by looking up their connections
    let authentik_user = get_user_by_uuid(&http_client, authentik_config, &user.sub)
        .await
        .map_err(|e| {
            (
                Status::NotFound,
                Json(AuthentikError {
                    error: "user_not_found".to_string(),
                    message: e,
                }),
            )
        })?;

    let user_sources = get_user_oauth_sources(&http_client, authentik_config, authentik_user.pk)
        .await
        .map_err(|e| {
            (
                Status::InternalServerError,
                Json(AuthentikError {
                    error: "fetch_sources_failed".to_string(),
                    message: e,
                }),
            )
        })?;

    // Check that the connection belongs to this user
    let connection = user_sources
        .iter()
        .find(|s| s.pk == connection_pk)
        .ok_or_else(|| {
            (
                Status::Forbidden,
                Json(AuthentikError {
                    error: "not_your_connection".to_string(),
                    message: "This connection does not belong to you".to_string(),
                }),
            )
        })?;

    let source_name = connection.source.name.clone();

    unlink_oauth_source(&http_client, authentik_config, connection_pk)
        .await
        .map_err(|e| {
            (
                Status::InternalServerError,
                Json(AuthentikError {
                    error: "unlink_failed".to_string(),
                    message: e,
                }),
            )
        })?;

    Ok(Json(AuthentikSuccess {
        message: format!("Successfully unlinked {}", source_name),
    }))
}

/// Database row for notes query
#[derive(Debug, FromRow)]
struct NoteRow {
    id: i64,
    text: Option<String>,
    date: String,
    is_ban: i32,
    ban_time: Option<i64>,
    admin_rank: String,
    note_category: Option<i32>,
    round_id: Option<i32>,
}

/// Database row for job bans query
#[derive(Debug, FromRow)]
struct JobBanRow {
    id: i64,
    text: String,
    date: Option<String>,
    ban_time: Option<i64>,
    expiration: Option<i64>,
    role: String,
}

/// GET /Authentik/MyPlayerInfo - get the current user's in-game player info (notes and job bans)
#[get("/MyPlayerInfo")]
pub async fn get_my_player_info(
    user: AuthenticatedUser<Player>,
    config: &State<Config>,
    mut db: Connection<Cmdb>,
) -> Result<Json<MyPlayerInfoResponse>, (Status, Json<AuthentikError>)> {
    let authentik_config = config.authentik.as_ref().ok_or_else(|| {
        (
            Status::InternalServerError,
            Json(AuthentikError {
                error: "not_configured".to_string(),
                message: "Authentik is not configured".to_string(),
            }),
        )
    })?;

    let http_client = reqwest::Client::new();

    // Get the user's Authentik profile to determine their ckey
    let authentik_user = get_user_by_uuid(&http_client, authentik_config, &user.sub)
        .await
        .map_err(|e| {
            (
                Status::NotFound,
                Json(AuthentikError {
                    error: "user_not_found".to_string(),
                    message: e,
                }),
            )
        })?;

    // Get linked sources to check for BYOND
    let user_sources = get_user_oauth_sources(&http_client, authentik_config, authentik_user.pk)
        .await
        .map_err(|e| {
            (
                Status::InternalServerError,
                Json(AuthentikError {
                    error: "fetch_sources_failed".to_string(),
                    message: e,
                }),
            )
        })?;

    // Determine ckey: BYOND if linked, else UUID without dashes (lowercase)
    let byond_source = user_sources.iter().find(|s| s.source.slug == "byond");
    let ckey = if let Some(byond) = byond_source {
        byond
            .identifier
            .strip_prefix("user:")
            .unwrap_or(&byond.identifier)
            .to_lowercase()
    } else {
        authentik_user
            .uuid
            .as_ref()
            .map(|u| u.replace('-', "").to_lowercase())
            .ok_or_else(|| {
                (
                    Status::BadRequest,
                    Json(AuthentikError {
                        error: "no_ckey".to_string(),
                        message: "No BYOND account linked and no UUID available".to_string(),
                    }),
                )
            })?
    };

    // Get player ID from ckey
    let player_id: i64 = sqlx::query("SELECT id FROM players WHERE ckey = ?")
        .bind(&ckey)
        .fetch_optional(&mut **db)
        .await
        .map_err(|e| {
            (
                Status::InternalServerError,
                Json(AuthentikError {
                    error: "database_error".to_string(),
                    message: format!("Failed to query player: {}", e),
                }),
            )
        })?
        .map(|row| row.get("id"))
        .ok_or_else(|| {
            (
                Status::NotFound,
                Json(AuthentikError {
                    error: "player_not_found".to_string(),
                    message: "No player record found for your account".to_string(),
                }),
            )
        })?;

    // Fetch non-confidential notes (is_confidential = 0)
    let notes: Vec<NoteRow> = query_as(
        "SELECT id, text, date, is_ban, ban_time, admin_rank, note_category, round_id
         FROM player_notes
         WHERE player_id = ? AND is_confidential = 0
         ORDER BY date DESC",
    )
    .bind(player_id)
    .fetch_all(&mut **db)
    .await
    .map_err(|e| {
        (
            Status::InternalServerError,
            Json(AuthentikError {
                error: "database_error".to_string(),
                message: format!("Failed to query notes: {}", e),
            }),
        )
    })?;

    // Fetch active job bans (expiration is NULL or > current time)
    let job_bans: Vec<JobBanRow> = query_as(
        "SELECT id, text, date, ban_time, expiration, role
         FROM player_job_bans
         WHERE player_id = ? AND (expiration IS NULL OR expiration > UNIX_TIMESTAMP())
         ORDER BY date DESC",
    )
    .bind(player_id)
    .fetch_all(&mut **db)
    .await
    .map_err(|e| {
        (
            Status::InternalServerError,
            Json(AuthentikError {
                error: "database_error".to_string(),
                message: format!("Failed to query job bans: {}", e),
            }),
        )
    })?;

    // Convert to public types
    let public_notes: Vec<PublicNote> = notes
        .into_iter()
        .map(|n| PublicNote {
            id: n.id,
            text: n.text,
            date: n.date,
            is_ban: n.is_ban != 0,
            ban_time: n.ban_time,
            admin_rank: n.admin_rank,
            note_category: n.note_category,
            round_id: n.round_id,
        })
        .collect();

    let public_job_bans: Vec<PublicJobBan> = job_bans
        .into_iter()
        .map(|jb| PublicJobBan {
            id: jb.id,
            text: jb.text,
            date: jb.date,
            ban_time: jb.ban_time,
            expiration: jb.expiration,
            role: jb.role,
        })
        .collect();

    Ok(Json(MyPlayerInfoResponse {
        ckey,
        display_name: authentik_user.name,
        notes: public_notes,
        job_bans: public_job_bans,
    }))
}

