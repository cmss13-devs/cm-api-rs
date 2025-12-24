use rocket::{State, http::Status, serde::json::Json};
use serde::{Deserialize, Serialize};

use crate::{
    Config,
    admin::{AuthenticatedUser, Management},
    logging::log_external,
};

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AuthentikConfig {
    pub token: String,
    pub base_url: String,
    /// whitelist of group names that can be modified through the API
    #[serde(default)]
    pub allowed_groups: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct UserGroupRequest {
    pub ckey: String,
    pub group_name: String,
}

#[derive(Debug, Deserialize)]
struct AuthentikUserSearchResponse {
    results: Vec<AuthentikUser>,
}

#[derive(Debug, Deserialize)]
struct AuthentikGroupSearchResponse {
    results: Vec<AuthentikGroup>,
}

#[derive(Debug, Deserialize)]
struct AuthentikGroup {
    pk: String,
}

#[derive(Debug, Deserialize)]
struct AuthentikUser {
    pk: i64,
    username: String,
    #[serde(default)]
    attributes: serde_json::Value,
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

/// Check if a group name is in the allowed whitelist
fn validate_group_allowed(config: &AuthentikConfig, group_name: &str) -> Result<(), String> {
    if config.allowed_groups.is_empty() {
        return Err("No groups are configured as allowed. Add groups to 'allowed_groups' in the Authentik config.".to_string());
    }

    if !config.allowed_groups.iter().any(|g| g == group_name) {
        return Err(format!(
            "Group '{}' is not in the allowed groups list. Allowed groups: {:?}",
            group_name, config.allowed_groups
        ));
    }

    Ok(())
}

/// GET /Authentik/AllowedGroups - get the list of allowed group names
#[get("/AllowedGroups")]
pub async fn get_allowed_groups(
    _manager: AuthenticatedUser<Management>,
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

    Ok(Json(authentik_config.allowed_groups.clone()))
}

/// POST /Authentik/AddUserToGroup - add a user to an Authentik group by ckey
#[post("/AddUserToGroup", format = "json", data = "<request>")]
pub async fn add_user_to_group(
    manager: AuthenticatedUser<Management>,
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

    // Validate group is in the allowed whitelist
    validate_group_allowed(authentik_config, &request.group_name).map_err(|e| {
        (
            Status::Forbidden,
            Json(AuthentikError {
                error: "group_not_allowed".to_string(),
                message: e,
            }),
        )
    })?;

    let http_client = reqwest::Client::new();

    // Step 1: Find the group by name
    let group_pk = find_group_by_name(&http_client, authentik_config, &request.group_name)
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

    // Step 2: Find the user by ckey attribute
    let user_pk = find_user_by_ckey(&http_client, authentik_config, &request.ckey)
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

    // Step 3: Add the user to the group
    add_user_to_authentik_group(&http_client, authentik_config, user_pk, &group_pk)
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

    // Log the action
    let _ = log_external(
        config,
        "User Manager: User Added to Group".to_string(),
        format!(
            "{} added ckey '{}' to group '{}'",
            manager.username, request.ckey, request.group_name
        ),
        true,
    )
    .await;

    Ok(Json(AuthentikSuccess {
        message: format!(
            "Successfully added user with ckey '{}' to group '{}'",
            request.ckey, request.group_name
        ),
    }))
}

/// find an Authentik user by their ckey attribute
async fn find_user_by_ckey(
    client: &reqwest::Client,
    config: &AuthentikConfig,
    ckey: &str,
) -> Result<i64, String> {
    let url = format!(
        "{}/api/v3/core/users/?attributes={{\"ckey\": \"{}\"}}",
        config.base_url.trim_end_matches('/'),
        ckey
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

    if search_response.results.is_empty() {
        return Err(format!("No user found with ckey '{}'", ckey));
    }

    if search_response.results.len() > 1 {
        return Err(format!(
            "Multiple users found with ckey '{}', expected exactly one",
            ckey
        ));
    }

    Ok(search_response.results[0].pk)
}

/// find an Authentik group by name and return its UUID
async fn find_group_by_name(
    client: &reqwest::Client,
    config: &AuthentikConfig,
    group_name: &str,
) -> Result<String, String> {
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

    Ok(search_response.results[0].pk.clone())
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
    manager: AuthenticatedUser<Management>,
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

    // Validate group is in the allowed whitelist
    validate_group_allowed(authentik_config, &request.group_name).map_err(|e| {
        (
            Status::Forbidden,
            Json(AuthentikError {
                error: "group_not_allowed".to_string(),
                message: e,
            }),
        )
    })?;

    let http_client = reqwest::Client::new();

    // Step 1: Find the group by name
    let group_pk = find_group_by_name(&http_client, authentik_config, &request.group_name)
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

    // Step 2: Find the user by ckey attribute
    let user_pk = find_user_by_ckey(&http_client, authentik_config, &request.ckey)
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

    // Step 3: Remove the user from the group
    remove_user_from_authentik_group(&http_client, authentik_config, user_pk, &group_pk)
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

    // Log the action
    let _ = log_external(
        config,
        "User Manager: User Removed from Group".to_string(),
        format!(
            "{} removed ckey '{}' from group '{}'",
            manager.username, request.ckey, request.group_name
        ),
        true,
    )
    .await;

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
    _manager: AuthenticatedUser<Management>,
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

    // Validate group is in the allowed whitelist
    validate_group_allowed(authentik_config, &group_name).map_err(|e| {
        (
            Status::Forbidden,
            Json(AuthentikError {
                error: "group_not_allowed".to_string(),
                message: e,
            }),
        )
    })?;

    let http_client = reqwest::Client::new();

    // Step 1: Find the group by name
    let group_pk = find_group_by_name(&http_client, authentik_config, &group_name)
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

    // Step 2: Fetch group members
    let members = fetch_group_members(&http_client, authentik_config, &group_pk)
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
