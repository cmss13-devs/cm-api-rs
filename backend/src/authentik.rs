use std::collections::HashMap;

use rocket::{State, http::Status, serde::json::Json};
use serde::{Deserialize, Serialize};

use crate::{
    Config,
    admin::{AuthenticatedUser, Management, Staff},
    logging::log_external,
};

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AuthentikConfig {
    pub token: String,
    pub base_url: String,
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

#[derive(Debug, Deserialize, Clone)]
struct AuthentikGroup {
    pk: String,
    #[serde(default)]
    attributes: serde_json::Value,
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

    add_user_to_authentik_group(&http_client, authentik_config, user_pk, &group.pk)
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

    remove_user_from_authentik_group(&http_client, authentik_config, user_pk, &group.pk)
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

/// GET /Authentik/GroupAdminRanks/<group_name> - get the admin_ranks attribute for a group
#[get("/GroupAdminRanks/<group_name>")]
pub async fn get_group_admin_ranks(
    user: AuthenticatedUser<Management>,
    config: &State<Config>,
    group_name: String,
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

    let admin_ranks = group
        .attributes
        .get("admin_ranks")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    Ok(Json(GroupAdminRanksResponse {
        group_name,
        admin_ranks,
        allowed_ranks: authentik_config.allowed_admin_ranks.clone(),
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
        obj.insert(
            "admin_ranks".to_string(),
            serde_json::json!(request.admin_ranks),
        );
    } else {
        attributes = serde_json::json!({
            "admin_ranks": request.admin_ranks
        });
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
            "{} updated admin_ranks for group '{}' to: {:?}",
            user.username, request.group_name, request.admin_ranks
        ),
        true,
    )
    .await;

    Ok(Json(AuthentikSuccess {
        message: format!(
            "Successfully updated admin_ranks for group '{}'",
            request.group_name
        ),
    }))
}
