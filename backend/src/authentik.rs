use std::collections::HashMap;

use rocket::{State, http::Status, serde::json::Json};
use serde::{Deserialize, Serialize};
use serde_json::Map;

use crate::{
    Config,
    admin::{AuthenticatedUser, Management, Staff},
    logging::log_external,
    player::AuthorizationHeader,
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
    /// list of allowed instance names for admin_ranks configuration
    /// eg: allowed_instances = ["cm13-live", "cm13-rp"]
    #[serde(default)]
    pub allowed_instances: Vec<String>,
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
    name: String,
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
    pub instance_name: String,
}

/// User info for the admin ranks export endpoint
#[derive(Debug, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct AdminRanksUser {
    pub ckey: String,
    pub primary_group: String,
}

/// Response for the admin ranks export endpoint
#[derive(Debug, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct AdminRanksExportResponse {
    pub users: Vec<AdminRanksUser>,
    pub groups: HashMap<String, HashMap<String, Vec<String>>>,
}

/// Extended group info including name and priority for sorting
#[derive(Debug, Clone)]
struct GroupWithPriority {
    name: String,
    priority: i64,
    admin_ranks: HashMap<String, Vec<String>>,
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

    #[derive(Deserialize)]
    struct AdminRanksResponse {
        admin_ranks: HashMap<String, Vec<String>>,
    }

    let ranks_response: AdminRanksResponse =
        serde_json::from_value(group.attributes).map_err(|e| {
            (
                Status::InternalServerError,
                Json(AuthentikError {
                    error: "could_not_deserialize".to_string(),
                    message: e.to_string(),
                }),
            )
        })?;

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

/// fetch all groups that have admin_ranks attribute set
async fn fetch_groups_with_admin_ranks(
    client: &reqwest::Client,
    config: &AuthentikConfig,
) -> Result<Vec<GroupWithPriority>, String> {
    let mut all_groups = Vec::new();
    let mut page = 1;
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

                all_groups.push(GroupWithPriority {
                    name: group.name,
                    priority,
                    admin_ranks,
                });
            }
        }

        page += 1;
    }

    Ok(all_groups)
}

/// Extended user info including groups for the export endpoint
#[derive(Debug, Deserialize)]
struct AuthentikUserWithGroups {
    #[serde(default)]
    attributes: serde_json::Value,
    #[serde(default)]
    groups_obj: Vec<AuthentikGroupRef>,
}

#[derive(Debug, Deserialize)]
struct AuthentikGroupRef {
    name: String,
}

#[derive(Debug, Deserialize)]
struct AuthentikUserWithGroupsSearchResponse {
    results: Vec<AuthentikUserWithGroups>,
}

/// Fetch all users in a specific group with their group memberships
async fn fetch_users_in_group_with_memberships(
    client: &reqwest::Client,
    config: &AuthentikConfig,
    group_pk: &str,
) -> Result<Vec<AuthentikUserWithGroups>, String> {
    let mut all_users = Vec::new();
    let mut page = 1;
    let page_size = 100;

    loop {
        let url = format!(
            "{}/api/v3/core/users/?groups_by_pk={}&page={}&page_size={}",
            config.base_url.trim_end_matches('/'),
            group_pk,
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

        let search_response: AuthentikUserWithGroupsSearchResponse = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse Authentik response: {}", e))?;

        if search_response.results.is_empty() {
            break;
        }

        all_users.extend(search_response.results);
        page += 1;
    }

    Ok(all_users)
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

/// GET /Authentik/AdminRanksExport - export all users with admin ranks and their groups
/// This endpoint uses Authorization header instead of session-based auth
#[get("/AdminRanksExport")]
pub async fn get_admin_ranks_export(
    auth_header: AuthorizationHeader,
    config: &State<Config>,
) -> Result<Json<AdminRanksExportResponse>, (Status, Json<AuthentikError>)> {
    // Validate authorization header
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

    // Fetch all groups with admin_ranks
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

    // Build the groups map for the response
    let mut groups_map: HashMap<String, HashMap<String, Vec<String>>> = HashMap::new();
    for group in &groups_with_ranks {
        groups_map.insert(group.name.clone(), group.admin_ranks.clone());
    }

    // Create a map of group name to priority for quick lookup
    let group_priority_map: HashMap<String, i64> = groups_with_ranks
        .iter()
        .map(|g| (g.name.clone(), g.priority))
        .collect();

    // Fetch users from each group and deduplicate by ckey
    let mut users_map: HashMap<String, AdminRanksUser> = HashMap::new();
    let mut user_max_priority: HashMap<String, i64> = HashMap::new();

    for group in &groups_with_ranks {
        // Get group pk by name
        let group_info = get_group_by_name(&http_client, authentik_config, &group.name)
            .await
            .map_err(|e| {
                (
                    Status::InternalServerError,
                    Json(AuthentikError {
                        error: "fetch_group_failed".to_string(),
                        message: e,
                    }),
                )
            })?;

        let users =
            fetch_users_in_group_with_memberships(&http_client, authentik_config, &group_info.pk)
                .await
                .map_err(|e| {
                    (
                        Status::InternalServerError,
                        Json(AuthentikError {
                            error: "fetch_users_failed".to_string(),
                            message: e,
                        }),
                    )
                })?;

        for user in users {
            let Some(ckey) = user
                .attributes
                .get("ckey")
                .and_then(|v| v.as_str())
                .map(String::from)
            else {
                continue; // Skip users without ckey
            };

            // Find the user's primary group (highest priority group that has admin_ranks)
            let user_groups: Vec<&str> = user.groups_obj.iter().map(|g| g.name.as_str()).collect();

            let mut best_group: Option<(&str, i64)> = None;
            for user_group in &user_groups {
                if let Some(&priority) = group_priority_map.get(*user_group) {
                    match best_group {
                        None => best_group = Some((user_group, priority)),
                        Some((_, current_priority)) if priority > current_priority => {
                            best_group = Some((user_group, priority));
                        }
                        _ => {}
                    }
                }
            }

            if let Some((primary_group, priority)) = best_group {
                // Only update if this is the first time seeing this user or if we found a higher priority group
                let should_update = match user_max_priority.get(&ckey) {
                    None => true,
                    Some(&existing_priority) => priority > existing_priority,
                };

                if should_update {
                    users_map.insert(
                        ckey.clone(),
                        AdminRanksUser {
                            ckey: ckey.clone(),
                            primary_group: primary_group.to_string(),
                        },
                    );
                    user_max_priority.insert(ckey, priority);
                }
            }
        }
    }

    let users: Vec<AdminRanksUser> = users_map.into_values().collect();

    Ok(Json(AdminRanksExportResponse {
        users,
        groups: groups_map,
    }))
}
