use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi};

use crate::{
    achievements, auth, byond, connections, discord, new_players, player, stickyban, ticket,
    twofactor, whitelist,
};

/// Security scheme modifier to add authentication definitions
struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            // Cookie-based session authentication
            components.add_security_scheme(
                "session_cookie",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .bearer_format("JWT")
                        .description(Some("Session cookie (JWT) for authenticated users"))
                        .build(),
                ),
            );
            // Bearer token for API authentication
            components.add_security_scheme(
                "bearer_token",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .description(Some("Bearer token for API authorization"))
                        .build(),
                ),
            );
        }
    }
}

#[derive(OpenApi)]
#[openapi(
    info(
        title = "CM API",
        version = "0.1.0",
        description = "CM-SS13 API"
    ),
    modifiers(&SecurityAddon),
    paths(
        // Auth endpoints
        auth::userinfo,
        // Player endpoints
        player::index,
        player::id,
        player::applied_notes,
        player::get_playtime,
        player::get_recent_playtime,
        player::get_total_playtime,
        player::get_vpn_whitelist,
        player::add_vpn_whitelist,
        player::remove_vpn_whitelist,
        player::get_banned_players,
        player::get_ban_history,
        player::get_known_alts,
        player::add_known_alt,
        player::remove_known_alt,
        // Connections endpoints
        connections::ip,
        connections::cid,
        connections::ckey,
        connections::connection_history_by_cid,
        connections::connection_history_by_ip,
        // Stickyban endpoints
        stickyban::all_stickybans,
        stickyban::whitelist,
        stickyban::get_matched_cids,
        stickyban::get_all_cid,
        stickyban::get_matched_ckey,
        stickyban::get_all_ckey,
        stickyban::get_matched_ip,
        stickyban::get_all_ip,
        // Ticket endpoints
        ticket::get_tickets_by_round_id,
        ticket::get_tickets_by_user,
        // Whitelist endpoints
        whitelist::get_all_whitelistees,
        // New players endpoints
        new_players::get_new_players,
        // Round/Byond endpoints
        byond::round,
        byond::recent,
        byond::byond_hash,
        // Discord endpoints
        discord::get_user_by_discord,
        discord::check_verified,
        discord::get_my_profile,
        // Achievements endpoints
        achievements::get_achievements,
        achievements::set_achievement,
        // Two factor endpoints
        twofactor::twofactor_validate,
    ),
    components(
        schemas(
            // Auth schemas
            auth::UserInfo,
            auth::AuthError,
            // Player schemas
            player::Player,
            player::Note,
            player::JobBan,
            player::Playtime,
            player::VpnWhitelist,
            player::BannedPlayer,
            player::HistoricalBan,
            player::KnownAltsResponse,
            player::AddKnownAltRequest,
            player::RemoveKnownAltRequest,
            // Connections schemas
            connections::LoginTriplet,
            connections::ConnectionHistory,
            // Stickyban schemas
            stickyban::Stickyban,
            stickyban::StickybanMatchedCid,
            stickyban::StickybanMatchedCkey,
            stickyban::StickybanMatchedIp,
            // Ticket schemas
            ticket::Ticket,
            // Whitelist schemas
            whitelist::WhitelistPlayer,
            // Byond schemas
            byond::GameResponse,
            byond::GameStatus,
            byond::ServerStatusResponse,
            byond::ServersResponse,
            byond::Round,
            byond::ByondHashResponse,
            // Discord schemas
            discord::DiscordError,
            discord::DiscordUserResponse,
            discord::VerifiedUserResponse,
            discord::DiscordProfileResponse,
            // Achievements schemas
            achievements::AchievementsResponse,
            achievements::SetAchievementRequest,
            achievements::SetAchievementResponse,
        )
    ),
    tags(
        (name = "auth", description = "Authentication endpoints"),
        (name = "player", description = "Player data and management"),
        (name = "connections", description = "Player connection history (IP/CID/ckey lookup)"),
        (name = "stickyban", description = "Stickyban management"),
        (name = "ticket", description = "Admin ticket viewer"),
        (name = "whitelist", description = "Player whitelist management"),
        (name = "new_players", description = "New player tracking"),
        (name = "round", description = "Game round information (public)"),
        (name = "byond", description = "BYOND version verification (public)"),
        (name = "discord", description = "Discord integration"),
        (name = "achievements", description = "Steam achievements integration"),
        (name = "twofactor", description = "Two-factor authentication validation"),
    )
)]
pub struct ApiDoc;
