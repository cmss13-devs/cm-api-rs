-- Schema for the cmapi database
-- Used by cm-api-rs for storing Steam authentication tokens

CREATE DATABASE IF NOT EXISTS cmapi;
USE cmapi;

CREATE TABLE steam_tokens (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    token VARCHAR(64) NOT NULL UNIQUE,
    steam_id VARCHAR(64) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,

    INDEX idx_token (token),
    INDEX idx_expires_at (expires_at),
    INDEX idx_steam_id (steam_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
