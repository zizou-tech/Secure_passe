-- ============================================================
-- SecurePass — Schéma de base de données
-- Base : SecurePass_db
-- Charset : utf8mb4 / utf8mb4_unicode_ci
-- ============================================================

CREATE DATABASE IF NOT EXISTS `SecurePass_db`
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE `SecurePass_db`;

-- ============================================================
-- TABLE : users
-- Stocke les comptes utilisateurs.
-- ============================================================
CREATE TABLE IF NOT EXISTS `users` (
    `id`            INT UNSIGNED     NOT NULL AUTO_INCREMENT,
    `prenom`        VARCHAR(100)     NOT NULL,
    `nom`           VARCHAR(100)     NOT NULL,
    `email`         VARCHAR(255)     NOT NULL,
    `password_hash` VARCHAR(255)     NOT NULL COMMENT 'Bcrypt cost=12',
    -- Token pour la fonctionnalité "Se souvenir de moi"
    `remember_token`     VARCHAR(64)  DEFAULT NULL,
    `remember_token_hash`VARCHAR(255) DEFAULT NULL,
    `remember_expires`   DATETIME     DEFAULT NULL,
    -- Réinitialisation de mot de passe
    `reset_token`        VARCHAR(64)  DEFAULT NULL,
    `reset_token_expires`DATETIME     DEFAULT NULL,
    -- Métadonnées
    `last_login`    DATETIME         DEFAULT NULL,
    `login_count`   INT UNSIGNED     NOT NULL DEFAULT 0,
    `is_active`     TINYINT(1)       NOT NULL DEFAULT 1,
    `created_at`    DATETIME         NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at`    DATETIME         NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    PRIMARY KEY (`id`),
    UNIQUE  KEY `uq_email` (`email`),
    KEY     `idx_reset_token` (`reset_token`),
    KEY     `idx_remember_token` (`remember_token`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- TABLE : saved_passwords
-- Coffre-fort chiffré de mots de passe par utilisateur.
-- Le champ password_encrypted utilise AES-256-GCM (voir crypto.php).
-- ============================================================
CREATE TABLE IF NOT EXISTS `saved_passwords` (
    `id`                 INT UNSIGNED     NOT NULL AUTO_INCREMENT,
    `user_id`            INT UNSIGNED     NOT NULL,
    -- Informations sur le site / service
    `site_name`          VARCHAR(255)     NOT NULL,
    `site_url`           VARCHAR(2048)    DEFAULT NULL,
    `username`           VARCHAR(255)     DEFAULT NULL,
    `email`              VARCHAR(255)     DEFAULT NULL,
    -- Mot de passe chiffré (base64, format : sel+IV+tag+ciphertext)
    `password_encrypted` TEXT             NOT NULL,
    -- Métadonnées supplémentaires
    `notes`              TEXT             DEFAULT NULL,
    `category`           VARCHAR(100)     DEFAULT 'Général',
    `is_favorite`        TINYINT(1)       NOT NULL DEFAULT 0,
    -- Score de force (0-7, calculé par AES256Encryption::evaluatePasswordStrength)
    `strength_score`     TINYINT UNSIGNED NOT NULL DEFAULT 0,
    -- Suivi des compromissions (rempli par check_pwned.php)
    `is_compromised`     TINYINT(1)       NOT NULL DEFAULT 0,
    `compromised_count`  INT UNSIGNED     NOT NULL DEFAULT 0,
    `last_pwned_check`   DATETIME         DEFAULT NULL,
    -- Dates
    `created_at`         DATETIME         NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at`         DATETIME         NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    PRIMARY KEY (`id`),
    KEY `idx_user_id`        (`user_id`),
    KEY `idx_user_site`      (`user_id`, `site_name`),
    KEY `idx_user_favorite`  (`user_id`, `is_favorite`),
    KEY `idx_strength`       (`user_id`, `strength_score`),
    CONSTRAINT `fk_passwords_user`
        FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
        ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- TABLE : login_attempts
-- Historique des tentatives de connexion (rate limiting persistant).
-- Alternative plus robuste au rate limiting en session.
-- ============================================================
CREATE TABLE IF NOT EXISTS `login_attempts` (
    `id`           INT UNSIGNED  NOT NULL AUTO_INCREMENT,
    `ip_address`   VARCHAR(45)   NOT NULL COMMENT 'IPv4 ou IPv6',
    `email`        VARCHAR(255)  DEFAULT NULL COMMENT 'Email tenté (peut être NULL)',
    `attempted_at` DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `success`      TINYINT(1)    NOT NULL DEFAULT 0,
    `user_agent`   VARCHAR(512)  DEFAULT NULL,

    PRIMARY KEY (`id`),
    KEY `idx_ip_time` (`ip_address`, `attempted_at`),
    KEY `idx_email_time` (`email`, `attempted_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- TABLE : password_categories
-- Catégories personnalisées par utilisateur.
-- ============================================================
CREATE TABLE IF NOT EXISTS `password_categories` (
    `id`         INT UNSIGNED NOT NULL AUTO_INCREMENT,
    `user_id`    INT UNSIGNED NOT NULL,
    `name`       VARCHAR(100) NOT NULL,
    `icon`       VARCHAR(50)  DEFAULT 'fa-folder',
    `color`      VARCHAR(7)   DEFAULT '#667eea' COMMENT 'Couleur hex',
    `created_at` DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (`id`),
    UNIQUE  KEY `uq_user_category` (`user_id`, `name`),
    KEY     `idx_user_id` (`user_id`),
    CONSTRAINT `fk_categories_user`
        FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
        ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- TABLE : audit_log
-- Journal d'activité pour la sécurité (lecture, copie, export…).
-- ============================================================
CREATE TABLE IF NOT EXISTS `audit_log` (
    `id`          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `user_id`     INT UNSIGNED    NOT NULL,
    `action`      VARCHAR(100)    NOT NULL COMMENT 'Ex: password_view, password_copy, login, logout',
    `target_id`   INT UNSIGNED    DEFAULT NULL COMMENT 'ID de la ressource concernée',
    `target_type` VARCHAR(50)     DEFAULT NULL COMMENT 'Ex: saved_password, user',
    `ip_address`  VARCHAR(45)     DEFAULT NULL,
    `user_agent`  VARCHAR(512)    DEFAULT NULL,
    `created_at`  DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (`id`),
    KEY `idx_user_date` (`user_id`, `created_at`),
    KEY `idx_action`    (`action`),
    CONSTRAINT `fk_audit_user`
        FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
        ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- DONNÉES PAR DÉFAUT — Catégories standard
-- (insérées après la création des tables)
-- ============================================================
-- Ces catégories sont créées automatiquement lors de l'inscription
-- via un trigger ou l'appel PHP handle_registration().
-- Pour test uniquement (user_id = 1 doit exister) :
-- INSERT INTO password_categories (user_id, name, icon, color)
-- VALUES (1,'Réseaux sociaux','fa-users','#667eea'),
--        (1,'Banque & Finance','fa-university','#48bb78'),
--        (1,'Travail','fa-briefcase','#ed8936'),
--        (1,'Shopping','fa-shopping-cart','#f56565'),
--        (1,'Email','fa-envelope','#764ba2'),
--        (1,'Autre','fa-folder','#718096');

-- ============================================================
-- NETTOYAGE AUTOMATIQUE (événements MySQL)
-- ============================================================
-- Supprimer les tentatives de connexion de plus de 30 jours
DELIMITER $$
CREATE EVENT IF NOT EXISTS `cleanup_login_attempts`
ON SCHEDULE EVERY 1 DAY
DO
  DELETE FROM `login_attempts` WHERE `attempted_at` < NOW() - INTERVAL 30 DAY;
$$

-- Supprimer les logs d'audit de plus de 90 jours
CREATE EVENT IF NOT EXISTS `cleanup_audit_log`
ON SCHEDULE EVERY 1 DAY
DO
  DELETE FROM `audit_log` WHERE `created_at` < NOW() - INTERVAL 90 DAY;
$$
DELIMITER ;
