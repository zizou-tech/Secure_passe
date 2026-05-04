<?php
/**
 * Configuration de sécurité pour SecurePass
 * Constantes et paramètres de sécurité conformes au cahier des charges
 */

// Empêcher l'accès direct au fichier
if (!defined('SECURE_ACCESS')) {
    die('Accès direct non autorisé');
}

// ================================
// CONFIGURATION GÉNÉRALE
// ================================

// Mode debug (à désactiver en production)
define('DEBUG', false);

// Durée de session (24 heures)
define('SESSION_LIFETIME', 24 * 60 * 60);

// Nom du cookie de session
define('SESSION_NAME', 'securepass_session');

// ================================
// CONFIGURATION MOTS DE PASSE
// ================================

// Longueur minimale des mots de passe générés
define('PASSWORD_MIN_LENGTH', 12);

// Longueur maximale des mots de passe générés
define('PASSWORD_MAX_LENGTH', 128);

// Longueur minimale du mot de passe maître
define('MASTER_PASSWORD_MIN_LENGTH', 8);

// Caractères par défaut pour la génération
define('CHARSET_LOWERCASE', 'abcdefghijklmnopqrstuvwxyz');
define('CHARSET_UPPERCASE', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ');
define('CHARSET_NUMBERS', '0123456789');
define('CHARSET_SPECIAL', '!@#$%^&*()_+-=[]|;:,.<>?');

// Caractères ambigus à exclure si demandé
define('CHARSET_AMBIGUOUS', '0Ol1I');

// ================================
// CONFIGURATION CHIFFREMENT
// ================================

// Algorithme de chiffrement (AES-256-GCM)
define('CIPHER_METHOD', 'aes-256-gcm');

// Longueur de la clé de chiffrement (32 bytes pour AES-256)
define('CIPHER_KEY_LENGTH', 32);

// Longueur de l'IV (16 bytes pour AES)
define('CIPHER_IV_LENGTH', 16);

// Longueur du tag d'authentification GCM
define('CIPHER_TAG_LENGTH', 16);

// ================================
// CONFIGURATION PBKDF2
// ================================

// Nombre d'itérations PBKDF2 (minimum recommandé)
define('PBKDF2_ITERATIONS', 100000);

// Longueur du salt (32 bytes)
define('PBKDF2_SALT_LENGTH', 32);

// Algorithme de hashage pour PBKDF2
define('PBKDF2_ALGORITHM', 'sha256');

// ================================
// CONFIGURATION BCRYPT
// ================================

// Coût bcrypt (12 pour un bon équilibre sécurité/performance)
define('BCRYPT_COST', 12);

// ================================
// CONFIGURATION SÉCURITÉ WEB
// ================================

// Headers de sécurité
define('SECURITY_HEADERS', [
    'X-Content-Type-Options' => 'nosniff',
    'X-Frame-Options' => 'DENY',
    'X-XSS-Protection' => '1; mode=block',
    'Referrer-Policy' => 'strict-origin-when-cross-origin',
    'Content-Security-Policy' => "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' https://api.pwnedpasswords.com;",
    'Strict-Transport-Security' => 'max-age=31536000; includeSubDomains; preload'
]);

// ================================
// CONFIGURATION RATE LIMITING
// ================================

// Nombre maximum de tentatives de connexion par IP
define('MAX_LOGIN_ATTEMPTS', 5);

// Durée de blocage après échec (15 minutes)
define('LOGIN_BLOCK_DURATION', 15 * 60);

// Nombre maximum de requêtes API par minute
define('API_RATE_LIMIT', 60);

// ================================
// CONFIGURATION API EXTERNE
// ================================

// URL de l'API HaveIBeenPwned
define('HIBP_API_URL', 'https://api.pwnedpasswords.com/range/');

// User-Agent pour les requêtes API
define('API_USER_AGENT', 'SecurePass-PasswordManager/1.0');

// Timeout pour les requêtes externes (5 secondes)
define('API_TIMEOUT', 5);

// ================================
// CONFIGURATION VALIDATION
// ================================

// Regex pour validation email
define('EMAIL_REGEX', '/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/');

// Regex pour validation nom d'utilisateur (alphanumérique + underscore, 3-20 caractères)
define('USERNAME_REGEX', '/^[a-zA-Z0-9_]{3,20}$/');

// Longueur maximale des notes associées aux mots de passe
define('NOTES_MAX_LENGTH', 1000);

// Longueur maximale des noms de dossiers/catégories
define('FOLDER_NAME_MAX_LENGTH', 50);

// ================================
// CONFIGURATION PERFORMANCE
// ================================

// Temps maximum de génération de mot de passe (100ms)
define('PASSWORD_GENERATION_TIMEOUT', 0.1);

// Temps maximum de chiffrement/déchiffrement (500ms)
define('CRYPTO_TIMEOUT', 0.5);

// Nombre maximum de mots de passe en génération lot
define('BATCH_GENERATION_LIMIT', 100);

// ================================
// CONFIGURATION LOGS
// ================================

// Niveau de log (0=NONE, 1=ERROR, 2=WARNING, 3=INFO, 4=DEBUG)
define('LOG_LEVEL', DEBUG ? 4 : 1);

// Fichier de log (relatif au dossier logs/)
define('LOG_FILE', 'securepass.log');

// Rotation des logs (en MB)
define('LOG_MAX_SIZE', 10);

// ================================
// CONFIGURATION NETTOYAGE
// ================================

// Durée de conservation des sessions expirées (7 jours)
define('SESSION_CLEANUP_AFTER', 7 * 24 * 60 * 60);

// Durée de conservation des logs de tentatives de connexion (30 jours)
define('LOGIN_ATTEMPTS_CLEANUP_AFTER', 30 * 24 * 60 * 60);

// Durée de conservation des tokens de récupération (1 heure)
define('RECOVERY_TOKEN_LIFETIME', 60 * 60);

// ================================
// SCORES DE ROBUSTESSE
// ================================

// Seuils pour les scores de robustesse (sur 100)
define('STRENGTH_SCORE_WEAK', 30);
define('STRENGTH_SCORE_MEDIUM', 60);
define('STRENGTH_SCORE_STRONG', 80);

// Points par critère de robustesse
define('STRENGTH_POINTS', [
    'length_base' => 4,        // Points par caractère
    'length_bonus' => 2,       // Bonus pour longueur > 12
    'uppercase' => 5,          // Bonus majuscules
    'lowercase' => 5,          // Bonus minuscules
    'numbers' => 5,            // Bonus chiffres
    'special' => 10,           // Bonus caractères spéciaux
    'variety' => 15,           // Bonus variété des caractères
    'no_common' => 20,         // Bonus si pas dans dictionnaire
    'entropy_bonus' => 10      // Bonus entropie élevée
]);

// ================================
// CONSTANTES SYSTÈME
// ================================

// Encodage par défaut
define('DEFAULT_ENCODING', 'UTF-8');

// Timezone par défaut
define('DEFAULT_TIMEZONE', 'Europe/Paris');

// Taille maximale des fichiers uploadés (si applicable)
define('MAX_UPLOAD_SIZE', 1024 * 1024); // 1MB

// ================================
// CONFIGURATION 2FA (optionnel)
// ================================

// Durée de validité du code 2FA (30 secondes)
define('TOTP_PERIOD', 30);

// Nombre de codes de récupération 2FA
define('RECOVERY_CODES_COUNT', 10);

// Longueur des codes de récupération
define('RECOVERY_CODE_LENGTH', 8);

// ================================
// FONCTIONS UTILITAIRES DE SÉCURITÉ
// ================================

/**
 * Génère un token sécurisé
 */
function generate_secure_token($length = 32) {
    return bin2hex(random_bytes($length));
}

/**
 * Génère un salt sécurisé
 */
function generate_salt($length = PBKDF2_SALT_LENGTH) {
    return random_bytes($length);
}

/**
 * Vérifie si HTTPS est activé
 */
function is_https() {
    return (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || $_SERVER['SERVER_PORT'] == 443
        || (!empty($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] == 'https');
}

/**
 * Applique les headers de sécurité
 */
function apply_security_headers() {
    foreach (SECURITY_HEADERS as $header => $value) {
        header($header . ': ' . $value);
    }
}

/**
 * Vérifie la force du mot de passe maître
 */
function is_master_password_strong($password) {
    $score = 0;
    $length = strlen($password);
    
    // Longueur minimale
    if ($length < MASTER_PASSWORD_MIN_LENGTH) {
        return false;
    }
    
    // Critères de complexité
    if (preg_match('/[a-z]/', $password)) $score += 25;
    if (preg_match('/[A-Z]/', $password)) $score += 25;
    if (preg_match('/[0-9]/', $password)) $score += 25;
    if (preg_match('/[^a-zA-Z0-9]/', $password)) $score += 25;
    
    return $score >= 75; // Au moins 3 critères sur 4
}

/**
 * Nettoie une chaîne pour éviter les injections
 */
function sanitize_string($string, $max_length = 255) {
    $string = trim($string);
    $string = filter_var($string, FILTER_SANITIZE_STRING, FILTER_FLAG_NO_ENCODE_QUOTES);
    
    if ($max_length > 0) {
        $string = substr($string, 0, $max_length);
    }
    
    return $string;
}

// ================================
// INITIALISATION
// ================================

// Définir la timezone
date_default_timezone_set(DEFAULT_TIMEZONE);

// Configurer les sessions de manière sécurisée
if (session_status() === PHP_SESSION_NONE) {
    // Configuration sécurisée des sessions
    ini_set('session.cookie_httponly', 1);
    ini_set('session.cookie_secure', is_https() ? 1 : 0);
    ini_set('session.use_strict_mode', 1);
    ini_set('session.cookie_samesite', 'Strict');
    ini_set('session.gc_maxlifetime', SESSION_LIFETIME);
    
    session_name(SESSION_NAME);
}

// Appliquer les headers de sécurité
apply_security_headers();

?>