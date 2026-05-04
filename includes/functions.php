<?php
/**
 * Fichier de fonctions utilitaires globales pour l'application.
 *
 * Ce fichier doit être inclus au début des scripts qui en ont besoin.
 * Il gère le démarrage de la session et fournit des fonctions pour :
 * - La sécurité (tokens CSRF, nettoyage des sorties)
 * - La gestion de l'authentification (vérification de connexion)
 * - L'affichage des notifications
 * - L'analyse de mots de passe
 */

// Démarrer la session si elle n'est pas déjà active. Essentiel pour les variables de session.
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Inclure la configuration de la base de données.
require_once __DIR__ . '/../config/database.php';

// =============================================================================
// FONCTIONS DE SÉCURITÉ ET D'AUTHENTIFICATION
// =============================================================================

/**
 * Génère et stocke un token CSRF (Cross-Site Request Forgery) en session.
 *
 * @return string Le token CSRF généré.
 */
function generate_csrf_token(): string {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

/**
 * Valide un token CSRF fourni par rapport à celui en session.
 *
 * @param string $token Le token à valider.
 * @return bool True si le token est valide, False sinon.
 */
function validate_csrf_token(string $token): bool {
    return !empty($token) && !empty($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

/**
 * Vérifie si l'utilisateur est actuellement connecté.
 *
 * @return bool True si l'utilisateur est connecté, False sinon.
 */
function is_logged_in(): bool {
    return isset($_SESSION['loggedin']) && $_SESSION['loggedin'] === true;
}

/**
 * Exige que l'utilisateur soit connecté. S'il ne l'est pas,
 * redirige vers la page de connexion et arrête le script.
 * Doit être appelée au début des pages protégées.
 */
function require_login(): void {
    if (!is_logged_in()) {
        $_SESSION['error_message'] = "Veuillez vous connecter pour accéder à cette page.";
        header('Location: login.php');
        exit();
    }
}

/**
 * Nettoie une chaîne de caractères pour un affichage sécurisé en HTML.
 * Prévient les attaques XSS.
 *
 * @param string|null $data La chaîne à nettoyer.
 * @return string La chaîne nettoyée.
 */
function sanitize_output(?string $data): string {
    return htmlspecialchars($data ?? '', ENT_QUOTES, 'UTF-8');
}


// =============================================================================
// FONCTIONS D'INTERFACE UTILISATEUR (UI)
// =============================================================================

/**
 * Affiche une alerte (succès ou erreur) stockée en session, puis la supprime.
 * Conforme au pattern Post-Redirect-Get.
 */
function display_session_alert(): void {
    if (isset($_SESSION['error_message'])) {
        echo '<div class="alert error">⚠️ ' . sanitize_output($_SESSION['error_message']) . '</div>';
        unset($_SESSION['error_message']);
    }

    if (isset($_SESSION['success_message'])) {
        echo '<div class="alert success">✅ ' . sanitize_output($_SESSION['success_message']) . '</div>';
        unset($_SESSION['success_message']);
    }
}


// =============================================================================
// FONCTIONS D'ANALYSE DE MOTS DE PASSE
// (Note: Celles-ci pourraient aussi être intégrées à la classe AES256Encryption)
// =============================================================================

/**
 * Calcule l'entropie d'un mot de passe en bits.
 *
 * @param string $password Le mot de passe à analyser.
 * @return float L'entropie en bits.
 */
function calculate_entropy(string $password): float {
    if (empty($password)) {
        return 0.0;
    }

    $char_set_size = 0;
    if (preg_match('/[a-z]/', $password)) $char_set_size += 26;
    if (preg_match('/[A-Z]/', $password)) $char_set_size += 26;
    if (preg_match('/[0-9]/', $password)) $char_set_size += 10;
    if (preg_match('/[^a-zA-Z0-9]/', $password)) $char_set_size += 32; // Estimation commune pour les symboles

    if ($char_set_size === 0) {
        return 0.0;
    }
    
    // Formule de l'entropie : E = L * log2(N)
    // L = longueur du mot de passe
    // N = taille du jeu de caractères
    $entropy = strlen($password) * log($char_set_size, 2);
    
    return round($entropy, 2);
}

/**
 * Estime le temps nécessaire pour cracker un mot de passe par force brute.
 *
 * @param string $password Le mot de passe à analyser.
 * @param int $attempts_per_second Le nombre de tentatives de crack par seconde (hypothèse).
 * @return string Une estimation du temps lisible par un humain.
 */
function estimate_crack_time(string $password, int $attempts_per_second = 1000000000): string {
    $entropy = calculate_entropy($password);
    if ($entropy === 0.0) {
        return "Instantané";
    }
    
    // Nombre total de combinaisons possibles = 2^entropie
    $combinations = pow(2, $entropy);
    
    $seconds = $combinations / $attempts_per_second;
    
    if ($seconds < 1) return "Moins d'une seconde";
    if ($seconds < 60) return round($seconds) . " secondes";
    if ($seconds < 3600) return round($seconds / 60) . " minutes";
    if ($seconds < 86400) return round($seconds / 3600) . " heures";
    if ($seconds < 2592000) return round($seconds / 86400) . " jours"; // ~30 jours
    if ($seconds < 31536000) return round($seconds / 2592000) . " mois"; // ~1 an
    
    $years = round($seconds / 31536000);
    if ($years > 1000000) return "Plusieurs millions d'années";
    if ($years > 1000) return "Plusieurs milliers d'années";
    
    return number_format($years) . " années";
}

?>