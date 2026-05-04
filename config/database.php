<?php
// Fichier de configuration de la base de données
// Configuration des constantes de base de données
define('DB_SERVER', 'localhost');
define('DB_USERNAME', 'root');
define('DB_PASSWORD', '');
define('DB_NAME', 'SecurePass_db');

// Configuration pour la connexion sécurisée
define('DB_CHARSET', 'utf8mb4');
define('DB_COLLATION', 'utf8mb4_unicode_ci');

// Tentative de connexion à la base de données MySQL
try {
    $link = mysqli_connect(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);
    
    // Vérifier la connexion
    if ($link === false) {
        throw new Exception("Impossible de se connecter à la base de données: " . mysqli_connect_error());
    }
    
    // Définir le charset pour éviter les problèmes d'encodage
    if (!mysqli_set_charset($link, DB_CHARSET)) {
        throw new Exception("Erreur lors de la définition du charset: " . mysqli_error($link));
    }
    
    // Configuration des options de sécurité MySQL
    mysqli_options($link, MYSQLI_OPT_CONNECT_TIMEOUT, 5);
    
} catch (Exception $e) {
    // Log l'erreur (en production, utilisez un système de log approprié)
    error_log("Erreur de connexion DB: " . $e->getMessage());
    
    // En production, ne pas exposer les détails de l'erreur
    if (defined('DEBUG') && DEBUG === true) {
        die("ERREUR DB: " . $e->getMessage());
    } else {
        die("Erreur de connexion à la base de données. Veuillez réessayer plus tard.");
    }
}

// Fonction utilitaire pour nettoyer les entrées
function sanitize_input($data) {
    global $link;
    $data = trim($data);
    $data = stripslashes($data);
    $data = htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
    return mysqli_real_escape_string($link, $data);
}

// Fonction pour exécuter des requêtes préparées de manière sécurisée
function execute_query($sql, $types = "", $params = []) {
    global $link;
    
    $stmt = mysqli_prepare($link, $sql);
    if (!$stmt) {
        error_log("Erreur de préparation: " . mysqli_error($link));
        return false;
    }
    
    if (!empty($params) && !empty($types)) {
        mysqli_stmt_bind_param($stmt, $types, ...$params);
    }
    
    $result = mysqli_stmt_execute($stmt);
    if (!$result) {
        error_log("Erreur d'exécution: " . mysqli_stmt_error($stmt));
        mysqli_stmt_close($stmt);
        return false;
    }
    
    return $stmt;
}

// Fonction pour fermer proprement la connexion
function close_db_connection() {
    global $link;
    if ($link) {
        mysqli_close($link);
    }
}

// Gérer la fermeture de la connexion à la fin du script
register_shutdown_function('close_db_connection');
?>