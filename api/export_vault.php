<?php
/**
 * SecurePass — api/export_vault.php
 * Exporte tous les mots de passe déchiffrés au format JSON.
 * Requiert le mot de passe maître pour déchiffrer chaque entrée.
 */

session_start();

header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');

// Auth
if (!isset($_SESSION['user_id'])) {
    http_response_code(401);
    die('Non autorisé.');
}

// CSRF
$csrf = $_POST['csrf_token'] ?? '';
if (empty($csrf) || empty($_SESSION['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $csrf)) {
    http_response_code(403);
    die('Token CSRF invalide.');
}

// Méthode
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    die('Méthode non autorisée.');
}

$master_password = $_POST['master_password'] ?? '';
if (empty($master_password)) {
    $_SESSION['error_message'] = 'Le mot de passe maître est requis pour exporter.';
    header('Location: ../pages/settings.php');
    exit();
}

require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../includes/crypto.php';

$user_id = (int) $_SESSION['user_id'];
$aes     = new AES256Encryption();

// Vérifier le mot de passe maître
$stmt = mysqli_prepare($link, "SELECT password_hash, prenom, nom, email FROM users WHERE id = ?");
mysqli_stmt_bind_param($stmt, 'i', $user_id);
mysqli_stmt_execute($stmt);
$user = mysqli_fetch_assoc(mysqli_stmt_get_result($stmt));
mysqli_stmt_close($stmt);

if (!$user || !password_verify($master_password, $user['password_hash'])) {
    $_SESSION['error_message'] = 'Mot de passe maître incorrect. Export annulé.';
    header('Location: ../pages/settings.php');
    exit();
}

// Récupérer toutes les entrées du coffre
$stmt = mysqli_prepare($link,
    "SELECT id, site_name, site_url, username, email, password_encrypted, notes, category, is_favorite, strength_score, created_at, updated_at
     FROM saved_passwords WHERE user_id = ? ORDER BY site_name ASC");
mysqli_stmt_bind_param($stmt, 'i', $user_id);
mysqli_stmt_execute($stmt);
$rows = mysqli_fetch_all(mysqli_stmt_get_result($stmt), MYSQLI_ASSOC);
mysqli_stmt_close($stmt);

// Déchiffrer chaque mot de passe
$entries = [];
$errors  = 0;
foreach ($rows as $row) {
    $plain = $aes->decrypt($row['password_encrypted'], $master_password);
    if ($plain === false) {
        $errors++;
        $plain = '[ERREUR DE DÉCHIFFREMENT]';
    }
    $entries[] = [
        'id'           => $row['id'],
        'site_name'    => $row['site_name'],
        'site_url'     => $row['site_url'] ?? '',
        'username'     => $row['username'] ?? '',
        'email'        => $row['email'] ?? '',
        'password'     => $plain,
        'notes'        => $row['notes'] ?? '',
        'category'     => $row['category'] ?? 'Général',
        'is_favorite'  => (bool) $row['is_favorite'],
        'strength_score' => (int) ($row['strength_score'] ?? 0),
        'created_at'   => $row['created_at'],
        'updated_at'   => $row['updated_at'],
    ];
}

// Construire le payload JSON
$export = [
    'export_info' => [
        'app'          => 'SecurePass',
        'version'      => '1.0',
        'exported_at'  => date('Y-m-d H:i:s'),
        'owner'        => $user['prenom'] . ' ' . $user['nom'],
        'email'        => $user['email'],
        'total'        => count($entries),
        'decrypt_errors' => $errors,
        'warning'      => 'Ce fichier contient vos mots de passe en clair. Conservez-le dans un endroit sécurisé et supprimez-le après utilisation.',
    ],
    'passwords' => $entries,
];

$json     = json_encode($export, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
$filename = 'securepass_export_' . date('Y-m-d_H-i-s') . '.json';

// Forcer le téléchargement
header('Content-Type: application/json; charset=utf-8');
header('Content-Disposition: attachment; filename="' . $filename . '"');
header('Content-Length: ' . strlen($json));
header('Cache-Control: no-store, no-cache, must-revalidate');
header('Pragma: no-cache');

echo $json;
exit();
