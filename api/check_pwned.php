<?php
/**
 * SecurePass — api/check_pwned.php
 * Vérifie si un mot de passe a été compromis via l'API HaveIBeenPwned (k-anonymat).
 * Le mot de passe n'est JAMAIS envoyé en clair : seuls les 5 premiers caractères
 * du hash SHA-1 sont transmis à l'API (protocole k-anonymat).
 *
 * Requête attendue : POST JSON { "password": "..." }
 *                 ou GET  ?hash_prefix=XXXXX (5 premiers chars SHA-1, majuscules)
 * Réponse JSON : { "success": bool, "pwned": bool, "count": int, "message": string }
 */

session_start();
header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');

// --- Authentification de session ---
if (!isset($_SESSION['user_id'])) {
    http_response_code(401);
    echo json_encode(['success' => false, 'message' => 'Non autorisé.']);
    exit();
}

// --- Rate limiting simple (session) ---
$rl_key = 'pwned_check_' . $_SESSION['user_id'];
$now    = time();
if (!isset($_SESSION[$rl_key])) {
    $_SESSION[$rl_key] = ['count' => 0, 'window' => $now];
}
// Réinitialise la fenêtre toutes les 60 s
if ($now - $_SESSION[$rl_key]['window'] > 60) {
    $_SESSION[$rl_key] = ['count' => 0, 'window' => $now];
}
if ($_SESSION[$rl_key]['count'] >= 30) {
    http_response_code(429);
    echo json_encode(['success' => false, 'message' => 'Trop de requêtes. Réessayez dans une minute.']);
    exit();
}
$_SESSION[$rl_key]['count']++;

// --- Récupération du mot de passe ou du préfixe ---
$hash_prefix = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $body = json_decode(file_get_contents('php://input'), true);
    if (isset($body['password']) && strlen($body['password']) > 0) {
        $sha1        = strtoupper(sha1($body['password']));
        $hash_prefix = substr($sha1, 0, 5);
        $hash_suffix = substr($sha1, 5);
    } elseif (isset($body['hash_prefix'])) {
        $hash_prefix = strtoupper(substr(preg_replace('/[^a-fA-F0-9]/', '', $body['hash_prefix']), 0, 5));
        $hash_suffix = null;
    }
} elseif ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['hash_prefix'])) {
    $hash_prefix = strtoupper(substr(preg_replace('/[^a-fA-F0-9]/', '', $_GET['hash_prefix']), 0, 5));
    $hash_suffix = null;
}

if (!$hash_prefix || strlen($hash_prefix) !== 5) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'Paramètre manquant ou invalide.']);
    exit();
}

// --- Appel à l'API HaveIBeenPwned ---
$api_url = 'https://api.pwnedpasswords.com/range/' . $hash_prefix;

$ctx = stream_context_create([
    'http' => [
        'method'          => 'GET',
        'header'          => "User-Agent: SecurePass/1.0 (Password Manager)\r\nAdd-Padding: true\r\n",
        'timeout'         => 5,
        'ignore_errors'   => true,
    ],
    'ssl' => [
        'verify_peer'      => true,
        'verify_peer_name' => true,
    ],
]);

$response = @file_get_contents($api_url, false, $ctx);

if ($response === false) {
    // L'API est injoignable : on retourne un résultat neutre plutôt qu'une erreur bloquante
    echo json_encode([
        'success' => true,
        'pwned'   => false,
        'count'   => 0,
        'message' => 'Impossible de contacter le service de vérification. Réessayez plus tard.',
        'offline' => true,
    ]);
    exit();
}

// --- Analyse de la réponse ---
// Format : "SUFFIXE_SHA1:OCCURRENCES\r\n" par ligne
$lines  = explode("\r\n", trim($response));
$pwned  = false;
$count  = 0;

foreach ($lines as $line) {
    if (empty($line)) continue;
    [$suffix, $occurrences] = explode(':', $line, 2);
    if ($hash_suffix !== null && strtoupper(trim($suffix)) === strtoupper(trim($hash_suffix))) {
        $pwned = true;
        $count = (int) trim($occurrences);
        break;
    }
    // Si on n'a pas le suffixe (appel direct avec hash_prefix uniquement), on liste tout
    if ($hash_suffix === null) {
        // Ne pas exposer les suffixes pour des raisons de sécurité
    }
}

$message = $pwned
    ? "⚠️ Ce mot de passe a été trouvé dans {$count} fuite(s) de données. N'utilisez pas ce mot de passe !"
    : "✅ Aucune fuite connue pour ce mot de passe.";

echo json_encode([
    'success' => true,
    'pwned'   => $pwned,
    'count'   => $count,
    'message' => $message,
]);
