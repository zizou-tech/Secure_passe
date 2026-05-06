<?php
/**
 * SecurePass — api/check_strength.php
 * Évalue la force d'un mot de passe côté serveur.
 * 
 * Requête : POST JSON { "password": "..." }
 * Réponse : {
 *   "success": bool,
 *   "score": int (0-7),
 *   "strength": string,
 *   "feedback": string[],
 *   "entropy": float,
 *   "crack_time": string,
 *   "checks": { lowercase, uppercase, numbers, symbols, length12, length16, noCommon }
 * }
 */

session_start();
header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');

// --- Auth ---
if (!isset($_SESSION['user_id'])) {
    http_response_code(401);
    echo json_encode(['success' => false, 'message' => 'Non autorisé.']);
    exit();
}

// --- Récupération ---
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['success' => false, 'message' => 'Méthode non autorisée.']);
    exit();
}

$body     = json_decode(file_get_contents('php://input'), true);
$password = $body['password'] ?? '';

if (!is_string($password) || strlen($password) === 0) {
    echo json_encode(['success' => false, 'message' => 'Mot de passe manquant.']);
    exit();
}

// Limiter à 512 caractères pour éviter les abus
$password = substr($password, 0, 512);

// -------------------------------------------------------
// ANALYSE
// -------------------------------------------------------

require_once __DIR__ . '/../includes/crypto.php';
$aes    = new AES256Encryption();
$result = $aes->evaluatePasswordStrength($password);

// Calcul entropie
$charsetSize = 0;
if (preg_match('/[a-z]/', $password)) $charsetSize += 26;
if (preg_match('/[A-Z]/', $password)) $charsetSize += 26;
if (preg_match('/[0-9]/', $password)) $charsetSize += 10;
if (preg_match('/[^a-zA-Z0-9]/', $password)) $charsetSize += 32;

$entropy = $charsetSize > 0 ? round(strlen($password) * log($charsetSize, 2), 2) : 0;

// Temps de crack (1 milliard de tentatives / s)
function estimate_crack_time_local(float $entropy): string {
    if ($entropy <= 0) return 'Instantané';
    $combinations = pow(2, $entropy);
    $seconds      = $combinations / 1e9;
    if ($seconds < 1)        return "Moins d'une seconde";
    if ($seconds < 60)       return round($seconds) . " secondes";
    if ($seconds < 3600)     return round($seconds / 60) . " minutes";
    if ($seconds < 86400)    return round($seconds / 3600) . " heures";
    if ($seconds < 2592000)  return round($seconds / 86400) . " jours";
    if ($seconds < 31536000) return round($seconds / 2592000) . " mois";
    $years = $seconds / 31536000;
    if ($years > 1e6)  return "Des millions d'années";
    if ($years > 1000) return "Des milliers d'années";
    return round($years) . " années";
}

// Checks individuels
$checks = [
    'lowercase'  => (bool) preg_match('/[a-z]/', $password),
    'uppercase'  => (bool) preg_match('/[A-Z]/', $password),
    'numbers'    => (bool) preg_match('/[0-9]/', $password),
    'symbols'    => (bool) preg_match('/[^a-zA-Z0-9]/', $password),
    'length12'   => strlen($password) >= 12,
    'length16'   => strlen($password) >= 16,
    'noRepeats'  => !preg_match('/(.)\1{2,}/', $password),
    'noCommon'   => !preg_match('/^(123|abc|qwerty|password|azerty|admin|welcome|letmein)/i', $password),
];

// --- Réponse ---
echo json_encode([
    'success'    => true,
    'score'      => $result['score'],
    'strength'   => $result['strength'],
    'feedback'   => $result['feedback'],
    'entropy'    => $entropy,
    'crack_time' => estimate_crack_time_local($entropy),
    'length'     => strlen($password),
    'checks'     => $checks,
]);
