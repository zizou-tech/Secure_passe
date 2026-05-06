<?php
/**
 * SecurePass — api/save_password.php
 * Actions : add | edit | delete
 * Body JSON attendu :
 *   add    → { action, master_password, site_name, site_url, username, email, password, notes, category }
 *   edit   → { action, id, master_password, site_name, site_url, username, email, password, notes, category }
 *   delete → { action, id }
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

// --- CSRF ---
$body = json_decode(file_get_contents('php://input'), true);
if (!$body) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'Corps de requête invalide.']);
    exit();
}

$csrf = $body['csrf_token'] ?? '';
if (empty($csrf) || empty($_SESSION['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $csrf)) {
    http_response_code(403);
    echo json_encode(['success' => false, 'message' => 'Token CSRF invalide.']);
    exit();
}

require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../includes/crypto.php';

$user_id = (int) $_SESSION['user_id'];
$action  = $body['action'] ?? '';
$aes     = new AES256Encryption();

// ============================================================
// ADD
// ============================================================
if ($action === 'add') {
    $master_password = $body['master_password'] ?? '';
    $site_name       = trim($body['site_name'] ?? '');
    $site_url        = trim($body['site_url'] ?? '');
    $username        = trim($body['username'] ?? '');
    $email           = trim($body['email'] ?? '');
    $password        = $body['password'] ?? '';
    $notes           = trim($body['notes'] ?? '');
    $category        = trim($body['category'] ?? 'Général');

    if (empty($master_password) || empty($site_name) || empty($password)) {
        echo json_encode(['success' => false, 'message' => 'Champs obligatoires manquants (site, mot de passe, mot de passe maître).']);
        exit();
    }

    // Vérifier le mot de passe maître
    $stmt = mysqli_prepare($link, "SELECT password_hash FROM users WHERE id = ?");
    mysqli_stmt_bind_param($stmt, 'i', $user_id);
    mysqli_stmt_execute($stmt);
    $res = mysqli_stmt_get_result($stmt);
    $user = mysqli_fetch_assoc($res);
    mysqli_stmt_close($stmt);

    if (!$user || !password_verify($master_password, $user['password_hash'])) {
        echo json_encode(['success' => false, 'message' => 'Mot de passe maître incorrect.']);
        exit();
    }

    // Chiffrer
    $encrypted = $aes->encrypt($password, $master_password);
    if ($encrypted === false) {
        echo json_encode(['success' => false, 'message' => 'Erreur de chiffrement.']);
        exit();
    }

    // Score de force
    $strength = $aes->evaluatePasswordStrength($password);
    $score    = max(0, (int) $strength['score']);

    $site_url = filter_var($site_url, FILTER_VALIDATE_URL) ? $site_url : '';
    $email    = filter_var($email, FILTER_VALIDATE_EMAIL) ? $email : '';

    $sql = "INSERT INTO saved_passwords (user_id, site_name, site_url, username, email, password_encrypted, notes, category, strength_score, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())";
    $stmt = mysqli_prepare($link, $sql);
    mysqli_stmt_bind_param($stmt, 'isssssssi',
        $user_id, $site_name, $site_url, $username, $email, $encrypted, $notes, $category, $score
    );

    if (mysqli_stmt_execute($stmt)) {
        $new_id = mysqli_insert_id($link);
        mysqli_stmt_close($stmt);
        echo json_encode([
            'success'  => true,
            'message'  => 'Mot de passe enregistré avec succès.',
            'id'       => $new_id,
            'strength' => $strength['strength'],
            'score'    => $score,
        ]);
    } else {
        mysqli_stmt_close($stmt);
        error_log("save_password INSERT: " . mysqli_error($link));
        echo json_encode(['success' => false, 'message' => 'Erreur lors de l\'enregistrement.']);
    }
    exit();
}

// ============================================================
// EDIT
// ============================================================
if ($action === 'edit') {
    $id              = (int) ($body['id'] ?? 0);
    $master_password = $body['master_password'] ?? '';
    $site_name       = trim($body['site_name'] ?? '');
    $site_url        = trim($body['site_url'] ?? '');
    $username        = trim($body['username'] ?? '');
    $email           = trim($body['email'] ?? '');
    $password        = $body['password'] ?? '';
    $notes           = trim($body['notes'] ?? '');
    $category        = trim($body['category'] ?? 'Général');

    if (!$id || empty($site_name)) {
        echo json_encode(['success' => false, 'message' => 'Données invalides.']);
        exit();
    }

    // Vérifier que l'entrée appartient à l'utilisateur
    $stmt = mysqli_prepare($link, "SELECT id FROM saved_passwords WHERE id = ? AND user_id = ?");
    mysqli_stmt_bind_param($stmt, 'ii', $id, $user_id);
    mysqli_stmt_execute($stmt);
    mysqli_stmt_store_result($stmt);
    if (mysqli_stmt_num_rows($stmt) === 0) {
        mysqli_stmt_close($stmt);
        echo json_encode(['success' => false, 'message' => 'Entrée introuvable.']);
        exit();
    }
    mysqli_stmt_close($stmt);

    // Si un nouveau mot de passe est fourni, vérifier le mot de passe maître et rechiffrer
    $score     = null;
    $encrypted = null;
    if (!empty($password)) {
        if (empty($master_password)) {
            echo json_encode(['success' => false, 'message' => 'Le mot de passe maître est requis pour modifier le mot de passe.']);
            exit();
        }
        $stmt = mysqli_prepare($link, "SELECT password_hash FROM users WHERE id = ?");
        mysqli_stmt_bind_param($stmt, 'i', $user_id);
        mysqli_stmt_execute($stmt);
        $res  = mysqli_stmt_get_result($stmt);
        $user = mysqli_fetch_assoc($res);
        mysqli_stmt_close($stmt);

        if (!$user || !password_verify($master_password, $user['password_hash'])) {
            echo json_encode(['success' => false, 'message' => 'Mot de passe maître incorrect.']);
            exit();
        }
        $encrypted = $aes->encrypt($password, $master_password);
        $strength  = $aes->evaluatePasswordStrength($password);
        $score     = max(0, (int) $strength['score']);
    }

    $site_url = filter_var($site_url, FILTER_VALIDATE_URL) ? $site_url : '';
    $email    = filter_var($email, FILTER_VALIDATE_EMAIL) ? $email : '';

    if ($encrypted !== null) {
        $sql  = "UPDATE saved_passwords SET site_name=?, site_url=?, username=?, email=?, password_encrypted=?, notes=?, category=?, strength_score=?, updated_at=NOW() WHERE id=? AND user_id=?";
        $stmt = mysqli_prepare($link, $sql);
        mysqli_stmt_bind_param($stmt, 'sssssssiii', $site_name, $site_url, $username, $email, $encrypted, $notes, $category, $score, $id, $user_id);
    } else {
        $sql  = "UPDATE saved_passwords SET site_name=?, site_url=?, username=?, email=?, notes=?, category=?, updated_at=NOW() WHERE id=? AND user_id=?";
        $stmt = mysqli_prepare($link, $sql);
        mysqli_stmt_bind_param($stmt, 'ssssssii', $site_name, $site_url, $username, $email, $notes, $category, $id, $user_id);
    }

    if (mysqli_stmt_execute($stmt)) {
        mysqli_stmt_close($stmt);
        echo json_encode(['success' => true, 'message' => 'Entrée mise à jour avec succès.']);
    } else {
        mysqli_stmt_close($stmt);
        echo json_encode(['success' => false, 'message' => 'Erreur lors de la mise à jour.']);
    }
    exit();
}

// ============================================================
// DELETE
// ============================================================
if ($action === 'delete') {
    $id = (int) ($body['id'] ?? 0);
    if (!$id) {
        echo json_encode(['success' => false, 'message' => 'ID manquant.']);
        exit();
    }
    $stmt = mysqli_prepare($link, "DELETE FROM saved_passwords WHERE id = ? AND user_id = ?");
    mysqli_stmt_bind_param($stmt, 'ii', $id, $user_id);
    if (mysqli_stmt_execute($stmt) && mysqli_stmt_affected_rows($stmt) > 0) {
        mysqli_stmt_close($stmt);
        echo json_encode(['success' => true, 'message' => 'Entrée supprimée.']);
    } else {
        mysqli_stmt_close($stmt);
        echo json_encode(['success' => false, 'message' => 'Entrée introuvable ou déjà supprimée.']);
    }
    exit();
}

http_response_code(400);
echo json_encode(['success' => false, 'message' => 'Action inconnue.']);
