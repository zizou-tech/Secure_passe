<?php
session_start();
header('Content-Type: application/json');

// --- DÉPENDANCES ET CONFIGURATION ---
require_once '../includes/crypto.php'; // Assurez-vous que le chemin vers crypto.php est correct

define('DB_HOST', 'localhost');
define('DB_NAME', 'SecurePass_db');
define('DB_USER', 'root');
define('DB_PASS', '');

// --- SÉCURITÉ ET VALIDATION ---
if (!isset($_SESSION['user_id'])) {
    echo json_encode(['success' => false, 'message' => 'Accès non autorisé.']);
    exit();
}
if (!isset($_GET['id']) || !is_numeric($_GET['id'])) {
    echo json_encode(['success' => false, 'message' => 'Identifiant manquant ou invalide.']);
    exit();
}

$user_id = $_SESSION['user_id'];
$password_id = (int)$_GET['id'];
$response = ['success' => false, 'message' => 'Erreur inconnue.'];

try {
    $pdo = new PDO("mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=utf8", DB_USER, DB_PASS);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    // Récupérer le mot de passe chiffré
    $stmt = $pdo->prepare(
        "SELECT password_encrypted FROM saved_passwords WHERE id = ? AND user_id = ?"
    );
    $stmt->execute([$password_id, $user_id]);
    $result = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($result) {
        $encrypted_password_hex = $result['password_encrypted'];
        
        // Clé de déchiffrement (DOIT être la même que celle utilisée pour le chiffrement)
        // Idéalement, cette clé est dérivée du mot de passe maître de l'utilisateur.
        // Pour cet exemple, nous utilisons une clé statique.
        // AVERTISSEMENT : NE PAS UTILISER DE CLÉ STATIQUE EN PRODUCTION.
        $decryption_key = 'votre-cle-secrete-de-32-octets-ici'; // REMPLACEZ PAR VOTRE VRAIE CLÉ

        $aes = new AES256Encryption();
        $decrypted_password = $aes->decrypt($encrypted_password_hex, $decryption_key);

        if ($decrypted_password !== false) {
            $response = ['success' => true, 'password' => $decrypted_password];
        } else {
            $response['message'] = 'Échec du déchiffrement. La clé est peut-être incorrecte.';
        }
    } else {
        $response['message'] = 'Mot de passe non trouvé ou accès non autorisé.';
    }

} catch (PDOException $e) {
    error_log("API Error: " . $e->getMessage());
    $response['message'] = 'Erreur de base de données.';
} catch (Exception $e) {
    error_log("Decryption Error: " . $e->getMessage());
    $response['message'] = 'Erreur de déchiffrement.';
}

echo json_encode($response);
?>