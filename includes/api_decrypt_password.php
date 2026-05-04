<?php
session_start();
header('Content-Type: application/json');

// Log des erreurs pour debugging
error_reporting(E_ALL);
ini_set('display_errors', 0); // Ne pas afficher les erreurs dans la réponse JSON
ini_set('log_errors', 1);

// 1. INCLUSIONS - Vérifiez les chemins selon votre structure
try {
    require_once __DIR__ . '/../config/database.php'; 
    
    // Ajustez ce chemin selon l'emplacement de votre fichier crypto.php
    // Si crypto.php est dans le même dossier que ce fichier :
    require_once __DIR__ . '/../includes/crypto.php';
    
    // Si crypto.php est dans le dossier parent :
    // require_once __DIR__ . '/../crypto.php';
    
    // Si crypto.php est dans un dossier spécifique :
    // require_once __DIR__ . '/../includes/crypto.php';
    
} catch (Exception $e) {
    error_log("Erreur d'inclusion: " . $e->getMessage());
    echo json_encode(['success' => false, 'error' => 'Erreur de configuration du serveur.']);
    exit();
}

// 2. SÉCURITÉ : VÉRIFICATION DE LA SESSION
if (!isset($_SESSION['user_id']) || !$_SESSION['user_id']) {
    echo json_encode(['success' => false, 'error' => 'Accès non autorisé. Session expirée.']);
    exit();
}

$user_id = $_SESSION['user_id'];
$response = ['success' => false];

// 3. VÉRIFICATION DES DONNÉES REÇUES
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $password_id = $_POST['password_id'] ?? null;
    $master_password = trim($_POST['master_password'] ?? '');

    // Log pour debugging
    error_log("Tentative de déchiffrement - User ID: $user_id, Password ID: $password_id");

    if (empty($password_id) || empty($master_password)) {
        $response['error'] = 'Informations manquantes.';
        echo json_encode($response);
        exit();
    }

    // 4. VÉRIFICATION DE LA CONNEXION DB
    if (!isset($link) || !$link) {
        error_log("Connexion DB non disponible");
        $response['error'] = 'Erreur de base de données.';
        echo json_encode($response);
        exit();
    }

    // 5. RÉCUPÉRATION DU MOT DE PASSE CHIFFRÉ
    $sql = "SELECT password_encrypted FROM saved_passwords WHERE id = ? AND user_id = ?";
    $stmt = mysqli_prepare($link, $sql);
    
    if ($stmt) {
        mysqli_stmt_bind_param($stmt, "ii", $password_id, $user_id);
        mysqli_stmt_execute($stmt);
        $result = mysqli_stmt_get_result($stmt);
        $row = mysqli_fetch_assoc($result);
        mysqli_stmt_close($stmt);

        if ($row) {
            $encrypted_password = $row['password_encrypted'];
            error_log("Mot de passe récupéré, tentative de déchiffrement");

            // 6. VÉRIFICATION DE LA CLASSE DE CHIFFREMENT
            if (!class_exists('AES256Encryption')) {
                error_log("Classe AES256Encryption non trouvée");
                $response['error'] = 'Erreur de configuration du chiffrement.';
                echo json_encode($response);
                exit();
            }

            // 7. DÉCHIFFREMENT
            try {
                $aes = new AES256Encryption();
                $decrypted_password = $aes->decrypt($encrypted_password, $master_password);

                if ($decrypted_password !== false && $decrypted_password !== null) {
                    $response['success'] = true;
                    $response['password'] = $decrypted_password;
                    error_log("Déchiffrement réussi pour l'utilisateur $user_id");
                } else {
                    $response['error'] = 'Mot de passe maître incorrect ou données corrompues.';
                    error_log("Échec du déchiffrement pour l'utilisateur $user_id");
                }
            } catch (Exception $e) {
                error_log("Erreur de déchiffrement: " . $e->getMessage());
                $response['error'] = 'Erreur lors du déchiffrement.';
            }
        } else {
            $response['error'] = 'Identifiant non trouvé ou non autorisé.';
            error_log("Aucun mot de passe trouvé pour ID: $password_id, User: $user_id");
        }
    } else {
        error_log("Erreur de préparation de la requête: " . mysqli_error($link));
        $response['error'] = 'Erreur de base de données.';
    }
} else {
    $response['error'] = 'Méthode non autorisée.';
}

// 8. ENVOI DE LA RÉPONSE JSON
echo json_encode($response);
exit();
?>