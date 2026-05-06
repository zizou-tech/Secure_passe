<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

session_start();
// Inclure le fichier de configuration de la base de données
require_once __DIR__ . '/../config/database.php'; // Changé de db.php à database.php

// Fonction de validation CSRF (très important pour la sécurité)
function generate_csrf_token() {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function validate_csrf_token($token) {
    if (empty($token) || empty($_SESSION['csrf_token']) || $token !== $_SESSION['csrf_token']) {
        return false;
    }
    return true;
}

// Vérifier l'action demandée
if (isset($_POST['action'])) {
    $action = $_POST['action'];

    // Validation CSRF pour toutes les actions POST sensibles
    if (!validate_csrf_token($_POST['csrf_token'] ?? '')) {
        $_SESSION['error_message'] = "Erreur de sécurité : Jeton CSRF invalide. Veuillez réessayer.";
        $redirect_page = 'login.php';
        if ($action === 'register') {
            $redirect_page = 'register.php';
        }
        header('Location: ../pages/' . $redirect_page);
        exit();
    }

    switch ($action) {
        case 'register':
            handle_registration();
            break;
        case 'login':
            handle_login();
            break;
        case 'forgot_password':
            handle_forgot_password();
            break;
        case 'reset_password':
            handle_reset_password();
            break;
        default:
            $_SESSION['error_message'] = "Action non reconnue.";
            header('Location: ../pages/login.php');
            exit();
    }
} elseif (isset($_GET['action']) && $_GET['action'] === 'logout') {
    handle_logout();
} else {
    $_SESSION['error_message'] = "Aucune action spécifiée.";
    header('Location: ../pages/login.php');
    exit();
}

// Gérer l'enregistrement de l'utilisateur
function handle_registration() {
    global $link; // Utiliser la variable globale de connexion
    
    // Nettoyage et validation des entrées
    $first_name = trim($_POST['firstName'] ?? '');
    $last_name = trim($_POST['lastName'] ?? '');
    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';
    $confirm_password = $_POST['confirmPassword'] ?? '';
    $terms = isset($_POST['terms']);

    // Validation des champs obligatoires
    if (empty($first_name) || empty($last_name) || empty($email) || empty($password) || empty($confirm_password) || !$terms) {
        $_SESSION['error_message'] = "Tous les champs sont obligatoires et vous devez accepter les conditions d'utilisation.";
        header('Location: ../pages/register.php');
        exit();
    }

    // Validation du format email
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $_SESSION['error_message'] = "Format d'email invalide.";
        header('Location: ../pages/register.php');
        exit();
    }

    // Validation des noms (lettres, espaces, tirets, apostrophes seulement)
    if (!preg_match('/^[a-zA-ZÀ-ÿ\s\-\']{2,100}$/', $first_name)) {
        $_SESSION['error_message'] = "Le prénom doit contenir uniquement des lettres, espaces, tirets ou apostrophes (2-100 caractères).";
        header('Location: ../pages/register.php');
        exit();
    }

    if (!preg_match('/^[a-zA-ZÀ-ÿ\s\-\']{2,100}$/', $last_name)) {
        $_SESSION['error_message'] = "Le nom doit contenir uniquement des lettres, espaces, tirets ou apostrophes (2-100 caractères).";
        header('Location: ../pages/register.php');
        exit();
    }

    // Validation de la robustesse du mot de passe
    if (strlen($password) < 12 ||
        !preg_match('/[A-Z]/', $password) ||
        !preg_match('/[a-z]/', $password) ||
        !preg_match('/\d/', $password) ||
        !preg_match('/[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]/', $password)) {
        $_SESSION['error_message'] = "Le mot de passe maître doit contenir au moins 12 caractères, inclure des majuscules, minuscules, chiffres et caractères spéciaux.";
        header('Location: ../pages/register.php');
        exit();
    }

    if ($password !== $confirm_password) {
        $_SESSION['error_message'] = "Les mots de passe ne correspondent pas.";
        header('Location: ../pages/register.php');
        exit();
    }

    // Vérifier si l'email existe déjà
    $sql = "SELECT id FROM users WHERE email = ?";
    if ($stmt = mysqli_prepare($link, $sql)) {
        mysqli_stmt_bind_param($stmt, "s", $email);
        
        if (mysqli_stmt_execute($stmt)) {
            mysqli_stmt_store_result($stmt);
            if (mysqli_stmt_num_rows($stmt) > 0) {
                $_SESSION['error_message'] = "Cet email est déjà utilisé.";
                mysqli_stmt_close($stmt);
                header('Location: ../pages/register.php');
                exit();
            }
        } else {
            $_SESSION['error_message'] = "Erreur lors de la vérification de l'email.";
            error_log("MySQL Error (email check): " . mysqli_error($link));
            mysqli_stmt_close($stmt);
            header('Location: ../pages/register.php');
            exit();
        }
        mysqli_stmt_close($stmt);
    } else {
        $_SESSION['error_message'] = "Erreur de préparation de la requête.";
        error_log("MySQL Prepare Error: " . mysqli_error($link));
        header('Location: ../pages/register.php');
        exit();
    }

    // Hachage du mot de passe
    $password_hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);

    // Insertion de l'utilisateur dans la base de données - CORRIGÉ
    $sql = "INSERT INTO users (prenom, nom, email, password_hash, created_at) VALUES (?, ?, ?, ?, NOW())";
    if ($stmt = mysqli_prepare($link, $sql)) {
        mysqli_stmt_bind_param($stmt, "ssss", $first_name, $last_name, $email, $password_hash);

        if (mysqli_stmt_execute($stmt)) {
            $_SESSION['success_message'] = "Compte créé avec succès ! Vous pouvez maintenant vous connecter.";
            mysqli_stmt_close($stmt);
            header('Location: ../pages/login.php');
            exit();
        } else {
            $_SESSION['error_message'] = "Erreur lors de la création du compte. Veuillez réessayer.";
            error_log("MySQL Error (insert): " . mysqli_error($link));
            mysqli_stmt_close($stmt);
            header('Location: ../pages/register.php');
            exit();
        }
    } else {
        $_SESSION['error_message'] = "Erreur de préparation de la requête d'insertion.";
        error_log("MySQL Prepare Error (insert): " . mysqli_error($link));
        header('Location: ../pages/register.php');
        exit();
    }
}

// Gérer la connexion de l'utilisateur
function handle_login() {
    global $link; // Utiliser la variable globale de connexion
    
    // Gestion du rate limiting
    $ip_address = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $login_attempts_key = 'login_attempts_' . md5($ip_address); // Hash pour la sécurité
    $max_attempts = 5;
    $lockout_time = 900; // 15 minutes

    // Initialiser les tentatives si non définies
    if (!isset($_SESSION[$login_attempts_key])) {
        $_SESSION[$login_attempts_key] = ['count' => 0, 'time' => time()];
    }

    // Vérifier si l'utilisateur est temporairement bloqué
    if ($_SESSION[$login_attempts_key]['count'] >= $max_attempts && 
        (time() - $_SESSION[$login_attempts_key]['time'] < $lockout_time)) {
        $remaining_time = $lockout_time - (time() - $_SESSION[$login_attempts_key]['time']);
        $_SESSION['error_message'] = "Trop de tentatives de connexion. Veuillez réessayer dans " . ceil($remaining_time / 60) . " minutes.";
        header('Location: ../pages/login.php');
        exit();
    }

    // Reset le compteur si le temps de blocage est écoulé
    if ($_SESSION[$login_attempts_key]['count'] >= $max_attempts && 
        (time() - $_SESSION[$login_attempts_key]['time'] >= $lockout_time)) {
        $_SESSION[$login_attempts_key] = ['count' => 0, 'time' => time()];
    }

    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';

    if (empty($email) || empty($password)) {
        $_SESSION['error_message'] = "Veuillez entrer votre email et votre mot de passe.";
        header('Location: ../pages/login.php');
        exit();
    }

    // Récupérer l'utilisateur par email - CORRIGÉ
    $sql = "SELECT id, prenom, nom, email, password_hash FROM users WHERE email = ?";
    if ($stmt = mysqli_prepare($link, $sql)) {
        mysqli_stmt_bind_param($stmt, "s", $email);
        
        if (mysqli_stmt_execute($stmt)) {
            $result = mysqli_stmt_get_result($stmt);
            
            if ($user = mysqli_fetch_assoc($result)) {
                if (password_verify($password, $user['password_hash'])) {
                    // Connexion réussie
                    // Réinitialiser les tentatives de connexion
                    unset($_SESSION[$login_attempts_key]);

                    // Régénérer l'ID de session pour la sécurité
                    session_regenerate_id(true);

                    // Stocker les informations utilisateur en session - CORRIGÉ
                    $_SESSION['user_id'] = $user['id'];
                    $_SESSION['username'] = $user['prenom'];
                    $_SESSION['user_email'] = $user['email'];
                    $_SESSION['user_full_name'] = $user['prenom'] . ' ' . $user['nom'];
                    $_SESSION['loggedin'] = true;
                    $_SESSION['login_time'] = time();

                    $_SESSION['success_message'] = "Connexion réussie ! Bienvenue, " . htmlspecialchars($user['prenom'], ENT_QUOTES, 'UTF-8') . ".";
                    
                    mysqli_stmt_close($stmt);
                    header('Location: ../pages/dashboard.php');
                    exit();
                } else {
                    // Mot de passe incorrect
                    $_SESSION[$login_attempts_key]['count']++;
                    $_SESSION[$login_attempts_key]['time'] = time();
                    $_SESSION['error_message'] = "Email ou mot de passe incorrect.";
                }
            } else {
                // Aucun compte trouvé
                $_SESSION[$login_attempts_key]['count']++;
                $_SESSION[$login_attempts_key]['time'] = time();
                $_SESSION['error_message'] = "Email ou mot de passe incorrect.";
            }
        } else {
            $_SESSION['error_message'] = "Erreur lors de la connexion.";
            error_log("MySQL Error (login): " . mysqli_error($link));
        }
        mysqli_stmt_close($stmt);
    } else {
        $_SESSION['error_message'] = "Erreur de préparation de la requête de connexion.";
        error_log("MySQL Prepare Error (login): " . mysqli_error($link));
    }
    
    header('Location: ../pages/login.php');
    exit();
}

// Gérer la déconnexion de l'utilisateur
function handle_logout() {
    // Détruire toutes les variables de session
    $_SESSION = array();
    
    // Supprimer le cookie de session si il existe
    if (ini_get("session.use_cookies")) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000,
            $params["path"], $params["domain"],
            $params["secure"], $params["httponly"]
        );
    }
    
    // Détruire la session
    session_destroy();
    
    // Démarrer une nouvelle session pour le message de succès
    session_start();
    $_SESSION['success_message'] = "Vous avez été déconnecté avec succès.";
    
    header('Location: ../pages/login.php');
    exit();
}
?>
// ============================================================
// MOT DE PASSE OUBLIÉ — Gestion dans le switch
// ============================================================
// (Ajoutez 'forgot_password' et 'reset_password' au switch existant)
// Ces fonctions sont appelées directement ci-dessous.

function handle_forgot_password() {
    global $link;

    $email = trim($_POST['email'] ?? '');

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $_SESSION['error_message'] = "Adresse email invalide.";
        header('Location: ../pages/forgot_password.php'); exit();
    }

    // Rate limiting
    $rl_key = 'reset_attempts_' . md5($_SERVER['REMOTE_ADDR'] ?? '');
    if (!isset($_SESSION[$rl_key])) $_SESSION[$rl_key] = ['count'=>0,'time'=>time()];
    if (time() - $_SESSION[$rl_key]['time'] > 3600) $_SESSION[$rl_key] = ['count'=>0,'time'=>time()];
    if ($_SESSION[$rl_key]['count'] >= 3) {
        $_SESSION['error_message'] = "Trop de demandes. Réessayez dans 1 heure.";
        header('Location: ../pages/forgot_password.php'); exit();
    }
    $_SESSION[$rl_key]['count']++;

    // Chercher l'utilisateur (réponse identique que l'email existe ou non = anti-enumeration)
    $stmt = mysqli_prepare($link, "SELECT id, prenom FROM users WHERE email = ?");
    mysqli_stmt_bind_param($stmt, 's', $email);
    mysqli_stmt_execute($stmt);
    $res  = mysqli_stmt_get_result($stmt);
    $user = mysqli_fetch_assoc($res);
    mysqli_stmt_close($stmt);

    if ($user) {
        // Générer un token sécurisé
        $token      = bin2hex(random_bytes(32)); // 64 chars hex
        $token_hash = hash('sha256', $token);    // On stocke le hash
        $expires    = date('Y-m-d H:i:s', time() + 3600); // 1 heure

        $stmt2 = mysqli_prepare($link,
            "UPDATE users SET reset_token=?, reset_token_expires=? WHERE id=?");
        mysqli_stmt_bind_param($stmt2, 'ssi', $token_hash, $expires, $user['id']);
        mysqli_stmt_execute($stmt2);
        mysqli_stmt_close($stmt2);

        // Construire le lien
        $scheme   = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
        $host     = $_SERVER['HTTP_HOST'] ?? 'localhost';
        $base     = dirname(dirname($_SERVER['PHP_SELF']));
        $reset_link = "{$scheme}://{$host}{$base}/pages/reset_password.php?token={$token}&email=" . urlencode($email);

        $to      = $email;
        $subject = "Réinitialisation de votre mot de passe SecurePass";
        $prenom  = htmlspecialchars($user['prenom']);

        $body = "Bonjour {$prenom},\n\n"
              . "Vous avez demandé la réinitialisation de votre mot de passe SecurePass.\n\n"
              . "Cliquez sur le lien ci-dessous pour définir un nouveau mot de passe :\n"
              . $reset_link . "\n\n"
              . "Ce lien est valable pendant 1 heure.\n"
              . "Si vous n'avez pas effectué cette demande, ignorez cet email.\n\n"
              . "L'équipe SecurePass";

        $html_body = "
            <div style='font-family:Inter,sans-serif;max-width:560px;margin:0 auto;padding:2rem;'>
              <div style='text-align:center;margin-bottom:2rem'>
                <span style='font-size:1.5rem;font-weight:800;color:#667eea'>🔐 SecurePass</span>
              </div>
              <div style='background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:2rem;'>
                <h2 style='color:#2d3748;margin-bottom:1rem'>Réinitialisation de mot de passe</h2>
                <p style='color:#718096;margin-bottom:1rem'>Bonjour <strong>{$prenom}</strong>,</p>
                <p style='color:#718096;margin-bottom:1.5rem'>
                  Vous avez demandé la réinitialisation de votre mot de passe SecurePass.
                </p>
                <div style='text-align:center;margin:2rem 0'>
                  <a href='" . htmlspecialchars($reset_link) . "'
                     style='display:inline-block;background:linear-gradient(135deg,#667eea,#764ba2);
                            color:#fff;padding:1rem 2rem;border-radius:8px;text-decoration:none;
                            font-weight:700;font-size:1rem;'>
                    Réinitialiser mon mot de passe
                  </a>
                </div>
                <p style='color:#718096;font-size:.85rem;margin-top:1.5rem'>
                  ⏰ Ce lien expire dans <strong>1 heure</strong>.<br>
                  Si vous n'avez pas effectué cette demande, ignorez cet email.<br><br>
                  Lien direct : <a href='" . htmlspecialchars($reset_link) . "' style='color:#667eea;word-break:break-all'>{$reset_link}</a>
                </p>
              </div>
              <p style='text-align:center;color:#a0aec0;font-size:.8rem;margin-top:1rem'>
                © SecurePass — Gestionnaire de mots de passe sécurisé
              </p>
            </div>";

        $headers  = "MIME-Version: 1.0\r\n";
        $headers .= "Content-Type: text/html; charset=UTF-8\r\n";
        $headers .= "From: SecurePass <noreply@securepass.local>\r\n";
        $headers .= "Reply-To: noreply@securepass.local\r\n";
        $headers .= "X-Mailer: SecurePass/1.0\r\n";

        @mail($to, $subject, $html_body, $headers);
        // On ne log pas si mail() échoue pour éviter l'enumeration,
        // mais en dev on peut loguer : error_log("Reset link: $reset_link");
    }

    // Même réponse qu'il y ait un compte ou non
    $_SESSION['email_sent'] = true;
    $_SESSION['success_message'] = "Si cet email est enregistré, vous recevrez un lien de réinitialisation.";
    header('Location: ../pages/forgot_password.php'); exit();
}

function handle_reset_password() {
    global $link;

    $token    = $_POST['token'] ?? '';
    $email    = trim($_POST['email'] ?? '');
    $new_pw   = $_POST['new_password'] ?? '';
    $conf_pw  = $_POST['confirm_password'] ?? '';

    if (empty($token) || empty($email) || empty($new_pw)) {
        $_SESSION['error_message'] = "Données manquantes.";
        header("Location: ../pages/reset_password.php?token={$token}&email=" . urlencode($email));
        exit();
    }

    if ($new_pw !== $conf_pw) {
        $_SESSION['error_message'] = "Les mots de passe ne correspondent pas.";
        header("Location: ../pages/reset_password.php?token={$token}&email=" . urlencode($email));
        exit();
    }

    if (strlen($new_pw) < 12 ||
        !preg_match('/[A-Z]/', $new_pw) || !preg_match('/[a-z]/', $new_pw) ||
        !preg_match('/\d/', $new_pw)    || !preg_match('/[^a-zA-Z0-9]/', $new_pw)) {
        $_SESSION['error_message'] = "Le mot de passe doit contenir au moins 12 caractères, une majuscule, un chiffre et un caractère spécial.";
        header("Location: ../pages/reset_password.php?token={$token}&email=" . urlencode($email));
        exit();
    }

    $token_hash = hash('sha256', $token);
    $stmt = mysqli_prepare($link,
        "SELECT id FROM users WHERE email = ? AND reset_token = ? AND reset_token_expires > NOW()");
    mysqli_stmt_bind_param($stmt, 'ss', $email, $token_hash);
    mysqli_stmt_execute($stmt);
    mysqli_stmt_store_result($stmt);

    if (mysqli_stmt_num_rows($stmt) === 0) {
        mysqli_stmt_close($stmt);
        $_SESSION['error_message'] = "Lien invalide ou expiré. Faites une nouvelle demande.";
        header('Location: ../pages/forgot_password.php'); exit();
    }
    mysqli_stmt_bind_result($stmt, $uid);
    mysqli_stmt_fetch($stmt);
    mysqli_stmt_close($stmt);

    $new_hash = password_hash($new_pw, PASSWORD_BCRYPT, ['cost' => 12]);
    $stmt2 = mysqli_prepare($link,
        "UPDATE users SET password_hash=?, reset_token=NULL, reset_token_expires=NULL, updated_at=NOW() WHERE id=?");
    mysqli_stmt_bind_param($stmt2, 'si', $new_hash, $uid);
    mysqli_stmt_execute($stmt2);
    mysqli_stmt_close($stmt2);

    $_SESSION['success_message'] = "Mot de passe réinitialisé avec succès ! Vous pouvez maintenant vous connecter.";
    header('Location: ../pages/login.php'); exit();
}
