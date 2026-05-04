<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);
session_start();

// Headers de sécurité conformes au cahier des charges
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('X-XSS-Protection: 1; mode=block');
header('Referrer-Policy: strict-origin-when-cross-origin');
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; font-src 'self' https://cdnjs.cloudflare.com; img-src 'self' data:;");

// Redirection si déjà connecté
if (isset($_SESSION['user_id']) && $_SESSION['user_id']) {
    header('Location: dashboard.php'); // Rediriger vers le tableau de bord
    exit();
}

// Génération du token CSRF
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Gestion des messages d'erreur/succès
$error_message = '';
$success_message = '';

if (isset($_SESSION['error_message'])) {
    $error_message = $_SESSION['error_message'];
    unset($_SESSION['error_message']);
}

if (isset($_SESSION['success_message'])) {
    $success_message = $_SESSION['success_message'];
    unset($_SESSION['success_message']);
}

// Vérification du rate limiting (tentatives de connexion) - Simple exemple basé sur la session
$login_attempts_key = 'login_attempts_' . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'); // Utilisation de l'IP pour un suivi plus global
$lockout_time = 900; // 15 minutes
$max_attempts = 5;

// Récupérer les tentatives et le dernier temps de tentative depuis la session
$login_attempts = $_SESSION[$login_attempts_key]['count'] ?? 0;
$last_attempt_time = $_SESSION[$login_attempts_key]['time'] ?? 0;

$locked_out = false;
if ($login_attempts >= $max_attempts && (time() - $last_attempt_time < $lockout_time)) {
    $locked_out = true;
    $remaining_time = $lockout_time - (time() - $last_attempt_time);
    $error_message = "Trop de tentatives de connexion. Veuillez réessayer dans " . ceil($remaining_time / 60) . " minutes.";
}

?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="Connectez-vous à SecurePass - Votre gestionnaire de mots de passe sécurisé.">
    <title>Connexion - SecurePass</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        /* Variables CSS pour le thème */
        :root {
            --primary-color: #667eea;
            --primary-dark: #764ba2;
            --success-color: #48bb78;
            --error-color: #f56565;
            --text-primary: #2d3748;
            --text-secondary: #718096;
            --bg-light: #f7fafc;
            --bg-white: #ffffff;
            --border-color: #e2e8f0;
            --border-focus: #667eea;
            --shadow-sm: 0 1px 3px rgba(0, 0, 0, 0.1);
            --shadow-lg: 0 25px 50px rgba(0, 0, 0, 0.2);
            --radius: 10px;
            --radius-lg: 20px;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: var(--text-primary);
            background: linear-gradient(135deg, var(--primary-color) 0%, var(--primary-dark) 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 1rem;
        }

        .auth-container {
            display: grid;
            grid-template-columns: 1fr 1fr;
            max-width: 850px;
            width: 100%;
            background: var(--bg-white);
            border-radius: var(--radius-lg);
            overflow: hidden;
            box-shadow: var(--shadow-lg);
        }

        .auth-form-section {
            padding: 2.5rem;
            display: flex;
            flex-direction: column;
            justify-content: center;
        }

        .auth-header {
            text-align: center;
            margin-bottom: 2rem;
        }

        .brand-logo {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 0.75rem;
            font-size: 1.5rem;
            font-weight: 700;
            color: var(--primary-color);
            margin-bottom: 1rem;
        }

        .auth-header h1 {
            font-size: 2rem;
            font-weight: 800;
            color: var(--text-primary);
            margin-bottom: 0.5rem;
        }

        .auth-header p {
            color: var(--text-secondary);
            font-size: 1rem;
        }

        .form-group {
            margin-bottom: 1.5rem;
        }

        label {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            font-weight: 600;
            color: var(--text-primary);
            margin-bottom: 0.75rem;
            font-size: 0.95rem;
        }

        input {
            width: 100%;
            padding: 1rem;
            border: 2px solid var(--border-color);
            border-radius: var(--radius);
            font-size: 1rem;
            transition: all 0.3s ease;
            background: var(--bg-white); /* Assurez-vous que le fond est blanc ici */
            color: var(--text-primary); /* Assurez-vous que le texte est lisible */
            font-family: inherit;
        }

        input:focus {
            outline: none;
            border-color: var(--border-focus);
            background: var(--bg-white);
            box-shadow: 0 0 0 3px rgba(102,126,234,0.1);
        }

        .password-input {
            position: relative;
        }

        .toggle-password {
            position: absolute;
            right: 1rem;
            top: 50%;
            transform: translateY(-50%);
            background: none;
            border: none;
            color: var(--text-secondary);
            cursor: pointer;
            font-size: 1rem;
            padding: 0.5rem;
            border-radius: 0.25rem;
            transition: color 0.2s ease;
        }

        .toggle-password:hover {
            color: var(--primary-color);
        }

        .form-options {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1.5rem;
            font-size: 0.9rem;
        }

        .checkbox-container {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            color: var(--text-primary);
            user-select: none;
            cursor: pointer;
        }

        .checkbox-container input[type="checkbox"] {
            width: auto;
            height: auto;
            margin: 0;
        }

        .forgot-password {
            color: var(--primary-color);
            text-decoration: none;
            font-weight: 600;
            transition: color 0.2s ease;
        }

        .forgot-password:hover {
            color: var(--primary-dark);
            text-decoration: underline;
        }

        .btn {
            padding: 1rem 1.5rem;
            border-radius: var(--radius);
            border: none;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 0.75rem;
            text-decoration: none;
            font-family: inherit;
            font-size: 1rem;
            position: relative;
        }

        .btn-primary {
            background: linear-gradient(45deg, var(--primary-color), var(--primary-dark));
            color: white;
            box-shadow: 0 4px 15px rgba(102,126,234,0.4);
        }

        .btn-primary:hover:not(:disabled) {
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(102,126,234,0.6);
        }

        .btn-primary:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
            box-shadow: 0 4px 15px rgba(102,126,234,0.2);
        }

        .auth-footer {
            text-align: center;
            margin-top: 2rem;
            color: var(--text-secondary);
        }

        .auth-footer p {
            margin-bottom: 0.5rem;
        }

        .auth-footer a {
            color: var(--primary-color);
            text-decoration: none;
            font-weight: 600;
            transition: color 0.2s ease;
        }

        .auth-footer a:hover {
            color: var(--primary-dark);
            text-decoration: underline;
        }

        .security-indicator-section {
            background: linear-gradient(135deg, var(--primary-color) 0%, var(--primary-dark) 100%);
            padding: 2.5rem;
            color: white;
            display: flex;
            flex-direction: column;
            justify-content: center;
            gap: 1.5rem;
        }

        .security-feature {
            background: rgba(255,255,255,0.1);
            padding: 1.5rem;
            border-radius: var(--radius);
        }

        .security-feature h3 {
            margin-bottom: 0.5rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .security-feature h3 i {
            color: #feca57;
        }

        .alert {
            padding: 1rem;
            border-radius: var(--radius);
            margin-bottom: 1.5rem;
            display: flex;
            align-items: center;
            gap: 0.75rem;
            font-weight: 500;
            transition: opacity 0.3s ease;
            /* display: none; */ /* Gérer la visibilité via JS/PHP directement */
        }
        .alert.hidden { /* Classe pour cacher via JS */
            display: none;
        }

        .alert-error {
            background: #fed7d7;
            color: #c53030;
            border: 1px solid #feb2b2;
        }

        .alert-success {
            background: #c6f6d5;
            color: #2f855a;
            border: 1px solid #9ae6b4;
        }

        .spinner {
            display: none;
            width: 20px;
            height: 20px;
            border: 2px solid rgba(255, 255, 255, 0.3);
            border-top: 2px solid white;
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        /* Responsive Design */
        @media (max-width: 768px) {
            .auth-container {
                grid-template-columns: 1fr;
            }
            .security-indicator-section {
                display: none;
            }
            .auth-form-section {
                padding: 2rem 1.5rem;
            }
            .auth-header h1 {
                font-size: 1.75rem;
            }
        }

        @media (max-width: 480px) {
            .brand-logo {
                font-size: 1.25rem;
            }
            .auth-header h1 {
                font-size: 1.5rem;
            }
        }

        /* Mode sombre (optionnel) */
        @media (prefers-color-scheme: dark) {
            :root {
                --text-primary: #f7fafc;
                --text-secondary: #a0aec0;
                --bg-light: #2d3748;
                --bg-white: #1a202c;
                --border-color: #4a5568;
            }
            .auth-container {
                background: var(--bg-white);
            }
            .security-indicator-section {
                background: linear-gradient(135deg, #2d3748 0%, #4a5568 100%);
            }
             input {
                background: var(--bg-light); /* En mode sombre, les inputs peuvent être plus sombres */
                color: var(--text-primary);
            }
            input:focus {
                background: var(--bg-light);
            }
        }

        /* Améliorations d'accessibilité */
        .btn:focus-visible,
        input:focus-visible {
            outline: 2px solid var(--primary-color);
            outline-offset: 2px;
        }

        /* Animation d'entrée */
        .auth-container {
            animation: slideInUp 0.6s ease-out;
        }

        @keyframes slideInUp {
            from {
                opacity: 0;
                transform: translateY(30px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
    </style>
</head>
<body>
    <div class="auth-container">
        <div class="auth-form-section">
            <div class="auth-header">
                <div class="brand-logo">
                    <i class="fas fa-shield-alt"></i>
                    <span>SecurePass</span>
                </div>
                <h1>Connexion</h1>
                <p>Accédez à votre gestionnaire de mots de passe sécurisé.</p>
            </div>

            <?php if ($error_message): ?>
                <div class="alert alert-error" id="alert">
                    <i class="fas fa-exclamation-triangle"></i>
                    <span id="alertText"><?php echo htmlspecialchars($error_message, ENT_QUOTES, 'UTF-8'); ?></span>
                </div>
            <?php endif; ?>

            <?php if ($success_message): ?>
                <div class="alert alert-success" id="alert">
                    <i class="fas fa-check-circle"></i>
                    <span id="alertText"><?php echo htmlspecialchars($success_message, ENT_QUOTES, 'UTF-8'); ?></span>
                </div>
            <?php endif; ?>

            <form id="loginForm" method="POST" action="../includes/auth.php">
                <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                <input type="hidden" name="action" value="login">

                <div class="form-group">
                    <label for="email"><i class="fas fa-envelope"></i> Email</label>
                    <input type="email" id="email" name="email" required placeholder="votre@email.com" autocomplete="email">
                </div>

                <div class="form-group">
                    <label for="password"><i class="fas fa-lock"></i> Mot de passe maître</label>
                    <div class="password-input">
                        <input type="password" id="password" name="password" required placeholder="Votre mot de passe maître" autocomplete="current-password">
                        <button type="button" class="toggle-password" onclick="togglePassword()">
                            <i class="fas fa-eye"></i>
                        </button>
                    </div>
                </div>

                <div class="form-options">
                    <div class="checkbox-container">
                        <input type="checkbox" id="rememberMe" name="rememberMe">
                        <label for="rememberMe">Se souvenir de moi</label>
                    </div>
                    <a href="forgot_password.php" class="forgot-password">Mot de passe oublié ?</a>
                </div>

                <button type="submit" class="btn btn-primary" id="submitBtn" <?php echo $locked_out ? 'disabled' : ''; ?>>
                    <span class="spinner" id="spinner"></span>
                    <i class="fas fa-sign-in-alt" id="submitIcon"></i>
                    <span id="submitText">Se connecter</span>
                </button>
            </form>

            <div class="auth-footer">
                <p>Nouveau sur SecurePass ? <a href="register.php">Créer un compte</a></p>
                <p class="legal-links">
                    <a href="../legal/privacy.php">Politique de confidentialité</a> •
                    <a href="../legal/terms.php">Conditions d'utilisation</a>
                </p>
            </div>
        </div>

        <div class="security-indicator-section">
            <div class="security-feature">
                <h3><i class="fas fa-shield-alt"></i> Sécurité Avancée</h3>
                <p>Protection de vos données avec des protocoles de chiffrement de pointe.</p>
            </div>
            <div class="security-feature">
                <h3><i class="fas fa-user-lock"></i> Authentification Forte</h3>
                <p>Système de connexion robuste pour une sécurité maximale de votre compte.</p>
            </div>
            <div class="security-feature">
                <h3><i class="fas fa-clock"></i> Accès Rapide</h3>
                <p>Connectez-vous rapidement et en toute sécurité à vos informations.</p>
            </div>
        </div>
    </div>

    <script>
        function togglePassword() {
            const passwordInput = document.getElementById('password');
            const toggleBtn = document.querySelector('.toggle-password i');
            if (passwordInput.type === 'password') {
                passwordInput.type = 'text';
                toggleBtn.classList.remove('fa-eye');
                toggleBtn.classList.add('fa-eye-slash');
            } else {
                passwordInput.type = 'password';
                toggleBtn.classList.remove('fa-eye-slash');
                toggleBtn.classList.add('fa-eye');
            }
        }

        function setLoadingState(isLoading) {
            const submitBtn = document.getElementById('submitBtn');
            const spinner = document.getElementById('spinner');
            const submitIcon = document.getElementById('submitIcon');
            const submitText = document.getElementById('submitText');

            if (isLoading) {
                submitBtn.disabled = true;
                spinner.style.display = 'block';
                submitIcon.style.display = 'none';
                submitText.textContent = 'Connexion en cours...';
            } else {
                submitBtn.disabled = false;
                spinner.style.display = 'none';
                submitIcon.style.display = 'inline';
                submitText.textContent = 'Se connecter';
            }
        }

        // Fonction pour afficher les messages d'alerte (succès/erreur)
        function showAlert(message, type = 'error') {
            const alertElement = document.getElementById('alert');
            const alertText = document.getElementById('alertText');
            
            alertText.textContent = message;
            alertElement.className = `alert alert-${type}`;
            alertElement.classList.remove('hidden');

            setTimeout(() => {
                alertElement.classList.add('hidden');
            }, 5000);
        }

        document.getElementById('loginForm').addEventListener('submit', function(e) {
            const email = document.getElementById('email').value.trim();
            const password = document.getElementById('password').value.trim();

            if (!email || !password) {
                showAlert('Veuillez entrer votre email et votre mot de passe.');
                e.preventDefault();
                return;
            }
            
            if (e.submitter.disabled) {
                e.preventDefault();
                return;
            }

            setLoadingState(true);
        });

        document.addEventListener('DOMContentLoaded', function() {
            const alertMessage = document.getElementById('alert');
            if (alertMessage && alertMessage.textContent.trim() !== '') {
                alertMessage.classList.remove('hidden');
                setTimeout(() => {
                    alertMessage.classList.add('hidden');
                }, 5000);
            } else if (alertMessage) {
                alertMessage.classList.add('hidden');
            }
            document.getElementById('email').focus();
        });

        window.addEventListener('beforeunload', function() {
            document.getElementById('password').value = '';
        });
    </script>
</body>
</html>