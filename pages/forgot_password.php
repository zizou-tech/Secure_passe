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
    header('Location: dashboard.php');
    exit();
}

// Génération du token CSRF
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Gestion des messages d'erreur/succès
$error_message = '';
$success_message = '';
$email_sent = false;

if (isset($_SESSION['error_message'])) {
    $error_message = $_SESSION['error_message'];
    unset($_SESSION['error_message']);
}

if (isset($_SESSION['success_message'])) {
    $success_message = $_SESSION['success_message'];
    unset($_SESSION['success_message']);
}

if (isset($_SESSION['email_sent'])) {
    $email_sent = $_SESSION['email_sent'];
    unset($_SESSION['email_sent']);
}

// Vérification du rate limiting pour les demandes de réinitialisation
$reset_attempts_key = 'reset_attempts_' . ($_SERVER['REMOTE_ADDR'] ?? 'unknown');
$lockout_time = 3600; // 1 heure
$max_attempts = 3; // Maximum 3 demandes par heure

$reset_attempts = $_SESSION[$reset_attempts_key]['count'] ?? 0;
$last_attempt_time = $_SESSION[$reset_attempts_key]['time'] ?? 0;

$locked_out = false;
if ($reset_attempts >= $max_attempts && (time() - $last_attempt_time < $lockout_time)) {
    $locked_out = true;
    $remaining_time = $lockout_time - (time() - $last_attempt_time);
    $error_message = "Trop de demandes de réinitialisation. Veuillez réessayer dans " . ceil($remaining_time / 60) . " minutes.";
}

?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="Réinitialisez votre mot de passe SecurePass en toute sécurité.">
    <title>Mot de passe oublié - SecurePass</title>
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
            --warning-color: #ed8936;
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
            max-width: 900px;
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
            line-height: 1.5;
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
            background: var(--bg-white);
            color: var(--text-primary);
            font-family: inherit;
        }

        input:focus {
            outline: none;
            border-color: var(--border-focus);
            background: var(--bg-white);
            box-shadow: 0 0 0 3px rgba(102,126,234,0.1);
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
            width: 100%;
        }

        .btn-primary {
            background: linear-gradient(45deg, var(--primary-color), var(--primary-dark));
            color: white;
            box-shadow: 0 4px 15px rgba(102,126,234,0.4);
            margin-bottom: 1rem;
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

        .btn-secondary {
            background: var(--bg-light);
            color: var(--text-primary);
            border: 2px solid var(--border-color);
        }

        .btn-secondary:hover {
            background: var(--border-color);
            transform: translateY(-1px);
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

        .recovery-info-section {
            background: linear-gradient(135deg, var(--primary-color) 0%, var(--primary-dark) 100%);
            padding: 2.5rem;
            color: white;
            display: flex;
            flex-direction: column;
            justify-content: center;
            gap: 1.5rem;
        }

        .recovery-step {
            background: rgba(255,255,255,0.1);
            padding: 1.5rem;
            border-radius: var(--radius);
            display: flex;
            align-items: flex-start;
            gap: 1rem;
        }

        .step-number {
            background: rgba(255,255,255,0.2);
            width: 2.5rem;
            height: 2.5rem;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 700;
            font-size: 1.1rem;
            flex-shrink: 0;
        }

        .step-content h3 {
            margin-bottom: 0.5rem;
            font-size: 1.1rem;
        }

        .step-content p {
            opacity: 0.9;
            line-height: 1.4;
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
        }

        .alert.hidden {
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

        .alert-info {
            background: #bee3f8;
            color: #2c5282;
            border: 1px solid #90cdf4;
        }

        .success-state {
            text-align: center;
            padding: 2rem 0;
        }

        .success-icon {
            font-size: 4rem;
            color: var(--success-color);
            margin-bottom: 1rem;
        }

        .success-state h2 {
            color: var(--text-primary);
            margin-bottom: 1rem;
            font-size: 1.5rem;
        }

        .success-state p {
            color: var(--text-secondary);
            margin-bottom: 2rem;
            line-height: 1.6;
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

        .security-notice {
            background: rgba(255,255,255,0.05);
            border: 1px solid rgba(255,255,255,0.1);
            padding: 1rem;
            border-radius: var(--radius);
            margin-top: 1.5rem;
            font-size: 0.9rem;
            opacity: 0.9;
        }

        .security-notice i {
            color: #feca57;
            margin-right: 0.5rem;
        }

        /* Responsive Design */
        @media (max-width: 768px) {
            .auth-container {
                grid-template-columns: 1fr;
            }
            .recovery-info-section {
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
            .recovery-info-section {
                background: linear-gradient(135deg, #2d3748 0%, #4a5568 100%);
            }
            input {
                background: var(--bg-light);
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

        .fade-in {
            animation: fadeIn 0.5s ease-in;
        }

        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
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
                <h1>Mot de passe oublié</h1>
                <p>Saisissez votre adresse email pour recevoir un lien de réinitialisation sécurisé.</p>
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

            <?php if ($email_sent): ?>
                <div class="success-state fade-in">
                    <div class="success-icon">
                        <i class="fas fa-paper-plane"></i>
                    </div>
                    <h2>Email envoyé !</h2>
                    <p>
                        Si votre adresse email est enregistrée dans notre système, vous recevrez un lien de réinitialisation dans les prochaines minutes.
                        <br><br>
                        Vérifiez votre boîte de réception et vos spams.
                    </p>
                    <a href="login.php" class="btn btn-primary">
                        <i class="fas fa-arrow-left"></i>
                        Retour à la connexion
                    </a>
                </div>
            <?php else: ?>
                <form id="forgotForm" method="POST" action="../includes/auth.php">
                    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                    <input type="hidden" name="action" value="forgot_password">

                    <div class="form-group">
                        <label for="email"><i class="fas fa-envelope"></i> Adresse email</label>
                        <input type="email" id="email" name="email" required 
                               placeholder="votre@email.com" 
                               autocomplete="email"
                               value="<?php echo isset($_POST['email']) ? htmlspecialchars($_POST['email'], ENT_QUOTES, 'UTF-8') : ''; ?>">
                    </div>

                    <div class="alert alert-info">
                        <i class="fas fa-info-circle"></i>
                        <span>Un email de réinitialisation sera envoyé si cette adresse est enregistrée dans notre système.</span>
                    </div>

                    <button type="submit" class="btn btn-primary" id="submitBtn" <?php echo $locked_out ? 'disabled' : ''; ?>>
                        <span class="spinner" id="spinner"></span>
                        <i class="fas fa-paper-plane" id="submitIcon"></i>
                        <span id="submitText">Envoyer le lien</span>
                    </button>

                    <a href="login.php" class="btn btn-secondary">
                        <i class="fas fa-arrow-left"></i>
                        Retour à la connexion
                    </a>
                </form>
            <?php endif; ?>

            <div class="auth-footer">
                <p>Besoin d'aide ? <a href="mailto:support@securepass.com">Contactez le support</a></p>
                <p class="legal-links">
                    <a href="../legal/privacy.php">Politique de confidentialité</a> •
                    <a href="../legal/terms.php">Conditions d'utilisation</a>
                </p>
            </div>
        </div>

        <div class="recovery-info-section">
            <div class="recovery-step">
                <div class="step-number">1</div>
                <div class="step-content">
                    <h3>Saisissez votre email</h3>
                    <p>Entrez l'adresse email associée à votre compte SecurePass.</p>
                </div>
            </div>

            <div class="recovery-step">
                <div class="step-number">2</div>
                <div class="step-content">
                    <h3>Vérifiez votre boîte mail</h3>
                    <p>Nous vous enverrons un lien sécurisé pour réinitialiser votre mot de passe.</p>
                </div>
            </div>

            <div class="recovery-step">
                <div class="step-number">3</div>
                <div class="step-content">
                    <h3>Créez un nouveau mot de passe</h3>
                    <p>Suivez le lien et définissez un nouveau mot de passe maître sécurisé.</p>
                </div>
            </div>

            <div class="security-notice">
                <i class="fas fa-shield-alt"></i>
                <strong>Sécurité garantie :</strong> Le lien de réinitialisation expire après 1 heure et ne peut être utilisé qu'une seule fois.
            </div>
        </div>
    </div>

    <script>
        function setLoadingState(isLoading) {
            const submitBtn = document.getElementById('submitBtn');
            const spinner = document.getElementById('spinner');
            const submitIcon = document.getElementById('submitIcon');
            const submitText = document.getElementById('submitText');

            if (isLoading) {
                submitBtn.disabled = true;
                spinner.style.display = 'block';
                submitIcon.style.display = 'none';
                submitText.textContent = 'Envoi en cours...';
            } else {
                submitBtn.disabled = false;
                spinner.style.display = 'none';
                submitIcon.style.display = 'inline';
                submitText.textContent = 'Envoyer le lien';
            }
        }

        function showAlert(message, type = 'error') {
            const alertElement = document.getElementById('alert');
            const alertText = document.getElementById('alertText');
            
            if (alertElement && alertText) {
                alertText.textContent = message;
                alertElement.className = `alert alert-${type}`;
                alertElement.classList.remove('hidden');

                setTimeout(() => {
                    alertElement.classList.add('hidden');
                }, 6000);
            }
        }

        document.getElementById('forgotForm')?.addEventListener('submit', function(e) {
            const email = document.getElementById('email').value.trim();

            if (!email) {
                showAlert('Veuillez entrer votre adresse email.');
                e.preventDefault();
                return;
            }

            // Validation email basique
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailRegex.test(email)) {
                showAlert('Veuillez entrer une adresse email valide.');
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
                }, 6000);
            } else if (alertMessage) {
                alertMessage.classList.add('hidden');
            }

            // Focus sur le champ email si le formulaire est présent
            const emailField = document.getElementById('email');
            if (emailField) {
                emailField.focus();
            }
        });

        // Nettoyage sécurisé lors de la fermeture de la page
        window.addEventListener('beforeunload', function() {
            const emailField = document.getElementById('email');
            if (emailField) {
                emailField.value = '';
            }
        });
    </script>
</body>
</html>