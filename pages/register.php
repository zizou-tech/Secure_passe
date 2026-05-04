<?php
session_start();

// Headers de sécurité conformes au cahier des charges
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('X-XSS-Protection: 1; mode=block');
header('Referrer-Policy: strict-origin-when-cross-origin');
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; font-src 'self' https://cdnjs.cloudflare.com; img-src 'self' data:;");

// Génération du token CSRF (inclus dans auth.php ou ici si vous voulez le générer avant le chargement de la page)
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
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="Créer un compte sécurisé sur SecurePass - Votre gestionnaire de mots de passe">
    <title>Inscription - SecurePass</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        /* Variables CSS pour le thème (alignées avec login.php) */
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

        .container {
            display: grid;
            grid-template-columns: 1fr 1fr;
            max-width: 900px; /* Increased max-width for better layout */
            width: 100%;
            background: var(--bg-white);
            border-radius: var(--radius-lg);
            overflow: hidden;
            box-shadow: var(--shadow-lg);
            animation: slideInUp 0.6s ease-out; /* Add entry animation */
        }

        .form-section {
            padding: 2.5rem; /* Consistent padding with login.php */
            overflow-y: auto;
            max-height: 90vh;
        }

        .header {
            text-align: center;
            margin-bottom: 2rem;
        }

        .logo {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 0.75rem; /* Consistent gap with login.php */
            font-size: 1.5rem;
            font-weight: 700; /* Consistent font-weight */
            color: var(--primary-color);
            margin-bottom: 1rem;
        }

        h1 {
            font-size: 2rem; /* Consistent font-size with login.php */
            font-weight: 800;
            color: var(--text-primary);
            margin-bottom: 0.5rem;
        }

        .subtitle {
            color: var(--text-secondary);
            font-size: 1rem; /* Consistent font-size */
        }

        .form-row {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1rem;
        }

        .form-group {
            margin-bottom: 1.5rem; /* Consistent margin-bottom */
        }

        label {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            font-weight: 600;
            color: var(--text-primary); /* Consistent color */
            margin-bottom: 0.75rem; /* Consistent margin-bottom */
            font-size: 0.95rem; /* Consistent font-size */
        }

        input {
            width: 100%;
            padding: 1rem;
            border: 2px solid var(--border-color); /* Consistent border */
            border-radius: var(--radius); /* Consistent border-radius */
            font-size: 1rem;
            transition: all 0.3s ease;
            background: var(--bg-white); /* Assurez-vous que le fond est blanc ici */
            color: var(--text-primary); /* Assurez-vous que le texte est lisible */
            font-family: inherit;
        }

        input:focus {
            outline: none;
            border-color: var(--border-focus); /* Consistent border-color */
            background: var(--bg-white); /* Consistent background */
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
            color: var(--text-secondary); /* Consistent color */
            cursor: pointer;
            font-size: 1rem; /* Consistent font-size */
            padding: 0.5rem;
            border-radius: 0.25rem;
            transition: color 0.2s ease;
        }

        .toggle-password:hover {
            color: var(--primary-color); /* Consistent hover */
        }

        .strength-bar {
            height: 6px;
            background: var(--border-color); /* Consistent background */
            border-radius: 3px;
            margin: 0.5rem 0;
        }

        .strength-fill {
            height: 100%;
            width: 0%;
            transition: all 0.3s ease;
            border-radius: 3px;
        }

        .requirements {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 0.5rem;
            font-size: 0.875rem;
            color: var(--text-secondary); /* Consistent color */
        }

        .requirement {
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .requirement.met {
            color: var(--success-color); /* Consistent color */
        }

        .checkbox-container {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            margin-bottom: 1.5rem; /* Consistent margin-bottom */
            font-size: 0.9rem; /* Consistent font-size */
            color: var(--text-primary);
            user-select: none;
            cursor: pointer;
        }

        .checkbox-container input[type="checkbox"] {
            width: auto; /* Allow auto width for checkboxes */
            height: auto; /* Allow auto height for checkboxes */
            margin: 0;
        }

        .btn {
            padding: 1rem 1.5rem; /* Consistent padding */
            border-radius: var(--radius); /* Consistent border-radius */
            border: none;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 0.75rem; /* Consistent gap */
            text-decoration: none;
            font-family: inherit;
            font-size: 1rem;
            position: relative;
        }

        .btn-primary {
            background: linear-gradient(45deg, var(--primary-color), var(--primary-dark)); /* Consistent gradient */
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

        .visual-section {
            background: linear-gradient(135deg, var(--primary-color) 0%, var(--primary-dark) 100%);
            padding: 2.5rem; /* Consistent padding */
            color: white;
            display: flex;
            flex-direction: column;
            justify-content: center;
            gap: 1.5rem; /* Add gap between features */
        }

        .feature {
            background: rgba(255,255,255,0.1);
            padding: 1.5rem;
            border-radius: var(--radius); /* Consistent radius */
        }

        .feature h3 {
            margin-bottom: 0.5rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .feature h3 i {
            color: #feca57; /* Highlight icon */
        }

        .error {
            color: var(--error-color); /* Consistent color */
            font-size: 0.875rem;
            margin-top: 0.5rem;
            display: none;
        }

        .error.show {
            display: block;
        }

        .alert {
            padding: 1rem;
            border-radius: var(--radius); /* Consistent radius */
            margin-bottom: 1.5rem; /* Consistent margin */
            display: flex;
            align-items: center;
            gap: 0.75rem; /* Consistent gap */
            font-weight: 500;
            transition: opacity 0.3s ease;
            /* display: none; */ /* Garder l'alerte visible si un message est défini par PHP */
        }

        .alert.hidden { /* Classe pour cacher via JS */
            display: none;
        }

        .alert-error {
            background: #fed7d7;
            color: #c53030;
            border: 1px solid #feb2b2; /* Consistent border */
        }

        .alert-success {
            background: #c6f6d5;
            color: #2f855a; /* Consistent color */
            border: 1px solid #9ae6b4; /* Consistent border */
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

        .redirect-message {
            background: #bee3f8;
            color: #2b6cb0;
            padding: 1rem;
            border-radius: var(--radius); /* Consistent radius */
            margin-top: 1rem;
            display: none;
            align-items: center;
            gap: 0.75rem; /* Consistent gap */
            font-weight: 500;
        }

        .redirect-message.show {
            display: flex;
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

        .legal-links {
            font-size: 0.8rem;
            margin-top: 1rem;
        }


        /* Responsive Design */
        @media (max-width: 768px) {
            .container {
                grid-template-columns: 1fr;
            }
            .visual-section {
                display: none;
            }
            .form-section {
                padding: 2rem 1.5rem;
            }
            .header h1 {
                font-size: 1.75rem;
            }
            .form-row {
                grid-template-columns: 1fr;
            }
        }

        @media (max-width: 480px) {
            .logo {
                font-size: 1.25rem;
            }
            .header h1 {
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

            .container {
                background: var(--bg-white);
            }

            .visual-section {
                background: linear-gradient(135deg, #2d3748 0%, #4a5568 100%);
            }

            .feature {
                background: rgba(255,255,255,0.05);
            }

            input {
                background: var(--bg-light); /* En mode sombre, les inputs peuvent être plus sombres */
                color: var(--text-primary);
            }
            input:focus {
                background: var(--bg-light);
            }
        }

        /* Animation d'entrée */
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
    <div class="container">
        <div class="form-section">
            <div class="header">
                <div class="logo">
                    <i class="fas fa-shield-alt"></i>
                    <span>SecurePass</span>
                </div>
                <h1>Créer un compte</h1>
                <p class="subtitle">Rejoignez des milliers d'utilisateurs qui protègent leurs données</p>
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

            <form id="registerForm" method="POST" action="../includes/auth.php">
                <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                <input type="hidden" name="action" value="register">

                <div class="form-row">
                    <div class="form-group">
                        <label for="firstName"><i class="fas fa-user"></i> Prénom</label>
                        <input type="text" id="firstName" name="firstName" required placeholder="Votre prénom" maxlength="100">
                        <div class="error" id="firstNameError"></div>
                    </div>
                    <div class="form-group">
                        <label for="lastName"><i class="fas fa-user"></i> Nom</label>
                        <input type="text" id="lastName" name="lastName" required placeholder="Votre nom" maxlength="100">
                        <div class="error" id="lastNameError"></div>
                    </div>
                </div>

                <div class="form-group">
                    <label for="email"><i class="fas fa-envelope"></i> Email</label>
                    <input type="email" id="email" name="email" required placeholder="votre@email.com" autocomplete="email" maxlength="255">
                    <div class="error" id="emailError"></div>
                </div>

                <div class="form-group">
                    <label for="password"><i class="fas fa-lock"></i> Mot de passe maître</label>
                    <div class="password-input">
                        <input type="password" id="password" name="password" required placeholder="Minimum 12 caractères" autocomplete="new-password" minlength="12" maxlength="128">
                        <button type="button" class="toggle-password" onclick="togglePassword('password')">
                            <i class="fas fa-eye"></i>
                        </button>
                    </div>
                    <div class="strength-bar">
                        <div class="strength-fill" id="strengthFill"></div>
                    </div>
                    <div class="requirements">
                        <div class="requirement" id="lengthReq"><i class="fas fa-times"></i> 12+ caractères</div>
                        <div class="requirement" id="uppercaseReq"><i class="fas fa-times"></i> Majuscule</div>
                        <div class="requirement" id="lowercaseReq"><i class="fas fa-times"></i> Minuscule</div>
                        <div class="requirement" id="numberReq"><i class="fas fa-times"></i> Chiffre</div>
                        <div class="requirement" id="specialReq"><i class="fas fa-times"></i> Spécial</div>
                    </div>
                </div>

                <div class="form-group">
                    <label for="confirmPassword"><i class="fas fa-lock"></i> Confirmer le mot de passe maître</label>
                    <div class="password-input">
                        <input type="password" id="confirmPassword" name="confirmPassword" required placeholder="Répétez votre mot de passe" autocomplete="new-password" minlength="12" maxlength="128">
                        <button type="button" class="toggle-password" onclick="togglePassword('confirmPassword')">
                            <i class="fas fa-eye"></i>
                        </button>
                    </div>
                    <div class="error" id="confirmPasswordError"></div>
                </div>

                <div class="checkbox-container">
                    <input type="checkbox" id="terms" name="terms" required>
                    <label for="terms">J'accepte les <a href="../legal/terms.php" style="color: var(--primary-color); text-decoration: none; font-weight: 600;" target="_blank">conditions d'utilisation</a></label>
                </div>

                <button type="submit" class="btn btn-primary" id="submitBtn">
                    <span class="spinner" id="spinner"></span>
                    <i class="fas fa-user-plus" id="submitIcon"></i>
                    <span id="submitText">Créer mon compte</span>
                </button>
            </form>

            <div class="redirect-message" id="redirectMessage">
                <i class="fas fa-info-circle"></i>
                <span>Inscription réussie ! Redirection vers la page de connexion dans <span id="countdown">3</span> secondes...</span>
            </div>

            <div class="auth-footer">
                <p>Déjà un compte ? <a href="login.php">Se connecter</a></p>
                <p class="legal-links">
                    <a href="../legal/privacy.php">Politique de confidentialité</a> •
                    <a href="../legal/terms.php">Conditions d'utilisation</a>
                </p>
            </div>
        </div>

        <div class="visual-section">
            <div class="feature">
                <h3><i class="fas fa-key"></i> Génération Avancée</h3>
                <p>Algorithmes cryptographiques pour des mots de passe ultra-sécurisés.</p>
            </div>
            <div class="feature">
                <h3><i class="fas fa-brain"></i> IA Intégrée</h3>
                <p>Analyse intelligente de la robustesse avec machine learning.</p>
            </div>
            <div class="feature">
                <h3><i class="fas fa-database"></i> Détection de Compromission</h3>
                <p>Vérification automatique dans les bases de données piratées.</p>
            </div>
        </div>
    </div>

    <script>
        function togglePassword(inputId) {
            const input = document.getElementById(inputId);
            const icon = input.nextElementSibling.querySelector('i');
            if (input.type === 'password') {
                input.type = 'text';
                icon.className = 'fas fa-eye-slash';
            } else {
                input.type = 'password';
                icon.className = 'fas fa-eye';
            }
        }

        function updateRequirement(id, isMet) {
            const req = document.getElementById(id);
            const icon = req.querySelector('i');
            if (isMet) {
                req.classList.add('met');
                icon.className = 'fas fa-check';
            } else {
                req.classList.remove('met');
                icon.className = 'fas fa-times';
            }
        }

        function analyzePassword(password) {
            const requirements = {
                length: password.length >= 12,
                uppercase: /[A-Z]/.test(password),
                lowercase: /[a-z]/.test(password),
                number: /\d/.test(password),
                special: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)
            };

            updateRequirement('lengthReq', requirements.length);
            updateRequirement('uppercaseReq', requirements.uppercase);
            updateRequirement('lowercaseReq', requirements.lowercase);
            updateRequirement('numberReq', requirements.number);
            updateRequirement('specialReq', requirements.special);

            const score = Object.values(requirements).reduce((acc, met) => acc + (met ? 1 : 0), 0);
            const strengthFill = document.getElementById('strengthFill');

            let percentage = (score / 5) * 100;
            let color = score <= 2 ? 'var(--error-color)' : score === 3 ? 'var(--warning-color)' : score === 4 ? '#ecc94b' : 'var(--success-color)';

            strengthFill.style.width = `${percentage}%`;
            strengthFill.style.backgroundColor = color;
        }

        function showAlert(message, type = 'error') {
            const alert = document.getElementById('alert');
            const text = document.getElementById('alertText');
            text.textContent = message;
            alert.className = `alert alert-${type}`;
            alert.classList.remove('hidden');

            setTimeout(() => {
                alert.classList.add('hidden');
            }, 5000);
        }

        function validateEmail(email) {
            return /^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$/i.test(email);
        }

        function validateName(name) {
            // Permet lettres, espaces, tirets, apostrophes. Minimum 2 caractères non-blanc.
            return /^[a-zA-ZÀ-ÿ\s\-']{2,}$/.test(name.trim());
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
                submitText.textContent = 'Création en cours...';
            } else {
                submitBtn.disabled = false;
                spinner.style.display = 'none';
                submitIcon.style.display = 'inline';
                submitText.textContent = 'Créer mon compte';
            }
        }

        // Event Listeners
        document.getElementById('password').addEventListener('input', function(e) {
            analyzePassword(e.target.value);
        });

        document.getElementById('registerForm').addEventListener('submit', function(e) {
            // Client-side validation
            const firstName = document.getElementById('firstName').value.trim();
            const lastName = document.getElementById('lastName').value.trim();
            const email = document.getElementById('email').value.trim();
            const password = document.getElementById('password').value;
            const confirmPassword = document.getElementById('confirmPassword').value;
            const terms = document.getElementById('terms').checked;

            if (!validateName(firstName)) {
                showAlert('Le prénom doit contenir au moins 2 caractères et uniquement des lettres, tirets ou apostrophes.');
                e.preventDefault();
                return;
            }
            if (!validateName(lastName)) {
                showAlert('Le nom doit contenir au moins 2 caractères et uniquement des lettres, tirets ou apostrophes.');
                e.preventDefault();
                return;
            }
            if (!validateEmail(email)) {
                showAlert('Veuillez entrer une adresse email valide.');
                e.preventDefault();
                return;
            }
            if (password.length < 12) {
                showAlert('Le mot de passe maître doit contenir au moins 12 caractères.');
                e.preventDefault();
                return;
            }
            const passwordRequirements = {
                uppercase: /[A-Z]/.test(password),
                lowercase: /[a-z]/.test(password),
                number: /\d/.test(password),
                special: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)
            };
            if (!Object.values(passwordRequirements).every(req => req)) {
                 showAlert('Le mot de passe maître doit inclure des majuscules, minuscules, chiffres et caractères spéciaux.');
                 e.preventDefault();
                 return;
            }
            if (password !== confirmPassword) {
                showAlert('Les mots de passe ne correspondent pas.');
                e.preventDefault();
                return;
            }
            if (!terms) {
                showAlert('Vous devez accepter les conditions d\'utilisation.');
                e.preventDefault();
                return;
            }

            setLoadingState(true); // Afficher le spinner
            // La soumission du formulaire continuera normalement vers auth.php
        });


        // Auto-hide alert on page load if present
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
            document.getElementById('firstName').focus();
        });

        // Clear sensitive fields before unload for security
        window.addEventListener('beforeunload', function() {
            const passwordField = document.getElementById('password');
            const confirmPasswordField = document.getElementById('confirmPassword');

            if (passwordField) passwordField.value = '';
            if (confirmPasswordField) confirmPasswordField.value = '';
        });
    </script>
</body>
</html>