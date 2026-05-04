<?php
session_start();

// Détruire toutes les données de session
$_SESSION = array();

// Détruire le cookie de session si il existe
if (ini_get("session.use_cookies")) {
    $params = session_get_cookie_params();
    setcookie(session_name(), '', time() - 42000,
        $params["path"], $params["domain"],
        $params["secure"], $params["httponly"]
    );
}

// Détruire la session
session_destroy();

// Supprimer le cookie "remember me" si il existe
if (isset($_COOKIE['remember_token'])) {
    setcookie('remember_token', '', time() - 3600, '/');
}
?>

<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Déconnexion - SecurePass</title>
    <link rel="stylesheet" href="../assets/css/style.css">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <meta http-equiv="refresh" content="5;url=../index.php">
</head>
<body class="auth-body">
    <div class="auth-container logout-container">
        <div class="auth-card logout-card">
            <div class="auth-header">
                <div class="brand-logo">
                    <i class="fas fa-shield-alt"></i>
                    <span>SecurePass</span>
                </div>
                <div class="logout-icon">
                    <i class="fas fa-sign-out-alt"></i>
                </div>
                <h1>Déconnexion réussie</h1>
                <p>Vous avez été déconnecté en toute sécurité</p>
            </div>

            <div class="logout-content">
                <div class="success-message">
                    <i class="fas fa-check-circle"></i>
                    <h3>Session terminée</h3>
                    <p>Toutes vos données ont été sécurisées et votre session a été fermée.</p>
                </div>

                <div class="logout-actions">
                    <a href="login.php" class="btn btn-primary btn-full">
                        <i class="fas fa-sign-in-alt"></i>
                        Se reconnecter
                    </a>
                    
                    <div class="divider">
                        <span>ou</span>
                    </div>
                    
                    <a href="../index.php" class="btn btn-secondary btn-full">
                        <i class="fas fa-home"></i>
                        Retour à l'accueil
                    </a>
                </div>

                <div class="auto-redirect">
                    <i class="fas fa-clock"></i>
                    <p>Redirection automatique vers la page d'accueil dans <span id="countdown">5</span> secondes...</p>
                </div>
            </div>
        </div>

        <div class="auth-visual logout-visual">
            <div class="security-animation">
                <div class="shield-container">
                    <i class="fas fa-shield-check shield-icon success"></i>
                    <div class="success-ring"></div>
                    <div class="success-ring delay-1"></div>
                </div>
                <h2>Session Sécurisée</h2>
                <p>Vos données restent protégées même après la déconnexion grâce à notre chiffrement avancé.</p>
                
                <div class="security-features">
                    <div class="feature">
                        <i class="fas fa-trash-alt"></i>
                        <span>Données de session effacées</span>
                    </div>
                    <div class="feature">
                        <i class="fas fa-cookie-bite"></i>
                        <span>Cookies sécurisés supprimés</span>
                    </div>
                    <div class="feature">
                        <i class="fas fa-history"></i>
                        <span>Historique de session nettoyé</span>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <style>
        .auth-body {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 2rem;
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
        }

        .auth-container {
            display: grid;
            grid-template-columns: 1fr 1fr;
            max-width: 1000px;
            width: 100%;
            background: white;
            border-radius: 20px;
            overflow: hidden;
            box-shadow: 0 25px 50px rgba(0, 0, 0, 0.2);
            min-height: 600px;
        }

        .auth-card {
            padding: 3rem;
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
            gap: 0.5rem;
            font-size: 1.5rem;
            font-weight: bold;
            color: #667eea;
            margin-bottom: 1rem;
        }

        .logout-icon {
            font-size: 3rem;
            color: #48bb78;
            margin-bottom: 1rem;
        }

        .auth-header h1 {
            font-size: 2rem;
            font-weight: 800;
            color: #2d3748;
            margin-bottom: 0.5rem;
        }

        .auth-header p {
            color: #718096;
            font-size: 1rem;
        }

        .logout-content {
            text-align: center;
        }

        .success-message {
            background: linear-gradient(135deg, #48bb78, #38a169);
            color: white;
            padding: 2rem;
            border-radius: 15px;
            margin-bottom: 2rem;
        }

        .success-message i {
            font-size: 2.5rem;
            margin-bottom: 1rem;
        }

        .success-message h3 {
            font-size: 1.5rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
        }

        .success-message p {
            opacity: 0.9;
            line-height: 1.5;
        }

        .logout-actions {
            margin-bottom: 2rem;
        }

        .btn {
            padding: 1rem 1.5rem;
            border-radius: 10px;
            border: none;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 0.5rem;
            text-decoration: none;
            margin-bottom: 1rem;
        }

        .btn-primary {
            background: linear-gradient(45deg, #667eea, #764ba2);
            color: white;
            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4);
        }

        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(102, 126, 234, 0.6);
        }

        .btn-secondary {
            background: white;
            border: 2px solid #e2e8f0;
            color: #4a5568;
        }

        .btn-secondary:hover {
            border-color: #cbd5e0;
            background: #f7fafc;
            transform: translateY(-1px);
        }

        .btn-full {
            width: 100%;
        }

        .divider {
            text-align: center;
            margin: 1rem 0;
            position: relative;
            color: #a0aec0;
        }

        .divider::before {
            content: '';
            position: absolute;
            top: 50%;
            left: 0;
            right: 0;
            height: 1px;
            background: #e2e8f0;
        }

        .divider span {
            background: white;
            padding: 0 1rem;
        }

        .auto-redirect {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 0.5rem;
            color: #718096;
            font-size: 0.9rem;
            background: #f7fafc;
            padding: 1rem;
            border-radius: 10px;
            border: 1px solid #e2e8f0;
        }

        .auto-redirect i {
            color: #667eea;
        }

        #countdown {
            font-weight: bold;
            color: #667eea;
        }

        .auth-visual {
            background: linear-gradient(135deg, #48bb78 0%, #38a169 100%);
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 3rem;
            color: white;
        }

        .security-animation {
            text-align: center;
        }

        .shield-container {
            position: relative;
            margin-bottom: 2rem;
            display: flex;
            justify-content: center;
            align-items: center;
        }

        .shield-icon {
            font-size: 4rem;
            z-index: 2;
            position: relative;
        }

        .shield-icon.success {
            animation: successPulse 2s infinite;
        }

        .success-ring {
            position: absolute;
            border: 3px solid rgba(255, 255, 255, 0.3);
            border-radius: 50%;
            width: 80px;
            height: 80px;
            animation: successRing 2s infinite;
        }

        .success-ring.delay-1 {
            animation-delay: 0.5s;
            width: 100px;
            height: 100px;
        }

        @keyframes successPulse {
            0%, 100% {
                transform: scale(1);
            }
            50% {
                transform: scale(1.1);
            }
        }

        @keyframes successRing {
            0% {
                transform: scale(0.8);
                opacity: 1;
            }
            100% {
                transform: scale(1.4);
                opacity: 0;
            }
        }

        .security-animation h2 {
            font-size: 2rem;
            margin-bottom: 1rem;
            font-weight: 700;
        }

        .security-animation p {
            margin-bottom: 2rem;
            opacity: 0.9;
            line-height: 1.6;
        }

        .security-features {
            display: flex;
            flex-direction: column;
            gap: 1rem;
        }

        .feature {
            display: flex;
            align-items: center;
            gap: 1rem;
            background: rgba(255, 255, 255, 0.1);
            padding: 1rem;
            border-radius: 10px;
            backdrop-filter: blur(10px);
        }

        .feature i {
            font-size: 1.2rem;
        }

        /* Responsive */
        @media (max-width: 768px) {
            .auth-container {
                grid-template-columns: 1fr;
                max-width: 500px;
            }
            
            .auth-visual {
                display: none;
            }
            
            .auth-card {
                padding: 2rem;
            }
        }
    </style>

    <script>
        // Compte à rebours pour la redirection
        let countdown = 5;
        const countdownElement = document.getElementById('countdown');
        
        const timer = setInterval(() => {
            countdown--;
            countdownElement.textContent = countdown;
            
            if (countdown <= 0) {
                clearInterval(timer);
                window.location.href = '../index.php';
            }
        }, 1000);

        // Permettre d'annuler la redirection en cliquant quelque part
        document.addEventListener('click', () => {
            clearInterval(timer);
            document.querySelector('.auto-redirect').innerHTML = 
                '<i class="fas fa-info-circle"></i><p>Redirection automatique annulée</p>';
        });
    </script>
</body>
</html>