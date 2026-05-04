<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecurePass - Générateur de Mots de Passe Sécurisé</title>
    <link rel="stylesheet" href="assets/css/style.css">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
</head>
<body>
    <div class="hero-container">
        <nav class="navbar">
            <div class="nav-brand">
                <i class="fas fa-shield-alt"></i>
                <span>SecurePass</span>
            </div>
            <div class="nav-links">
                <a href="pages/login.php" class="btn btn-outline">Connexion</a>
                <a href="pages/register.php" class="btn btn-primary">S'inscrire</a>
            </div>
        </nav>

        <div class="hero-content">
            <div class="hero-text">
                <h1>Sécurisez vos données avec des <span class="highlight">mots de passe inviolables</span></h1>
                <p class="hero-subtitle">
                    Générez, analysez et stockez vos mots de passe en toute sécurité. 
                    Protégez-vous contre les cyberattaques avec notre solution avancée.
                </p>
                
                <div class="features-grid">
                    <div class="feature-card">
                        <div class="feature-icon">
                            <i class="fas fa-key"></i>
                        </div>
                        <h3>Génération Sécurisée</h3>
                        <p>Mots de passe de 12+ caractères avec cryptographie avancée</p>
                    </div>
                    
                    <div class="feature-card">
                        <div class="feature-icon">
                            <i class="fas fa-chart-line"></i>
                        </div>
                        <h3>Analyse de Robustesse</h3>
                        <p>Évaluation intelligente basée sur l'IA et machine learning</p>
                    </div>
                    
                    <div class="feature-card">
                        <div class="feature-icon">
                            <i class="fas fa-database"></i>
                        </div>
                        <h3>Vérification Compromis</h3>
                        <p>Détection des mots de passe dans les bases de données piratées</p>
                    </div>
                    
                    <div class="feature-card">
                        <div class="feature-icon">
                            <i class="fas fa-vault"></i>
                        </div>
                        <h3>Stockage Chiffré</h3>
                        <p>Coffre-fort personnel avec chiffrement AES-256</p>
                    </div>
                </div>
            </div>

            <div class="hero-visual">
                <div class="password-demo">
                    <div class="demo-window">
                        <div class="window-header">
                            <div class="window-controls">
                                <span class="control red"></span>
                                <span class="control yellow"></span>
                                <span class="control green"></span>
                            </div>
                            <span class="window-title">Générateur SecurePass</span>
                        </div>
                        <div class="demo-content">
                            <div class="password-field">
                                <input type="text" value="X9k#mP8$vL2@nQ4!" readonly>
                                <div class="strength-indicator">
                                    <div class="strength-bar excellent"></div>
                                    <span>Excellent</span>
                                </div>
                            </div>
                            <div class="demo-options">
                                <label><input type="checkbox" checked> Majuscules</label>
                                <label><input type="checkbox" checked> Minuscules</label>
                                <label><input type="checkbox" checked> Chiffres</label>
                                <label><input type="checkbox" checked> Symboles</label>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <footer class="footer">
        <div class="footer-content">
            <div class="footer-brand">
                <i class="fas fa-shield-alt"></i>
                <span>SecurePass</span>
            </div>
            <p>&copy; 2025 SecurePass. Votre sécurité est notre priorité.</p>
        </div>
    </footer>

    <style>
        /* CSS intégré pour cette démonstration */
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            line-height: 1.6;
            color: #333;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }

        .hero-container {
            min-height: 100vh;
            display: flex;
            flex-direction: column;
        }

        .navbar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 1rem 2rem;
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            border-bottom: 1px solid rgba(255, 255, 255, 0.2);
        }

        .nav-brand {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            font-size: 1.5rem;
            font-weight: bold;
            color: white;
        }

        .nav-links {
            display: flex;
            gap: 1rem;
        }

        .btn {
            padding: 0.75rem 1.5rem;
            border-radius: 50px;
            text-decoration: none;
            font-weight: 600;
            transition: all 0.3s ease;
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            border: none;
            cursor: pointer;
        }

        .btn-primary {
            background: linear-gradient(45deg, #ff6b6b, #ee5a24);
            color: white;
            box-shadow: 0 4px 15px rgba(255, 107, 107, 0.4);
        }

        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(255, 107, 107, 0.6);
        }

        .btn-secondary {
            background: rgba(255, 255, 255, 0.2);
            color: white;
            border: 2px solid rgba(255, 255, 255, 0.3);
        }

        .btn-secondary:hover {
            background: rgba(255, 255, 255, 0.3);
            transform: translateY(-2px);
        }

        .btn-outline {
            background: transparent;
            color: white;
            border: 2px solid rgba(255, 255, 255, 0.5);
        }

        .btn-outline:hover {
            background: white;
            color: #667eea;
        }

        .btn-large {
            padding: 1rem 2rem;
            font-size: 1.1rem;
        }

        .hero-content {
            flex: 1;
            display: grid;
            grid-template-columns: 1fr 1fr;
            align-items: center;
            gap: 4rem;
            padding: 4rem 2rem;
            max-width: 1200px;
            margin: 0 auto;
        }

        .hero-text h1 {
            font-size: 3.5rem;
            font-weight: 900;
            color: white;
            margin-bottom: 1.5rem;
            line-height: 1.2;
        }

        .highlight {
            background: linear-gradient(45deg, #ff6b6b, #feca57);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .hero-subtitle {
            font-size: 1.2rem;
            color: rgba(255, 255, 255, 0.9);
            margin-bottom: 3rem;
        }

        .features-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 1.5rem;
            margin-bottom: 3rem;
        }

        .feature-card {
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            padding: 1.5rem;
            border-radius: 20px;
            border: 1px solid rgba(255, 255, 255, 0.2);
            transition: transform 0.3s ease;
        }

        .feature-card:hover {
            transform: translateY(-5px);
        }

        .feature-icon {
            font-size: 2rem;
            color: #feca57;
            margin-bottom: 1rem;
        }

        .feature-card h3 {
            color: white;
            font-size: 1.1rem;
            margin-bottom: 0.5rem;
        }

        .feature-card p {
            color: rgba(255, 255, 255, 0.8);
            font-size: 0.9rem;
        }

        .cta-buttons {
            display: flex;
            gap: 1rem;
            flex-wrap: wrap;
        }

        .hero-visual {
            display: flex;
            justify-content: center;
            align-items: center;
        }

        .password-demo {
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(20px);
            border-radius: 20px;
            padding: 2rem;
            border: 1px solid rgba(255, 255, 255, 0.2);
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
        }

        .demo-window {
            background: white;
            border-radius: 15px;
            overflow: hidden;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.2);
        }

        .window-header {
            background: #f8f9fa;
            padding: 1rem;
            display: flex;
            align-items: center;
            gap: 1rem;
            border-bottom: 1px solid #e9ecef;
        }

        .window-controls {
            display: flex;
            gap: 0.5rem;
        }

        .control {
            width: 12px;
            height: 12px;
            border-radius: 50%;
        }

        .control.red { background: #ff5f56; }
        .control.yellow { background: #ffbd2e; }
        .control.green { background: #27ca3f; }

        .window-title {
            font-weight: 600;
            color: #495057;
        }

        .demo-content {
            padding: 2rem;
        }

        .password-field {
            margin-bottom: 1.5rem;
        }

        .password-field input {
            width: 100%;
            padding: 1rem;
            border: 2px solid #e9ecef;
            border-radius: 10px;
            font-family: 'Courier New', monospace;
            font-size: 1.1rem;
            font-weight: bold;
            text-align: center;
            background: #f8f9fa;
        }

        .strength-indicator {
            display: flex;
            align-items: center;
            gap: 1rem;
            margin-top: 1rem;
        }

        .strength-bar {
            flex: 1;
            height: 8px;
            border-radius: 4px;
            position: relative;
            background: #e9ecef;
        }

        .strength-bar.excellent::after {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            height: 100%;
            width: 100%;
            background: linear-gradient(90deg, #27ca3f, #10ac84);
            border-radius: 4px;
        }

        .strength-indicator span {
            font-weight: 600;
            color: #27ca3f;
        }

        .demo-options {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 1rem;
        }

        .demo-options label {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            font-size: 0.9rem;
            color: #495057;
        }

        .security-stats {
            display: flex;
            justify-content: center;
            gap: 4rem;
            padding: 2rem;
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            border-top: 1px solid rgba(255, 255, 255, 0.2);
        }

        .stat-item {
            text-align: center;
        }

        .stat-number {
            font-size: 2.5rem;
            font-weight: 900;
            color: #feca57;
            margin-bottom: 0.5rem;
        }

        .stat-label {
            color: rgba(255, 255, 255, 0.9);
            font-weight: 600;
        }

        .footer {
            background: rgba(0, 0, 0, 0.3);
            backdrop-filter: blur(10px);
            border-top: 1px solid rgba(255, 255, 255, 0.1);
        }

        .footer-content {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 2rem;
            max-width: 1200px;
            margin: 0 auto;
            color: rgba(255, 255, 255, 0.8);
        }

        .footer-brand {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            font-weight: bold;
            color: white;
        }

        @media (max-width: 768px) {
            .hero-content {
                grid-template-columns: 1fr;
                text-align: center;
                gap: 2rem;
            }

            .hero-text h1 {
                font-size: 2.5rem;
            }

            .features-grid {
                grid-template-columns: 1fr;
            }

            .security-stats {
                gap: 2rem;
            }

            .cta-buttons {
                justify-content: center;
            }

            .footer-content {
                flex-direction: column;
                gap: 1rem;
                text-align: center;
            }
        }
    </style>
</body>
</html>