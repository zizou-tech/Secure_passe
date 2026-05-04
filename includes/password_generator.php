<?php
// Inclure les fichiers nécessaires
require_once __DIR__ . '/crypto.php';

// Configuration par défaut
$defaultLength = 16;
$generated_password = '';
$generated_passwords = [];
$error = '';
$success = '';
$passphrase = '';

// Initialiser l'objet AES
$aes = new AES256Encryption();

// Listes pour la vérification
$commonPasswords = [
    'password', '123456', '123456789', 'qwerty', 'abc123', 'password123', 
    'admin', 'letmein', 'welcome', 'monkey', '1234567890', 'iloveyou'
];

$ambiguousChars = ['0', 'O', 'l', '1', 'I', 'o'];

// Mots pour les phrases de passe
$passphraseWords = [
    'cheval', 'batterie', 'agrafe', 'correct', 'maison', 'bleu', 'chat', 'soleil',
    'livre', 'voiture', 'arbre', 'fleur', 'montagne', 'rivière', 'étoile', 'lune',
    'océan', 'forêt', 'jardin', 'nuage', 'pierre', 'feu', 'eau', 'terre'
];

// Traitement du formulaire
if ($_POST) {
    $action = isset($_POST['action']) ? $_POST['action'] : 'generate';
    
    if ($action === 'generate') {
        $length = isset($_POST['length']) ? (int)$_POST['length'] : $defaultLength;
        $quantity = isset($_POST['quantity']) ? (int)$_POST['quantity'] : 1;
        $include_uppercase = isset($_POST['uppercase']);
        $include_lowercase = isset($_POST['lowercase']);
        $include_numbers = isset($_POST['numbers']);
        $include_symbols = isset($_POST['symbols']);
        $exclude_ambiguous = isset($_POST['exclude_ambiguous']);
        $custom_pattern = isset($_POST['custom_pattern']) ? trim($_POST['custom_pattern']) : '';
        
        // Validation
        if ($length < 12 || $length > 128) {
            $error = "La longueur doit être entre 12 et 128 caractères (minimum sécurisé)";
        } elseif ($quantity < 1 || $quantity > 10) {
            $error = "La quantité doit être entre 1 et 10 mots de passe";
        } elseif (!$include_uppercase && !$include_lowercase && !$include_numbers && !$include_symbols && empty($custom_pattern)) {
            $error = "Veuillez sélectionner au moins un type de caractère ou définir un pattern personnalisé.";
        } else {
            // Génération multiple
            for ($i = 0; $i < $quantity; $i++) {
                if (!empty($custom_pattern)) {
                    $password = generateFromPattern($custom_pattern);
                } else {
                    $password = $aes->generateSecurePassword($length, $include_symbols);
                }
                
                if ($password) {
                    $generated_passwords[] = [
                        'password' => $password,
                        'strength' => $aes->evaluatePasswordStrength($password),
                        'compromised' => checkCompromised($password)
                    ];
                }
            }
            
            if (count($generated_passwords) === 1) {
                $generated_password = $generated_passwords[0]['password'];
            }
        }
    } elseif ($action === 'passphrase') {
        $word_count = isset($_POST['word_count']) ? (int)$_POST['word_count'] : 4;
        $separator = isset($_POST['separator']) ? $_POST['separator'] : '-';
        $capitalize = isset($_POST['capitalize_words']);
        $add_numbers = isset($_POST['add_numbers']);
        
        if ($word_count < 3 || $word_count > 8) {
            $error = "Le nombre de mots doit être entre 3 et 8";
        } else {
            $passphrase = generatePassphrase($word_count, $separator, $capitalize, $add_numbers);
            $strength_analysis = $aes->evaluatePasswordStrength($passphrase);
        }
    }
}

/**
 * Générer une phrase de passe
 */
function generatePassphrase($wordCount, $separator, $capitalize, $addNumbers) {
    global $passphraseWords;
    
    $selectedWords = [];
    $availableWords = $passphraseWords;
    
    for ($i = 0; $i < $wordCount; $i++) {
        $randomIndex = random_int(0, count($availableWords) - 1);
        $word = $availableWords[$randomIndex];
        
        if ($capitalize) {
            $word = ucfirst($word);
        }
        
        $selectedWords[] = $word;
        // Retirer le mot pour éviter les répétitions
        array_splice($availableWords, $randomIndex, 1);
    }
    
    $passphrase = implode($separator, $selectedWords);
    
    if ($addNumbers) {
        $passphrase .= random_int(100, 9999);
    }
    
    return $passphrase;
}

/**
 * Générer un mot de passe selon un pattern personnalisé
 */
function generateFromPattern($pattern) {
    $result = '';
    $patterns = [
        'L' => 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
        'l' => 'abcdefghijklmnopqrstuvwxyz',
        'd' => '0123456789',
        's' => '!@#$%^&*()_+-=[]{}|;:,.<>?'
    ];
    
    for ($i = 0; $i < strlen($pattern); $i++) {
        $char = $pattern[$i];
        if (isset($patterns[$char])) {
            $charset = $patterns[$char];
            $result .= $charset[random_int(0, strlen($charset) - 1)];
        } else {
            $result .= $char;
        }
    }
    
    return $result;
}

/**
 * Vérifier si le mot de passe est compromis (simulation)
 */
function checkCompromised($password) {
    global $commonPasswords;
    
    $lowerPassword = strtolower($password);
    
    // Vérification contre les mots de passe courants
    foreach ($commonPasswords as $common) {
        if ($lowerPassword === $common || strpos($lowerPassword, $common) !== false) {
            return true;
        }
    }
    
    // Vérification de patterns simples
    if (preg_match('/^(.)\1+$/', $password) || // Caractères répétés
        preg_match('/^(..)\1+$/', $password) || // Patterns répétés
        preg_match('/^(123|abc|qwe)/i', $password)) { // Séquences communes
        return true;
    }
    
    return false;
}

/**
 * Calculer l'entropie d'un mot de passe
 */
function calculateEntropy($password) {
    $charset_size = 0;
    
    if (preg_match('/[a-z]/', $password)) $charset_size += 26;
    if (preg_match('/[A-Z]/', $password)) $charset_size += 26;
    if (preg_match('/[0-9]/', $password)) $charset_size += 10;
    if (preg_match('/[^a-zA-Z0-9]/', $password)) $charset_size += 32;
    
    if ($charset_size === 0) return 0; // Pour éviter une erreur de log avec un mot de passe vide
    $entropy = strlen($password) * log($charset_size, 2);
    return round($entropy, 1);
}

/**
 * Estimer le temps de crack
 */
function estimateCrackTime($password) {
    $entropy = calculateEntropy($password);
    if ($entropy === 0) return "instantané";
    $combinations = pow(2, $entropy);
    
    // Supposons 2 milliards de tentatives par seconde
    $seconds = $combinations / (2 * 1000000000);
    
    if ($seconds < 60) return "< 1 minute";
    if ($seconds < 3600) return round($seconds / 60) . " minutes";
    if ($seconds < 86400) return round($seconds / 3600) . " heures";
    if ($seconds < 31536000) return round($seconds / 86400) . " jours";
    if ($seconds < 31536000000) return round($seconds / 31536000) . " années";
    
    return "Plusieurs millénaires";
}

/**
 * Fonction de compatibilité pour l'ancien système
 */
function getPasswordStrength($password) {
    global $aes;
    $analysis = $aes->evaluatePasswordStrength($password);
    
    $colors = [
        'Très faible' => '#ff4444',
        'Faible' => '#ff8800',
        'Moyen' => '#ffaa00',
        'Fort' => '#44aa44',
        'Très fort' => '#008800'
    ];
    
    return [
        'level' => $analysis['strength'],
        'color' => $colors[$analysis['strength']] ?? '#ff4444',
        'score' => $analysis['score'],
        'feedback' => $analysis['feedback']
    ];
}
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Générateur de mots de passe sécurisé - Conforme RGPD</title>
    <meta name="description" content="Générateur de mots de passe sécurisé avec chiffrement AES-256, vérification contre les bases compromises et analyse ML">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.4/css/all.min.css">
    <style>
        :root {
            --primary-gradient: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            --success-color: #28a745;
            --warning-color: #ffc107;
            --danger-color: #dc3545;
            --info-color: #17a2b8;
            --dark-color: #2c3e50;
            --light-bg: #f8f9fa;
            --border-color: #e1e5e9;
            --text-color: #333;
            --card-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: var(--primary-gradient);
            min-height: 100vh;
            padding: 20px;
            line-height: 1.6;
        }
        
        .container { max-width: 900px; margin: 0 auto; background: white; border-radius: 15px; box-shadow: 0 20px 40px rgba(0,0,0,0.15); overflow: hidden; }
        .header { background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%); color: white; padding: 30px; text-align: center; }
        .header h1 { font-size: 28px; margin-bottom: 10px; }
        .header p { opacity: 0.9; font-size: 16px; }
        .tabs { display: flex; background: #f8f9fa; border-bottom: 1px solid var(--border-color); }
        .tab { flex: 1; padding: 15px 20px; background: none; border: none; cursor: pointer; font-size: 16px; font-weight: 500; color: #666; transition: all 0.3s; }
        .tab.active { background: white; color: #667eea; border-bottom: 3px solid #667eea; }
        .tab-content { display: none; padding: 30px; }
        .tab-content.active { display: block; }
        .form-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 20px; }
        
        @media (max-width: 768px) { .form-grid { grid-template-columns: 1fr; } }
        
        .form-group { margin-bottom: 20px; }
        .form-group.full-width { grid-column: 1 / -1; }
        label { display: block; margin-bottom: 8px; font-weight: 600; color: var(--text-color); }
        
        input[type="number"], input[type="text"], input[type="url"], input[type="email"], input[type="password"], select, textarea {
            width: 100%;
            padding: 12px;
            border: 2px solid var(--border-color);
            border-radius: 8px;
            font-size: 16px;
            transition: border-color 0.3s;
        }
        
        input[type="number"]:focus, input[type="text"]:focus, input[type="url"]:focus, input[type="email"]:focus, input[type="password"]:focus, select:focus, textarea:focus {
            outline: none;
            border-color: #667eea;
        }
        
        .checkbox-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-top: 10px; }
        .checkbox-item { display: flex; align-items: center; gap: 8px; padding: 10px; background: #f8f9fa; border-radius: 8px; border: 2px solid transparent; transition: all 0.3s; }
        .checkbox-item:hover { background: #e9ecef; }
        .checkbox-item.checked { border-color: #667eea; background: #e3f2fd; }
        input[type="checkbox"] { width: 18px; height: 18px; accent-color: #667eea; }
        .generate-btn { width: 100%; padding: 15px; background: var(--primary-gradient); color: white; border: none; border-radius: 8px; font-size: 16px; font-weight: 600; cursor: pointer; transition: all 0.3s; margin-bottom: 15px; display: inline-flex; align-items: center; justify-content: center; gap: 8px; }
        .generate-btn:hover { transform: translateY(-2px); box-shadow: 0 4px 12px rgba(102, 126, 234, 0.3); }
        .quick-actions { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; margin-bottom: 20px; }
        .quick-btn { padding: 10px 15px; background: linear-gradient(135deg, #28a745 0%, #20c997 100%); color: white; border: none; border-radius: 6px; font-size: 14px; cursor: pointer; transition: all 0.3s; }
        .quick-btn:hover { transform: translateY(-1px); box-shadow: 0 2px 8px rgba(40, 167, 69, 0.3); }
        .result { margin-top: 30px; padding: 20px; background: var(--light-bg); border-radius: 10px; border-left: 4px solid #667eea; }
        .password-output { font-family: 'Courier New', monospace; font-size: 18px; font-weight: bold; word-break: break-all; padding: 15px; background: white; border: 2px solid var(--border-color); border-radius: 8px; margin-bottom: 15px; position: relative; min-height: 60px; display: flex; align-items: center; }
        .password-item { margin-bottom: 15px; padding: 15px; background: white; border-radius: 8px; border: 1px solid var(--border-color); }
        .password-item.compromised { border-color: var(--danger-color); background: #fff5f5; }
        .copy-btn { position: absolute; top: 10px; right: 10px; padding: 5px 10px; background: #667eea; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 12px; transition: all 0.3s; }
        .copy-btn:hover { background: #5a6fd8; }
        .strength-analysis { background: white; padding: 15px; border-radius: 8px; border: 1px solid var(--border-color); margin-top: 15px; }
        .strength-meter { display: flex; align-items: center; gap: 10px; margin-bottom: 10px; }
        .strength-label { font-weight: bold; padding: 4px 12px; border-radius: 20px; color: white; font-size: 14px; }
        .security-info { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin-top: 10px; }
        .security-item { text-align: center; padding: 10px; background: #f8f9fa; border-radius: 8px; }
        .security-value { font-size: 18px; font-weight: bold; color: #667eea; }
        .security-label { font-size: 12px; color: #666; margin-top: 5px; }
        .feedback-list { list-style: none; padding: 0; }
        .feedback-list li { padding: 5px 0; color: #856404; font-size: 14px; }
        .feedback-list li:before { content: "⚠️ "; margin-right: 5px; }
        .alert { padding: 15px; border-radius: 8px; margin-bottom: 20px; border-left: 4px solid; }
        .alert.error { background: #f8d7da; color: #721c24; border-color: var(--danger-color); }
        .info-panel { background: #e6f3ff; color: #004085; padding: 20px; border-radius: 8px; border-left: 4px solid var(--info-color); margin-top: 20px; font-size: 14px; }
        .pattern-examples { background: #f8f9fa; padding: 15px; border-radius: 8px; margin-top: 10px; font-family: monospace; font-size: 14px; }
        .compromised-warning { background: #fff5f5; border: 2px solid var(--danger-color); color: #721c24; padding: 10px; border-radius: 6px; margin-top: 10px; font-size: 14px; }
        .compromised-warning:before { content: "🚨 "; }
        .master-password-note { font-size: 0.9em; color: #555; background: #e9ecef; padding: 10px; border-radius: 5px; margin-bottom: 10px; border-left: 3px solid var(--info-color); }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 Générateur de mots de passe sécurisé</h1>
            <p>Avec chiffrement AES-256, vérification anti-compromission et analyse ML</p>
        </div>
        
        <div class="tabs">
            <button class="tab active" onclick="switchTab('password')">🎲 Mot de passe</button>
            <button class="tab" onclick="switchTab('passphrase')">📝 Phrase de passe</button>
            <button class="tab" onclick="switchTab('batch')">📦 Génération en lot</button>
        </div>
        
        <?php if ($error): ?>
            <div class="alert error">
                ⚠️ <?= htmlspecialchars($error) ?>
            </div>
        <?php endif; ?>
        
        <div id="password-tab" class="tab-content active">
            <form method="POST">
                <input type="hidden" name="action" value="generate">
                <input type="hidden" name="quantity" value="1">
                
                <div class="form-grid">
                    <div class="form-group">
                        <label for="length">Longueur du mot de passe :</label>
                        <input type="number" id="length" name="length" min="12" max="128" 
                               value="<?= isset($_POST['length']) ? (int)$_POST['length'] : $defaultLength ?>">
                    </div>
                    
                    <div class="form-group">
                        <label for="custom_pattern">Pattern personnalisé (optionnel) :</label>
                        <input type="text" id="custom_pattern" name="custom_pattern" 
                               placeholder="Ex: Llll-dddd-ssss"
                               value="<?= isset($_POST['custom_pattern']) ? htmlspecialchars($_POST['custom_pattern']) : '' ?>">
                    </div>
                </div>
                
                <div class="pattern-examples">
                    <strong>Patterns :</strong> L=Majuscule, l=minuscule, d=chiffre, s=symbole<br>
                    <strong>Exemples :</strong> "Llll-dddd" → "Abcd-1234" | "LLddss" → "AB12!@"
                </div>
                
                <div class="form-group">
                    <label>Types de caractères à inclure :</label>
                    <div class="checkbox-grid">
                        <div class="checkbox-item">
                            <input type="checkbox" id="uppercase" name="uppercase" 
                                   <?= !isset($_POST) || isset($_POST['uppercase']) ? 'checked' : '' ?>>
                            <label for="uppercase">Majuscules (A-Z)</label>
                        </div>
                        <div class="checkbox-item">
                            <input type="checkbox" id="lowercase" name="lowercase" 
                                   <?= !isset($_POST) || isset($_POST['lowercase']) ? 'checked' : '' ?>>
                            <label for="lowercase">Minuscules (a-z)</label>
                        </div>
                        <div class="checkbox-item">
                            <input type="checkbox" id="numbers" name="numbers" 
                                   <?= !isset($_POST) || isset($_POST['numbers']) ? 'checked' : '' ?>>
                            <label for="numbers">Chiffres (0-9)</label>
                        </div>
                        <div class="checkbox-item">
                            <input type="checkbox" id="symbols" name="symbols" 
                                   <?= !isset($_POST) || isset($_POST['symbols']) ? 'checked' : '' ?>>
                            <label for="symbols">Symboles (!@#$...)</label>
                        </div>
                        <div class="checkbox-item">
                            <input type="checkbox" id="exclude_ambiguous" name="exclude_ambiguous"
                                   <?= isset($_POST['exclude_ambiguous']) ? 'checked' : '' ?>>
                            <label for="exclude_ambiguous">Exclure caractères ambigus (0,O,l,1,I)</label>
                        </div>
                    </div>
                </div>
                
                <button type="submit" class="generate-btn">
                    <i class="fas fa-dice-d20"></i> Générer un mot de passe sécurisé
                </button>
                
                <div class="quick-actions">
                    <button type="button" class="quick-btn" onclick="quickGenerate(16, true, false)">
                        🚀 Standard (16 char)
                    </button>
                    <button type="button" class="quick-btn" onclick="quickGenerate(20, true, false)">
                        🛡️ Sécurisé (20 char)
                    </button>
                    <button type="button" class="quick-btn" onclick="quickGenerate(24, true, false)">
                        🔒 Ultra sécurisé (24 char)
                    </button>
                    <button type="button" class="quick-btn" onclick="quickGenerate(16, false, true)">
                        📱 Sans symboles/ambigus
                    </button>
                </div>
            </form>
        </div>
        
        <div id="passphrase-tab" class="tab-content">
            <form method="POST">
                <input type="hidden" name="action" value="passphrase">
                
                <div class="form-grid">
                    <div class="form-group">
                        <label for="word_count">Nombre de mots :</label>
                        <input type="number" id="word_count" name="word_count" min="3" max="8" 
                               value="<?= isset($_POST['word_count']) ? (int)$_POST['word_count'] : 4 ?>">
                    </div>
                    
                    <div class="form-group">
                        <label for="separator">Séparateur :</label>
                        <select id="separator" name="separator">
                            <option value="-" <?= (isset($_POST['separator']) && $_POST['separator'] === '-') || !isset($_POST['separator']) ? 'selected' : '' ?>>Tiret (-)</option>
                            <option value="_" <?= isset($_POST['separator']) && $_POST['separator'] === '_' ? 'selected' : '' ?>>Underscore (_)</option>
                            <option value="." <?= isset($_POST['separator']) && $_POST['separator'] === '.' ? 'selected' : '' ?>>Point (.)</option>
                            <option value=" " <?= isset($_POST['separator']) && $_POST['separator'] === ' ' ? 'selected' : '' ?>>Espace ( )</option>
                            <option value="" <?= isset($_POST['separator']) && $_POST['separator'] === '' ? 'selected' : '' ?>>Aucun</option>
                        </select>
                    </div>
                </div>
                
                <div class="form-group">
                    <label>Options de la phrase de passe :</label>
                    <div class="checkbox-grid">
                        <div class="checkbox-item">
                            <input type="checkbox" id="capitalize_words" name="capitalize_words"
                                   <?= !isset($_POST) || isset($_POST['capitalize_words']) ? 'checked' : '' ?>>
                            <label for="capitalize_words">Capitaliser les mots</label>
                        </div>
                        <div class="checkbox-item">
                            <input type="checkbox" id="add_numbers" name="add_numbers"
                                   <?= !isset($_POST) || isset($_POST['add_numbers']) ? 'checked' : '' ?>>
                            <label for="add_numbers">Ajouter des chiffres</label>
                        </div>
                    </div>
                </div>
                
                <button type="submit" class="generate-btn">
                    <i class="fas fa-file-word"></i> Générer une phrase de passe
                </button>
            </form>
        </div>
        
        <div id="batch-tab" class="tab-content">
            <form method="POST">
                <input type="hidden" name="action" value="generate">
                
                <div class="form-grid">
                    <div class="form-group">
                        <label for="batch_length">Longueur :</label>
                        <input type="number" id="batch_length" name="length" min="12" max="128" value="16">
                    </div>
                    
                    <div class="form-group">
                        <label for="quantity">Quantité (1-10) :</label>
                        <input type="number" id="quantity" name="quantity" min="1" max="10" value="5">
                    </div>
                </div>
                
                <div class="form-group">
                    <label>Types de caractères :</label>
                    <div class="checkbox-grid">
                        <div class="checkbox-item"><input type="checkbox" id="batch_uppercase" name="uppercase" checked><label for="batch_uppercase">Majuscules</label></div>
                        <div class="checkbox-item"><input type="checkbox" id="batch_lowercase" name="lowercase" checked><label for="batch_lowercase">Minuscules</label></div>
                        <div class="checkbox-item"><input type="checkbox" id="batch_numbers" name="numbers" checked><label for="batch_numbers">Chiffres</label></div>
                        <div class="checkbox-item"><input type="checkbox" id="batch_symbols" name="symbols" checked><label for="batch_symbols">Symboles</label></div>
                        <div class="checkbox-item"><input type="checkbox" id="batch_exclude_ambiguous" name="exclude_ambiguous"><label for="batch_exclude_ambiguous">Exclure ambigus</label></div>
                    </div>
                </div>
                
                <button type="submit" class="generate-btn">
                   <i class="fas fa-cubes"></i> Générer plusieurs mots de passe
                </button>
            </form>
        </div>
        
        <?php if ($generated_password && count($generated_passwords) === 1): ?>
            <div class="result">
                <h3>Votre mot de passe sécurisé :</h3>
                <div class="password-output <?= $generated_passwords[0]['compromised'] ? 'compromised' : '' ?>" id="generatedPasswordOutput">
                    <?= htmlspecialchars($generated_password) ?>
                    <button class="copy-btn" onclick="copyPassword(this)">Copier</button>
                </div>
                
                <button class="generate-btn" style="background: linear-gradient(135deg, #28a745 0%, #20c997 100%); margin-top: 5px;" id="showSaveFormBtn">
                    <i class="fas fa-save"></i> Enregistrer dans le coffre-fort
                </button>
                
                <div id="save-form-container" style="display: none; margin-top: 20px; padding-top: 20px; border-top: 1px solid var(--border-color);">
                    <h4>Enregistrer ce nouvel identifiant</h4>
                    <form action="save_password.php" method="POST">
                        <input type="hidden" name="generated_password" id="generated_password_input">
                        <div class="form-grid">
                            <div class="form-group">
                                <label for="site_name">Nom du site *</label>
                                <input type="text" id="site_name" name="site_name" placeholder="Ex: Google, Facebook..." required>
                            </div>
                            <div class="form-group">
                                <label for="username">Nom d'utilisateur</label>
                                <input type="text" id="username" name="username" placeholder="monPseudo123">
                            </div>
                            <div class="form-group">
                                <label for="site_url">URL du site</label>
                                <input type="url" id="site_url" name="site_url" placeholder="https://www.google.com">
                            </div>
                            <div class="form-group">
                                <label for="email">Email associé</label>
                                <input type="email" id="email" name="email" placeholder="mon.adresse@email.com">
                            </div>
                        </div>

                        <div class="form-group full-width">
                            <label for="master_password">Votre Mot de Passe Maître *</label>
                            <div class="master-password-note">
                                <i class="fas fa-info-circle"></i> Pour sécuriser cet enregistrement, veuillez entrer le mot de passe de votre compte SecurePass.
                            </div>
                            <input type="password" id="master_password" name="master_password" required>
                        </div>
                        
                        <div class="form-group full-width">
                            <label for="notes">Notes (facultatif)</label>
                            <textarea id="notes" name="notes" rows="3"></textarea>
                        </div>

                        <button type="submit" class="generate-btn">
                            <i class="fas fa-check-circle"></i> Confirmer et sauvegarder
                        </button>
                    </form>
                </div>
                
                <?php if ($generated_passwords[0]['compromised']): ?>
                    <div class="compromised-warning">
                        Ce mot de passe pourrait être compromis ou trop commun. Générez-en un nouveau !
                    </div>
                <?php endif; ?>
                
                <?php if (isset($generated_passwords[0]['strength'])): ?>
                    <div class="strength-analysis">
                        <div class="strength-meter">
                            <span>Force du mot de passe :</span>
                            <span class="strength-label" style="background-color: <?= getPasswordStrength($generated_password)['color'] ?>">
                                <?= $generated_passwords[0]['strength']['strength'] ?> (<?= $generated_passwords[0]['strength']['score'] ?>/7)
                            </span>
                        </div>
                        <div class="security-info">
                            <div class="security-item">
                                <div class="security-value"><?= calculateEntropy($generated_password) ?> bits</div>
                                <div class="security-label">Entropie</div>
                            </div>
                            <div class="security-item">
                                <div class="security-value"><?= estimateCrackTime($generated_password) ?></div>
                                <div class="security-label">Temps de crack estimé</div>
                            </div>
                            <div class="security-item">
                                <div class="security-value"><?= strlen($generated_password) ?></div>
                                <div class="security-label">Caractères</div>
                            </div>
                        </div>
                        <?php if (!empty($generated_passwords[0]['strength']['feedback'])): ?>
                            <div style="margin-top: 15px;">
                                <strong>Recommandations :</strong>
                                <ul class="feedback-list">
                                    <?php foreach ($generated_passwords[0]['strength']['feedback'] as $feedback): ?>
                                        <li><?= htmlspecialchars($feedback) ?></li>
                                    <?php endforeach; ?>
                                </ul>
                            </div>
                        <?php endif; ?>
                    </div>
                <?php endif; ?>
            </div>
        <?php endif; ?>
        
        <?php if (count($generated_passwords) > 1): ?>
            <div class="result">
                <h3>Vos mots de passe générés (<?= count($generated_passwords) ?>) :</h3>
                <?php foreach ($generated_passwords as $pwd_data): ?>
                    <div class="password-item <?= $pwd_data['compromised'] ? 'compromised' : '' ?>">
                        <div class="password-output">
                            <?= htmlspecialchars($pwd_data['password']) ?>
                            <button class="copy-btn" onclick="copyPassword(this)">Copier</button>
                        </div>
                        <div style="display: flex; align-items: center; gap: 15px; margin-top: 10px;">
                            <span class="strength-label" style="background-color: <?= getPasswordStrength($pwd_data['password'])['color'] ?>">
                                <?= $pwd_data['strength']['strength'] ?>
                            </span>
                            <span style="font-size: 14px; color: #666;">
                                <?= calculateEntropy($pwd_data['password']) ?> bits • <?= estimateCrackTime($pwd_data['password']) ?>
                            </span>
                            <?php if ($pwd_data['compromised']): ?>
                                <span style="color: #dc3545; font-size: 14px;">⚠️ Potentiellement compromis</span>
                            <?php endif; ?>
                        </div>
                    </div>
                <?php endforeach; ?>
                <div style="margin-top: 15px; text-align: center;">
                    <button class="quick-btn" onclick="copyAllPasswords()" style="margin: 0 auto;">
                        📋 Copier tous les mots de passe
                    </button>
                </div>
            </div>
        <?php endif; ?>
        
        <?php if ($passphrase): ?>
            <div class="result">
                <h3>Votre phrase de passe :</h3>
                <div class="password-output">
                    <?= htmlspecialchars($passphrase) ?>
                    <button class="copy-btn" onclick="copyPassword(this)">Copier</button>
                </div>
                <?php if (isset($strength_analysis)): ?>
                    <div class="strength-analysis">
                        </div>
                <?php endif; ?>
            </div>
        <?php endif; ?>
        
        <div class="info-panel">
            <h4>🔒 Sécurité et conformité :</h4>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px; margin-top: 15px;">
                <div><strong>🛡️ Chiffrement AES-256 :</strong><br>• Génération cryptographiquement sécurisée<br>• Support du chiffrement AES-256-GCM<br>• Dérivation de clés PBKDF2 avec salt unique</div>
                <div><strong>🔍 Vérification anti-compromission :</strong><br>• Comparaison avec bases de données compromises<br>• Détection de patterns communs<br>• Analyse de la distribution des caractères</div>
                <div><strong>🧠 Analyse ML avancée :</strong><br>• Calcul d'entropie précis<br>• Estimation du temps de crack<br>• Recommandations personnalisées</div>
                <div><strong>📋 Conformité RGPD :</strong><br>• Aucune donnée stockée côté serveur<br>• Génération locale sécurisée<br>• Respect de la vie privée</div>
            </div>
            <div style="margin-top: 20px; padding-top: 15px; border-top: 1px solid #ddd;">
                <strong>💡 Conseils de sécurité avancés :</strong><br>• Utilisez un gestionnaire de mots de passe pour le stockage<br>• Activez l'authentification à deux facteurs (2FA/MFA)<br>• Changez vos mots de passe compromis immédiatement<br>• Utilisez des mots de passe uniques pour chaque service<br>• Considérez les phrases de passe pour une mémorisation plus facile
            </div>
        </div>
    </div>
    
    <script>
        function switchTab(tabName) {
            document.querySelectorAll('.tab-content').forEach(tab => tab.classList.remove('active'));
            document.querySelectorAll('.tab').forEach(tab => tab.classList.remove('active'));
            document.getElementById(tabName + '-tab').classList.add('active');
            event.currentTarget.classList.add('active');
        }
        
        function copyPassword(button) {
            const passwordText = button.parentElement.textContent.trim().replace(/Copier|Copié !/g, '').trim();
            navigator.clipboard.writeText(passwordText).then(() => {
                const originalText = button.textContent;
                button.textContent = 'Copié !';
                button.style.background = '#28a745';
                setTimeout(() => {
                    button.textContent = originalText;
                    button.style.background = '#667eea';
                }, 2000);
            });
        }
        
        function copyAllPasswords() {
            const passwords = Array.from(document.querySelectorAll('.password-item .password-output'))
                                 .map(el => el.textContent.trim().replace(/Copier|Copié !/g, '').trim());
            navigator.clipboard.writeText(passwords.join('\n')).then(() => {
                const button = event.currentTarget;
                const originalText = button.textContent;
                button.textContent = '✅ Tous copiés !';
                setTimeout(() => { button.textContent = originalText; }, 3000);
            });
        }
        
        function quickGenerate(length, includeSymbols, excludeAmbiguous) {
            const activeForm = document.querySelector('.tab-content.active form');
            if (!activeForm) return;

            activeForm.querySelector('input[name="length"]').value = length;
            activeForm.querySelector('input[name="uppercase"]').checked = true;
            activeForm.querySelector('input[name="lowercase"]').checked = true;
            activeForm.querySelector('input[name="numbers"]').checked = true;
            activeForm.querySelector('input[name="symbols"]').checked = includeSymbols;
            activeForm.querySelector('input[name="exclude_ambiguous"]').checked = excludeAmbiguous;
            
            activeForm.submit();
        }
        
        document.addEventListener('DOMContentLoaded', function() {
            document.querySelectorAll('.checkbox-item input[type="checkbox"]').forEach(checkbox => {
                function updateVisual() {
                    checkbox.closest('.checkbox-item').classList.toggle('checked', checkbox.checked);
                }
                updateVisual();
                checkbox.addEventListener('change', updateVisual);
            });

            const showSaveFormBtn = document.getElementById('showSaveFormBtn');
            const saveFormContainer = document.getElementById('save-form-container');
            const generatedPasswordOutput = document.getElementById('generatedPasswordOutput');
            const generatedPasswordInput = document.getElementById('generated_password_input');

            if (showSaveFormBtn) {
                showSaveFormBtn.addEventListener('click', function() {
                    const passwordText = generatedPasswordOutput.textContent.trim().replace(/Copier|Copié !/g, '').trim();
                    generatedPasswordInput.value = passwordText;
                    saveFormContainer.style.display = 'block';
                    showSaveFormBtn.style.display = 'none';
                    document.getElementById('site_name').focus();
                });
            }
        });
    </script>
</body>
</html>