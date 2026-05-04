<?php
session_start();

// [CORRECTION] Connexion à la base de données via votre fichier de configuration standard
require_once __DIR__ . '/../config/database.php';

// Headers de sécurité
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('X-XSS-Protection: 1; mode=block');
header('Referrer-Policy: strict-origin-when-cross-origin');
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com; font-src 'self' https://cdnjs.cloudflare.com https://fonts.gstatic.com; img-src 'self' data:;");

// Vérifier si l'utilisateur est connecté
if (!isset($_SESSION['user_id']) || !$_SESSION['user_id']) {
    $_SESSION['error_message'] = "Veuillez vous connecter pour accéder au tableau de bord.";
    header('Location: ../login.php');
    exit();
}

$user_id = $_SESSION['user_id'];

// --- RÉCUPÉRATION DES DONNÉES DE L'UTILISATEUR AVEC MYSQLI ---
$stmt = mysqli_prepare($link, "SELECT prenom FROM users WHERE id = ?");
mysqli_stmt_bind_param($stmt, "i", $user_id);
mysqli_stmt_execute($stmt);
$user = mysqli_fetch_assoc(mysqli_stmt_get_result($stmt));
$username = $user ? $user['prenom'] : 'Utilisateur';
$_SESSION['username'] = $username;
mysqli_stmt_close($stmt);

// --- CALCUL DES STATISTIQUES AVEC MYSQLI ---
// 1. Score de sécurité basé sur la table `saved_passwords`
$security_score = 0;
$sql_score = "SELECT AVG(strength_score) as avg_score FROM saved_passwords WHERE user_id = ?";
$stmt_score = mysqli_prepare($link, $sql_score);
if ($stmt_score) {
    mysqli_stmt_bind_param($stmt_score, "i", $user_id);
    if (mysqli_stmt_execute($stmt_score)) {
        $result_score = mysqli_stmt_get_result($stmt_score);
        $score_data = mysqli_fetch_assoc($result_score);
        // Conversion du score (max 7) en pourcentage (0-100)
        if ($score_data && !is_null($score_data['avg_score'])) {
            $security_score = ($score_data['avg_score'] / 7) * 100;
        }
    }
    mysqli_stmt_close($stmt_score);
}


// 2. Nombre total de mots de passe
$sql_total = "SELECT COUNT(*) as total FROM saved_passwords WHERE user_id = ?";
$stmt_total = mysqli_prepare($link, $sql_total);
mysqli_stmt_bind_param($stmt_total, "i", $user_id);
mysqli_stmt_execute($stmt_total);
$total_passwords = mysqli_fetch_assoc(mysqli_stmt_get_result($stmt_total))['total'] ?? 0;
mysqli_stmt_close($stmt_total);

// 3. Nombre de mots de passe faibles (basé sur le score)
$sql_weak = "SELECT COUNT(*) as weak_total FROM saved_passwords WHERE user_id = ? AND strength_score <= 2";
$stmt_weak = mysqli_prepare($link, $sql_weak);
mysqli_stmt_bind_param($stmt_weak, "i", $user_id);
mysqli_stmt_execute($stmt_weak);
$weak_passwords_count = mysqli_fetch_assoc(mysqli_stmt_get_result($stmt_weak))['weak_total'] ?? 0;
mysqli_stmt_close($stmt_weak);

// [AJOUT] Récupération de la liste des mots de passe faibles pour la section Analyse
$weak_passwords_list = [];
if ($weak_passwords_count > 0) {
    $sql_weak_list = "SELECT id, site_name, username, email FROM saved_passwords WHERE user_id = ? AND strength_score <= 2 ORDER BY site_name";
    $stmt_weak_list = mysqli_prepare($link, $sql_weak_list);
    mysqli_stmt_bind_param($stmt_weak_list, "i", $user_id);
    mysqli_stmt_execute($stmt_weak_list);
    $weak_passwords_list = mysqli_fetch_all(mysqli_stmt_get_result($stmt_weak_list), MYSQLI_ASSOC);
    mysqli_stmt_close($stmt_weak_list);
}


// 4. Nombre de mots de passe compromis (placeholder)
$compromised_count = 0; 
// [AJOUT] Liste des mots de passe compromis (placeholder pour une future intégration API)
$compromised_passwords_list = [];

// 5. Nombre de doublons (groupes de mots de passe identiques)
$sql_duplicates = "SELECT COUNT(DISTINCT password_encrypted) FROM saved_passwords WHERE user_id = ? AND password_encrypted IN (SELECT password_encrypted FROM saved_passwords WHERE user_id = ? GROUP BY password_encrypted HAVING COUNT(*) > 1)";
$stmt_duplicates_count = mysqli_prepare($link, $sql_duplicates);
mysqli_stmt_bind_param($stmt_duplicates_count, "ii", $user_id, $user_id);
mysqli_stmt_execute($stmt_duplicates_count);
$duplicate_groups_count = mysqli_fetch_row(mysqli_stmt_get_result($stmt_duplicates_count))[0] ?? 0;
mysqli_stmt_close($stmt_duplicates_count);

// [AJOUT] Récupération de la liste des doublons
$duplicate_passwords_list = [];
if ($duplicate_groups_count > 0) {
    $sql_duplicates_list = "
        SELECT id, site_name, username, email, password_encrypted
        FROM saved_passwords
        WHERE user_id = ? AND password_encrypted IN (
            SELECT password_encrypted FROM saved_passwords WHERE user_id = ? GROUP BY password_encrypted HAVING COUNT(*) > 1
        )
        ORDER BY password_encrypted, site_name";
    $stmt_duplicates_list = mysqli_prepare($link, $sql_duplicates_list);
    mysqli_stmt_bind_param($stmt_duplicates_list, "ii", $user_id, $user_id);
    mysqli_stmt_execute($stmt_duplicates_list);
    $duplicate_passwords_list = mysqli_fetch_all(mysqli_stmt_get_result($stmt_duplicates_list), MYSQLI_ASSOC);
    mysqli_stmt_close($stmt_duplicates_list);
}


// 6. Mots de passe anciens
$sql_old = "SELECT COUNT(*) as old_total FROM saved_passwords WHERE user_id = ? AND updated_at < DATE_SUB(NOW(), INTERVAL 6 MONTH)";
$stmt_old = mysqli_prepare($link, $sql_old);
mysqli_stmt_bind_param($stmt_old, "i", $user_id);
mysqli_stmt_execute($stmt_old);
$old_passwords_count = mysqli_fetch_assoc(mysqli_stmt_get_result($stmt_old))['old_total'] ?? 0;
mysqli_stmt_close($stmt_old);

// [AJOUT] Récupération de la liste des mots de passe anciens
$old_passwords_list = [];
if ($old_passwords_count > 0) {
    $sql_old_list = "SELECT id, site_name, username, email, updated_at FROM saved_passwords WHERE user_id = ? AND updated_at < DATE_SUB(NOW(), INTERVAL 6 MONTH) ORDER BY updated_at ASC";
    $stmt_old_list = mysqli_prepare($link, $sql_old_list);
    mysqli_stmt_bind_param($stmt_old_list, "i", $user_id);
    mysqli_stmt_execute($stmt_old_list);
    $old_passwords_list = mysqli_fetch_all(mysqli_stmt_get_result($stmt_old_list), MYSQLI_ASSOC);
    mysqli_stmt_close($stmt_old_list);
}


// --- RÉCUPÉRATION DES MOTS DE PASSE RÉCENTS ---
$recent_passwords = [];
$sql_recent = "SELECT site_name, site_url, username, updated_at FROM saved_passwords WHERE user_id = ? ORDER BY updated_at DESC LIMIT 5";
$stmt_recent = mysqli_prepare($link, $sql_recent);
mysqli_stmt_bind_param($stmt_recent, "i", $user_id);
if(mysqli_stmt_execute($stmt_recent)) {
    $result_recent = mysqli_stmt_get_result($stmt_recent);
    $recent_passwords = mysqli_fetch_all($result_recent, MYSQLI_ASSOC);
}
mysqli_stmt_close($stmt_recent);

function format_time_ago($date_string) {
    if (is_null($date_string)) return 'jamais';
    $date = new DateTime($date_string);
    $now = new DateTime();
    $interval = $now->diff($date);
    if ($interval->y > 0) return 'il y a ' . $interval->y . ' an(s)';
    if ($interval->m > 0) return 'il y a ' . $interval->m . ' mois';
    if ($interval->d > 0) return 'il y a ' . $interval->d . ' jour(s)';
    if ($interval->h > 0) return 'il y a ' . $interval->h . ' heure(s)';
    if ($interval->i > 0) return 'il y a ' . $interval->i . ' minute(s)';
    return 'à l\'instant';
}

// [AJOUT] Fonction pour afficher la force du mot de passe (reprise de vault.php)
function get_strength_display($score) {
    $score = $score ?? 0;
    if ($score >= 6) return ['label' => 'Très Fort', 'color' => '#38a169', 'icon' => 'fa-shield-alt'];
    if ($score >= 5) return ['label' => 'Fort', 'color' => 'var(--success-color)', 'icon' => 'fa-check-circle'];
    if ($score >= 3) return ['label' => 'Moyen', 'color' => 'var(--warning-color)', 'icon' => 'fa-exclamation-circle'];
    return ['label' => 'Faible', 'color' => 'var(--danger-color)', 'icon' => 'fa-exclamation-triangle'];
}

?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="Tableau de bord SecurePass - Gérez vos mots de passe en toute sécurité.">
    <title>Tableau de bord - SecurePass</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        :root {
            --primary-color: #667eea; --secondary-color: #764ba2; --success-color: #48bb78;
            --error-color: #f56565; --danger-color: #f56565; --warning-color: #ed8936;
            --text-primary: #2d3748; --text-secondary: #718096; --bg-light: #f7fafc;
            --bg-white: #ffffff; --border-color: #e2e8f0; --shadow-sm: 0 1px 3px rgba(0, 0, 0, 0.05);
            --shadow-md: 0 4px 6px rgba(0, 0, 0, 0.05); --shadow-lg: 0 10px 15px rgba(0, 0, 0, 0.05);
            --radius: 12px; --sidebar-width: 280px;
        }
        body.dark-mode {
            --text-primary: #f7fafc; --text-secondary: #a0aec0; --bg-light: #1a202c;
            --bg-white: #2d3748; --border-color: #4a5568;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Inter', sans-serif; background-color: var(--bg-light); color: var(--text-primary); display: flex; min-height: 100vh; transition: background-color 0.3s ease, color 0.3s ease; }
        .sidebar { width: var(--sidebar-width); background: var(--bg-white); border-right: 1px solid var(--border-color); display: flex; flex-direction: column; position: fixed; height: 100vh; left: 0; top: 0; z-index: 1000; transition: transform 0.3s ease; }
        .sidebar-header { padding: 2rem; border-bottom: 1px solid var(--border-color); }
        .brand-logo { display: flex; align-items: center; gap: 0.75rem; font-size: 1.5rem; font-weight: 800; color: var(--primary-color); }
        .sidebar-menu { list-style: none; padding: 1rem 0; margin: 0; flex-grow: 1; }
        .menu-item { margin-bottom: 0.5rem; }
        .menu-item a { display: flex; align-items: center; gap: 1rem; padding: 1rem 2rem; color: var(--text-secondary); text-decoration: none; transition: all 0.3s ease; border-left: 4px solid transparent; cursor: pointer; }
        .menu-item a:hover { color: var(--primary-color); background: var(--bg-light); }
        .menu-item.active a { color: var(--primary-color); border-left-color: var(--primary-color); font-weight: 600; background: var(--bg-light); }
        .sidebar-footer { padding: 1.5rem; border-top: 1px solid var(--border-color); }
        .main-content { flex: 1; margin-left: var(--sidebar-width); padding: 2rem; max-width: calc(100vw - var(--sidebar-width)); }
        .dashboard-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 2rem; }
        .dashboard-header h1 { font-size: 2rem; font-weight: 800; }
        .dashboard-header p { color: var(--text-secondary); }
        .header-actions { display: flex; gap: 1rem; align-items: center; }
        .btn { padding: 0.75rem 1.5rem; border-radius: 8px; border: none; font-weight: 600; cursor: pointer; transition: all 0.3s ease; display: inline-flex; align-items: center; gap: 0.5rem; text-decoration: none; font-size: 0.9rem; }
        .btn-primary { background: linear-gradient(45deg, var(--primary-color), var(--secondary-color)); color: white; box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4); }
        .btn-primary:hover { transform: translateY(-2px); box-shadow: 0 8px 25px rgba(102, 126, 234, 0.6); }
        .btn-secondary { background: var(--bg-white); color: var(--text-primary); border: 1px solid var(--border-color); }
        .btn-secondary:hover { background: var(--bg-light); }
        .btn-danger { background: var(--danger-color); color: white; }
        .btn-warning { background: var(--warning-color); color: white; }
        .btn-sm { padding: 0.5rem 1rem; font-size: 0.8rem; }
        .theme-toggle { background: var(--bg-white); border: 1px solid var(--border-color); border-radius: 8px; padding: 0.75rem; cursor: pointer; color: var(--text-secondary); }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 1.5rem; margin-bottom: 2rem; }
        .stat-card { background: var(--bg-white); padding: 1.5rem; border-radius: var(--radius); box-shadow: var(--shadow-md); border: 1px solid var(--border-color); display: flex; align-items: center; gap: 1.5rem; }
        .stat-icon { width: 50px; height: 50px; border-radius: 10px; display: flex; align-items: center; justify-content: center; font-size: 1.5rem; color: white; }
        .stat-icon.security-strong { background: linear-gradient(45deg, var(--success-color), #38a169); }
        .stat-icon.passwords { background: linear-gradient(45deg, var(--primary-color), var(--secondary-color)); }
        .stat-icon.compromised { background: linear-gradient(45deg, var(--danger-color), #e53e3e); }
        .stat-icon.duplicates { background: linear-gradient(45deg, var(--warning-color), #dd6b20); }
        .stat-content h3 { font-size: 0.9rem; color: var(--text-secondary); margin-bottom: 0.5rem; }
        .stat-value { font-size: 1.8rem; font-weight: 800; }
        .generator-section { margin-bottom: 2rem; }
        .section-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem; }
        .section-header h2 { font-size: 1.5rem; font-weight: 700; }
        .generator-card { background: var(--bg-white); padding: 2rem; border-radius: var(--radius); box-shadow: var(--shadow-md); border: 1px solid var(--border-color); }
        .generated-password-container { display: flex; align-items: center; gap: 1rem; margin-bottom: 1.5rem; }
        #generatedPassword { flex-grow: 1; font-size: 1.5rem; font-weight: 600; padding: 1rem; border: 1px solid var(--border-color); background-color: var(--bg-light); border-radius: 8px; color: var(--text-primary); text-align: center; letter-spacing: 2px; font-family: monospace; }
        .generator-actions { display: flex; gap: 0.5rem; }
        .generator-controls { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1.5rem; margin-top: 1.5rem; }
        .control-group { display: flex; flex-direction: column; gap: 1rem; }
        .length-control { display: flex; flex-direction: column; gap: 0.5rem; }
        .length-label { display: flex; justify-content: space-between; font-weight: 500; font-size: 0.9rem; }
        #passwordLength { width: 100%; cursor: pointer; }
        .checkbox-group label { display: flex; align-items: center; gap: 0.75rem; cursor: pointer; user-select: none; font-weight: 500; }
        .strength-meter { margin-top: 1rem; }
        #strength-bar { width: 100%; height: 8px; background-color: var(--border-color); border-radius: 4px; overflow: hidden; margin-bottom: 0.5rem; }
        #strength-bar-fill { height: 100%; width: 0%; background-color: var(--danger-color); transition: width 0.3s ease, background-color 0.3s ease; }
        #strength-text { font-size: 0.9rem; font-weight: 600; }
        .passwords-section, .security-alerts { margin-bottom: 2rem; }
        .passwords-grid { display: flex; flex-direction: column; gap: 1rem; }
        .empty-state { text-align: center; padding: 2rem; background: var(--bg-white); border-radius: var(--radius); border: 1px dashed var(--border-color); margin-top: 1rem; }
        .password-item { background: var(--bg-white); padding: 1rem 1.5rem; border-radius: var(--radius); border: 1px solid var(--border-color); display: flex; align-items: center; gap: 1rem; transition: all 0.3s ease; }
        .password-item:hover { box-shadow: var(--shadow-lg); transform: translateY(-3px); }
        .password-icon { width: 40px; height: 40px; border-radius: 8px; background: var(--bg-light); display: flex; align-items: center; justify-content: center; font-size: 1.2rem; color: var(--primary-color); }
        .password-info { flex: 1; }
        .password-info h4 { font-weight: 600; margin-bottom: 0.25rem; }
        .last-updated { font-size: 0.7rem; color: var(--text-secondary); }
        .alerts-list { display: flex; flex-direction: column; gap: 1rem; }
        .alert-item { background: var(--bg-white); padding: 1.5rem; border-radius: var(--radius); border: 1px solid var(--border-color); display: flex; align-items: center; gap: 1rem; }
        .alert-item.critical { border-left: 4px solid var(--danger-color); }
        .alert-item.warning { border-left: 4px solid var(--warning-color); }
        
        /* Styles pour la section Analyse de Sécurité */
        .security-analysis-card { background: var(--bg-white); border-radius: var(--radius); border: 1px solid var(--border-color); margin-bottom: 1.5rem; }
        .security-analysis-header { padding: 1.5rem; border-bottom: 1px solid var(--border-color); display: flex; align-items: center; gap: 1rem; }
        .security-analysis-header h3 { font-size: 1.2rem; font-weight: 700; margin: 0; }
        .security-analysis-header .badge { padding: 0.3rem 0.8rem; border-radius: 20px; font-size: 0.8rem; font-weight: 600; color: white; }
        .security-analysis-body { padding: 1.5rem; }
        .security-analysis-body p { color: var(--text-secondary); margin-bottom: 1rem; }
        .analysis-item-list { display: flex; flex-direction: column; gap: 0.75rem; }
        .analysis-item { display: flex; align-items: center; gap: 1rem; padding: 0.75rem; border-radius: 8px; background-color: var(--bg-light); }
        .analysis-item .password-info { flex-grow: 1; }
        .duplicate-group { margin-bottom: 1rem; padding: 1rem; border: 1px solid var(--border-color); border-radius: var(--radius); }
        .duplicate-group .analysis-item { background-color: var(--bg-white); }
        .duplicate-group:last-child { margin-bottom: 0; }

        .notification-container { position: fixed; top: 1.5rem; right: 1.5rem; z-index: 2000; display: flex; flex-direction: column; gap: 0.75rem; }
        .notification { background: var(--bg-white); color: var(--text-primary); padding: 1rem 1.5rem; border-radius: var(--radius); box-shadow: var(--shadow-lg); display: flex; align-items: center; gap: 1rem; opacity: 0; transform: translateX(100%); animation: slideIn 0.5s forwards, fadeOut 0.5s 4.5s forwards; min-width: 250px; max-width: 350px; border-left: 5px solid var(--primary-color); }
        .notification.success { border-left-color: var(--success-color); }
        .notification.error { border-left-color: var(--error-color); }
        @keyframes slideIn { to { opacity: 1; transform: translateX(0); } }
        @keyframes fadeOut { to { opacity: 0; transform: translateX(100%); } }
        .mobile-menu-btn { display: none; }
        @media (max-width: 768px) {
            .sidebar { transform: translateX(-100%); }
            .sidebar.open { transform: translateX(0); }
            .main-content { margin-left: 0; max-width: 100vw; padding: 1rem; padding-top: 5rem; }
            .mobile-menu-btn { display: block; position: fixed; top: 1rem; left: 1rem; z-index: 1001; background: var(--primary-color); color: white; border: none; padding: 0.75rem; border-radius: 8px; cursor: pointer; font-size: 1.2rem; }
        }
    </style>
</head>
<body class="dashboard-body">
    <button class="mobile-menu-btn" onclick="toggleSidebar()"><i class="fas fa-bars"></i></button>
    <nav class="sidebar">
        <div class="sidebar-header"><div class="brand-logo"><i class="fas fa-shield-alt"></i><span>SecurePass</span></div></div>
        <ul class="sidebar-menu">
            <li class="menu-item active"><a onclick="switchContent('dashboard', this)"><i class="fas fa-home"></i> <span>Dashboard</span></a></li>
            <li class="menu-item"><a href="../includes/password_generator.php"><i class="fas fa-key"></i> <span>Générateur Avancé</span></a></li>
            <li class="menu-item"><a href="vault.php"><i class="fas fa-lock"></i> <span>Mes mots de passe</span></a></li>
            <li class="menu-item"><a onclick="switchContent('security', this)"><i class="fas fa-shield-virus"></i> <span>Analyse sécurité</span></a></li>
            <li class="menu-item"><a onclick="switchContent('settings', this)"><i class="fas fa-cog"></i> <span>Paramètres</span></a></li>
        </ul>
        <div class="sidebar-footer">
            <div style="display: flex; align-items: center; gap: 1rem;">
                <div style="width: 40px; height: 40px; border-radius: 50%; background-color: var(--primary-color); color: white; display: flex; align-items: center; justify-content: center; font-size: 1.2rem;"><i class="fas fa-user"></i></div>
                <div><span style="font-weight: 600;"><?php echo htmlspecialchars($username, ENT_QUOTES, 'UTF-8'); ?></span></div>
            </div>
            <a href="../includes/auth.php?action=logout" class="btn" style="width: 100%; margin-top: 1rem;"><i class="fas fa-sign-out-alt"></i> Déconnexion</a>
        </div>
    </nav>
    <main class="main-content">
        <section id="dashboard" class="content-section">
            <div class="dashboard-header">
                <div><h1>Bonjour, <?php echo htmlspecialchars($username, ENT_QUOTES, 'UTF-8'); ?> !</h1><p>Bienvenue dans votre coffre-fort sécurisé.</p></div>
                <div class="header-actions">
                    <button class="btn btn-primary" onclick="window.location.href='../includes/password_generator.php'"><i class="fas fa-plus"></i> Ajouter un mot de passe</button>
                    <button class="theme-toggle" id="themeToggle" title="Changer le thème (Ctrl+T)"><i class="fas fa-moon" id="themeIcon"></i></button>
                </div>
            </div>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-icon security-strong"><i class="fas fa-shield-alt"></i></div>
                    <div class="stat-content"><h3>Score de sécurité</h3><div class="stat-value"><?php echo round($security_score); ?>/100</div></div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon passwords"><i class="fas fa-key"></i></div>
                    <div class="stat-content"><h3>Mots de passe</h3><div class="stat-value"><?php echo $total_passwords; ?></div></div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon compromised"><i class="fas fa-exclamation-triangle"></i></div>
                    <div class="stat-content"><h3>Compromis</h3><div class="stat-value"><?php echo $compromised_count; ?></div></div>
                </div>
                 <div class="stat-card">
                    <div class="stat-icon duplicates"><i class="fas fa-copy"></i></div>
                    <div class="stat-content"><h3>Groupes de doublons</h3><div class="stat-value"><?php echo $duplicate_groups_count; ?></div></div>
                </div>
            </div>
            <div class="generator-section">
                <div class="section-header"><h2>Générateur Rapide</h2></div>
                <div class="generator-card">
                    <div class="generated-password-container">
                        <input type="text" id="generatedPassword" readonly value="Générez un mot de passe..."><div class="generator-actions"><button class="btn btn-secondary" id="copyPasswordBtn" title="Copier le mot de passe"><i class="fas fa-copy"></i></button><button class="btn btn-primary" id="regenerateBtn" title="Générer un nouveau mot de passe"><i class="fas fa-sync-alt"></i></button></div>
                    </div>
                    <div class="strength-meter"><div id="strength-bar"><div id="strength-bar-fill"></div></div><span id="strength-text"></span></div>
                    <div class="generator-controls">
                        <div class="control-group"><div class="length-control"><div class="length-label"><span>Longueur du mot de passe</span><span id="lengthValue">16</span></div><input type="range" id="passwordLength" min="12" max="64" value="16"></div></div>
                        <div class="control-group"><div class="checkbox-group"><label><input type="checkbox" id="includeUppercase" checked> Inclure des majuscules (A-Z)</label><label><input type="checkbox" id="includeNumbers" checked> Inclure des chiffres (0-9)</label><label><input type="checkbox" id="includeSymbols" checked> Inclure des symboles (!@#...)</label><label><input type="checkbox" id="excludeAmbiguous"> Exclure les caractères ambigus (l, 1, O, 0)</label></div></div>
                    </div>
                </div>
            </div>
            <div class="passwords-section">
                 <div class="section-header"><h2>Mots de passe récents</h2><button class="btn btn-secondary" onclick="window.location.href='vault.php'">Voir tout</button></div>
                 <div class="passwords-grid">
                     <?php if (empty($recent_passwords)): ?>
                         <div class="empty-state"><i class="fas fa-key"></i><p>Vous n'avez aucun mot de passe enregistré.</p></div>
                     <?php else: ?>
                         <?php foreach ($recent_passwords as $password): ?>
                             <div class="password-item"><div class="password-icon"><i class="fas fa-globe"></i></div><div class="password-info"><h4><?php echo htmlspecialchars($password['site_name']); ?></h4><span><?php echo htmlspecialchars($password['username']); ?></span></div><span class="last-updated">Modifié <?php echo format_time_ago($password['updated_at']); ?></span></div>
                         <?php endforeach; ?>
                     <?php endif; ?>
                 </div>
            </div>
            <div class="security-alerts">
                <div class="section-header"><h2>Alertes de sécurité</h2></div>
                <div class="alerts-list">
                    <?php if ($compromised_count > 0): ?><div class="alert-item critical"><div><h4><?php echo $compromised_count; ?> mot(s) de passe compromis</h4><p>Changez-les immédiatement.</p><button class="btn btn-sm btn-danger" onclick="switchContent('security', document.querySelector('a[onclick*=\'security\']'))">Agir</button></div></div><?php endif; ?>
                    <?php if ($old_passwords_count > 0): ?><div class="alert-item warning"><div><h4><?php echo $old_passwords_count; ?> mot(s) de passe anciens</h4><p>Pensez à les renouveler.</p><button class="btn btn-sm btn-warning" onclick="switchContent('security', document.querySelector('a[onclick*=\'security\']'))">Réviser</button></div></div><?php endif; ?>
                    <?php if ($compromised_count == 0 && $old_passwords_count == 0 && $weak_passwords_count == 0 && $duplicate_groups_count == 0): ?><div class="empty-state"><i class="fas fa-check-circle" style="color: var(--success-color);"></i><p>Aucune alerte de sécurité. Bravo !</p></div><?php endif; ?>
                </div>
            </div>
        </section>

        <section id="security" class="content-section" style="display: none;">
            <div class="dashboard-header"><h1><i class="fas fa-shield-virus"></i> Analyse de sécurité</h1></div>
            
            <div class="security-analysis-card">
                <div class="security-analysis-header">
                    <div class="stat-icon security-strong" style="background: hsl(<?php echo round($security_score * 1.2); ?>, 70%, 50%);"><i class="fas fa-shield-alt"></i></div>
                    <div>
                        <h3>Score de sécurité global</h3>
                        <p class="stat-value" style="font-size: 1.5rem; margin: 0;"><?php echo round($security_score); ?>/100</p>
                    </div>
                </div>
            </div>

            <?php if ($compromised_count == 0 && $weak_passwords_count == 0 && $duplicate_groups_count == 0 && $old_passwords_count == 0): ?>
                <div class="empty-state" style="padding: 4rem;">
                    <i class="fas fa-check-circle" style="font-size: 3rem; color: var(--success-color);"></i>
                    <h2>Félicitations, votre coffre-fort est en excellente santé !</h2>
                    <p>Aucune alerte de sécurité n'a été détectée. Continuez à maintenir de bonnes pratiques.</p>
                </div>
            <?php endif; ?>

            <?php if ($compromised_count > 0): ?>
            <div class="security-analysis-card">
                <div class="security-analysis-header">
                    <span class="badge" style="background-color: var(--danger-color);"><?php echo $compromised_count; ?></span>
                    <h3>Mots de passe compromis</h3>
                </div>
                <div class="security-analysis-body">
                    <p>Ces mots de passe ont été trouvés dans des fuites de données publiques. Changez-les immédiatement pour sécuriser vos comptes.</p>
                    <div class="analysis-item-list">
                        <?php foreach ($compromised_passwords_list as $p): ?>
                        <div class="analysis-item">
                            <div class="password-icon"><i class="fas fa-globe"></i></div>
                            <div class="password-info">
                                <h4><?php echo htmlspecialchars($p['site_name']); ?></h4>
                                <span><?php echo htmlspecialchars($p['username'] ?: $p['email']); ?></span>
                            </div>
                            <a href="vault.php" class="btn btn-sm btn-danger">Modifier</a>
                        </div>
                        <?php endforeach; ?>
                    </div>
                </div>
            </div>
            <?php endif; ?>

            <?php if ($weak_passwords_count > 0): ?>
            <div class="security-analysis-card">
                <div class="security-analysis-header">
                    <span class="badge" style="background-color: var(--danger-color);"><?php echo $weak_passwords_count; ?></span>
                    <h3>Mots de passe faibles</h3>
                </div>
                <div class="security-analysis-body">
                    <p>Ces mots de passe sont trop simples et peuvent être facilement devinés ou cassés. Mettez-les à jour avec des mots de passe plus robustes.</p>
                    <div class="analysis-item-list">
                         <?php foreach ($weak_passwords_list as $p): ?>
                        <div class="analysis-item">
                            <div class="password-icon"><i class="fas fa-shield-alt" style="color: var(--danger-color);"></i></div>
                            <div class="password-info">
                                <h4><?php echo htmlspecialchars($p['site_name']); ?></h4>
                                <span><?php echo htmlspecialchars($p['username'] ?: $p['email']); ?></span>
                            </div>
                            <a href="vault.php" class="btn btn-sm btn-danger">Modifier</a>
                        </div>
                        <?php endforeach; ?>
                    </div>
                </div>
            </div>
            <?php endif; ?>
            
            <?php if ($duplicate_groups_count > 0): ?>
            <div class="security-analysis-card">
                <div class="security-analysis-header">
                     <span class="badge" style="background-color: var(--warning-color);"><?php echo $duplicate_groups_count; ?></span>
                     <h3>Mots de passe réutilisés</h3>
                </div>
                <div class="security-analysis-body">
                     <p>La réutilisation d'un même mot de passe sur plusieurs sites est risquée. Si un site est compromis, tous les autres comptes utilisant ce mot de passe le sont aussi.</p>
                     <?php 
                        $current_pwd_hash = null;
                        foreach ($duplicate_passwords_list as $p):
                            if ($p['password_encrypted'] !== $current_pwd_hash) {
                                if ($current_pwd_hash !== null) echo '</div></div>'; // Ferme le groupe précédent
                                $current_pwd_hash = $p['password_encrypted'];
                                echo '<div class="duplicate-group"><p style="font-weight: 600; margin-bottom: 0.5rem;">Mot de passe réutilisé sur les sites suivants :</p><div class="analysis-item-list">';
                            }
                     ?>
                        <div class="analysis-item">
                             <div class="password-icon"><i class="fas fa-copy" style="color: var(--warning-color);"></i></div>
                             <div class="password-info">
                                 <h4><?php echo htmlspecialchars($p['site_name']); ?></h4>
                                 <span><?php echo htmlspecialchars($p['username'] ?: $p['email']); ?></span>
                             </div>
                             <a href="vault.php" class="btn btn-sm btn-warning">Modifier</a>
                        </div>
                     <?php endforeach; ?>
                     <?php if ($current_pwd_hash !== null) echo '</div></div>'; // Ferme le dernier groupe ?>
                </div>
            </div>
            <?php endif; ?>

            <?php if ($old_passwords_count > 0): ?>
            <div class="security-analysis-card">
                <div class="security-analysis-header">
                    <span class="badge" style="background-color: var(--primary-color);"><?php echo $old_passwords_count; ?></span>
                    <h3>Mots de passe anciens</h3>
                </div>
                <div class="security-analysis-body">
                    <p>Il est recommandé de renouveler régulièrement vos mots de passe, en particulier pour les services sensibles. Ces mots de passe n'ont pas été changés depuis plus de 6 mois.</p>
                    <div class="analysis-item-list">
                        <?php foreach ($old_passwords_list as $p): ?>
                        <div class="analysis-item">
                            <div class="password-icon"><i class="fas fa-calendar-alt"></i></div>
                            <div class="password-info">
                                <h4><?php echo htmlspecialchars($p['site_name']); ?></h4>
                                <span>Dernière mise à jour : <?php echo format_time_ago($p['updated_at']); ?></span>
                            </div>
                            <a href="vault.php" class="btn btn-sm" style="background-color: var(--bg-white); border: 1px solid var(--border-color);">Réviser</a>
                        </div>
                        <?php endforeach; ?>
                    </div>
                </div>
            </div>
            <?php endif; ?>

        </section>

        <section id="settings" class="content-section" style="display: none;">
            <div class="dashboard-header"><h1><i class="fas fa-cog"></i> Paramètres</h1></div>
            <p>Cette section est en cours de construction.</p>
        </section>
    </main>

    <div class="notification-container"></div>
    <script>
        document.addEventListener('DOMContentLoaded', () => {
            const generatedPasswordField = document.getElementById('generatedPassword');
            const lengthSlider = document.getElementById('passwordLength');
            const lengthValueLabel = document.getElementById('lengthValue');
            const options = { 
                uppercase: document.getElementById('includeUppercase'), 
                numbers: document.getElementById('includeNumbers'), 
                symbols: document.getElementById('includeSymbols'), 
                ambiguous: document.getElementById('excludeAmbiguous') 
            };
            const copyBtn = document.getElementById('copyPasswordBtn');
            const regenerateBtn = document.getElementById('regenerateBtn');
            const strengthBarFill = document.getElementById('strength-bar-fill');
            const strengthText = document.getElementById('strength-text');
            const charSets = { 
                lower: 'abcdefghijklmnopqrstuvwxyz', 
                upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 
                numbers: '0123456789', 
                symbols: '!@#$%^&*()_+-=[]{}|;:,.<>?', 
                ambiguous: 'l1O0' 
            };

            function generatePassword() {
                if (!charSets) return;
                let charPool = charSets.lower; 
                const length = lengthSlider.value; 
                let password = [];
                if (options.uppercase.checked) { charPool += charSets.upper; password.push(charSets.upper[Math.floor(Math.random() * charSets.upper.length)]); }
                if (options.numbers.checked) { charPool += charSets.numbers; password.push(charSets.numbers[Math.floor(Math.random() * charSets.numbers.length)]); }
                if (options.symbols.checked) { charPool += charSets.symbols; password.push(charSets.symbols[Math.floor(Math.random() * charSets.symbols.length)]); }
                if (options.ambiguous.checked) { charPool = charPool.split('').filter(char => !charSets.ambiguous.includes(char)).join(''); }
                const remainingLength = length - password.length;
                for (let i = 0; i < remainingLength; i++) { password.push(charPool[Math.floor(Math.random() * charPool.length)]); }
                password = password.sort(() => Math.random() - 0.5);
                const finalPassword = password.join(''); 
                generatedPasswordField.value = finalPassword; 
                updateStrength(finalPassword);
            }

            function updateStrength(password) {
                if(!strengthBarFill) return;
                let score = 0; 
                if (password.length >= 12) score += 25; 
                if (/[A-Z]/.test(password)) score += 25; 
                if (/[0-9]/.test(password)) score += 25; 
                if (/[^A-Za-z0-9]/.test(password)) score += 25;
                strengthBarFill.style.width = score + '%'; 
                let strengthLabel = 'Faible'; 
                let color = 'var(--danger-color)';
                if (score >= 50) { strengthLabel = 'Moyen'; color = 'var(--warning-color)'; } 
                if (score >= 75) { strengthLabel = 'Fort'; color = 'var(--success-color)'; } 
                if (score >= 100) { strengthLabel = 'Très Fort'; color = '#38a169'; }
                strengthText.textContent = `Robustesse : ${strengthLabel}`; 
                strengthText.style.color = color; 
                strengthBarFill.style.backgroundColor = color;
            }
            
            if(lengthSlider) lengthSlider.addEventListener('input', (e) => { lengthValueLabel.textContent = e.target.value; generatePassword(); });
            Object.values(options).forEach(opt => { if(opt) opt.addEventListener('change', generatePassword) });
            if(regenerateBtn) regenerateBtn.addEventListener('click', generatePassword);
            if(copyBtn) copyBtn.addEventListener('click', () => { if (generatedPasswordField.value && generatedPasswordField.value !== "Générez un mot de passe...") { copyToClipboard(generatedPasswordField.value); } else { showNotification("Veuillez d'abord générer un mot de passe.", "error"); } });
            
            // Initial generation
            if(generatedPasswordField) generatePassword();
            
            // Theme initial
            if (localStorage.getItem('theme') === 'dark') { document.body.classList.add('dark-mode'); document.getElementById('themeIcon').className = 'fas fa-sun'; }
            
            // Welcome message
            <?php if (!isset($_SESSION['welcome_message_shown'])): ?> 
                setTimeout(() => { showNotification('Bienvenue, <?php echo htmlspecialchars($username, ENT_QUOTES, 'UTF-8'); ?> !', 'success'); }, 1000); 
                <?php $_SESSION['welcome_message_shown'] = true; ?> 
            <?php endif; ?>

            // Navigation initial
            const hash = window.location.hash.substring(1);
            if (hash) {
                const targetElement = document.querySelector(`.menu-item a[onclick*="'${hash}'"]`);
                if (targetElement) {
                    switchContent(hash, targetElement);
                }
            }
        });

        document.getElementById('themeToggle').addEventListener('click', function() { 
            document.body.classList.toggle('dark-mode'); 
            const isDarkMode = document.body.classList.contains('dark-mode'); 
            document.getElementById('themeIcon').className = isDarkMode ? 'fas fa-sun' : 'fas fa-moon'; 
            localStorage.setItem('theme', isDarkMode ? 'dark' : 'light'); 
        });

        function toggleSidebar() { document.querySelector('.sidebar').classList.toggle('open'); }
        
        function showNotification(message, type = 'info') { 
            const container = document.querySelector('.notification-container'); 
            const notif = document.createElement('div'); 
            notif.className = `notification ${type}`; 
            const icon = type === 'success' ? 'fa-check-circle' : type === 'error' ? 'fa-times-circle' : 'fa-info-circle'; 
            notif.innerHTML = `<i class="fas ${icon}"></i> <span>${message}</span>`; 
            container.appendChild(notif); 
            setTimeout(() => { notif.remove(); }, 5000); 
        }
        
        function switchContent(sectionId, clickedElement = null) { 
            document.querySelectorAll('.content-section').forEach(s => s.style.display = 'none'); 
            const section = document.getElementById(sectionId);
            if(section) section.style.display = 'block';
            
            document.querySelectorAll('.sidebar-menu .menu-item').forEach(i => i.classList.remove('active')); 
            if(clickedElement) {
                clickedElement.closest('.menu-item').classList.add('active');
                if (window.history.pushState) {
                    history.pushState(null, null, '#' + sectionId);
                } else {
                    window.location.hash = sectionId;
                }
            }
        }
        
        function copyToClipboard(textToCopy) { 
            if (!navigator.clipboard) { 
                showNotification("La copie sécurisée n'est pas supportée.", 'error'); 
                return; 
            } 
            navigator.clipboard.writeText(textToCopy).then(() => { 
                showNotification('Copié ! Effacement du presse-papiers dans 15s.', 'success'); 
                setTimeout(() => { 
                    navigator.clipboard.writeText('').catch(()=>{}); 
                }, 15000); 
            }).catch(err => { 
                showNotification('Échec de la copie.', 'error'); 
            }); 
        }
        
        document.addEventListener('keydown', function(event) { 
            if (event.ctrlKey && event.key.toLowerCase() === 't') { 
                event.preventDefault(); 
                document.getElementById('themeToggle').click(); 
            } 
        });
    </script>
</body>
</html>