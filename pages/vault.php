<?php
session_start();

// [CORRECTION] Standardisation de la connexion à la base de données en utilisant votre fichier de config
require_once __DIR__ . '/../config/database.php';

// --- HEADERS DE SÉCURITÉ ---
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('X-XSS-Protection: 1; mode=block');
header('Referrer-Policy: strict-origin-when-cross-origin');

// --- VÉRIFICATION DE LA SESSION UTILISATEUR ---
if (!isset($_SESSION['user_id']) || !$_SESSION['user_id']) {
    $_SESSION['error_message'] = "Veuillez vous connecter pour accéder à votre coffre-fort.";
    header('Location: ../login.php'); // Assumant que login.php est à la racine
    exit();
}

$user_id = $_SESSION['user_id'];

// --- RÉCUPÉRATION DES DONNÉES AVEC MYSQLI ---
$username = 'Utilisateur';
$stmt_user = mysqli_prepare($link, "SELECT prenom FROM users WHERE id = ?");
mysqli_stmt_bind_param($stmt_user, "i", $user_id);
if (mysqli_stmt_execute($stmt_user)) {
    $result_user = mysqli_stmt_get_result($stmt_user);
    if ($user_data = mysqli_fetch_assoc($result_user)) {
        $username = htmlspecialchars($user_data['prenom']);
    }
}
mysqli_stmt_close($stmt_user);


// --- RÉCUPÉRATION DE TOUS LES MOTS DE PASSE ENREGISTRÉS ---
$all_passwords = [];
// [MODIFICATION] On sélectionne aussi la nouvelle colonne strength_score
$sql_passwords = "SELECT id, site_name, site_url, username, email, category, is_favorite, updated_at, strength_score FROM saved_passwords WHERE user_id = ? ORDER BY site_name ASC";
$stmt_all_passwords = mysqli_prepare($link, $sql_passwords);
mysqli_stmt_bind_param($stmt_all_passwords, "i", $user_id);
if(mysqli_stmt_execute($stmt_all_passwords)) {
    $result_passwords = mysqli_stmt_get_result($stmt_all_passwords);
    $all_passwords = mysqli_fetch_all($result_passwords, MYSQLI_ASSOC);
}
mysqli_stmt_close($stmt_all_passwords);


// --- CALCUL DES STATISTIQUES (simplifié pour MySQLi) ---
$total_passwords = count($all_passwords);
$weak_passwords_count = 0; 
$compromised_count = 0;
$duplicate_count = 0;


function format_time_ago($date_string) {
    if (is_null($date_string)) return 'jamais';
    try {
        $date = new DateTime($date_string);
        $now = new DateTime();
        $interval = $now->diff($date);
        if ($interval->y > 0) return 'il y a ' . $interval->y . ' an(s)';
        if ($interval->m > 0) return 'il y a ' . $interval->m . ' mois';
        if ($interval->d > 0) return 'il y a ' . $interval->d . ' jour(s)';
        if ($interval->h > 0) return 'il y a ' . $interval->h . ' heure(s)';
        if ($interval->i > 0) return 'il y a ' . $interval->i . ' minute(s)';
        return 'à l\'instant';
    } catch (Exception $e) {
        return 'date invalide';
    }
}

// [NOUVEAU] Fonction pour afficher la force du mot de passe
function get_strength_display($score) {
    $score = $score ?? 0;
    if ($score >= 6) return ['label' => 'Très Fort', 'color' => '#38a169'];
    if ($score >= 5) return ['label' => 'Fort', 'color' => 'var(--success-color)'];
    if ($score >= 3) return ['label' => 'Moyen', 'color' => 'var(--warning-color)'];
    return ['label' => 'Faible', 'color' => 'var(--danger-color)'];
}
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="Mon Coffre-fort - Gérez vos mots de passe en toute sécurité.">
    <title>Mon Coffre-fort - SecurePass</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        :root {
            --primary-color: #667eea; --secondary-color: #764ba2; --success-color: #48bb78;
            --error-color: #f56565; --danger-color: #f56565; --warning-color: #ed8936;
            --text-primary: #2d3748; --text-secondary: #718096; --bg-light: #f7fafc;
            --bg-white: #ffffff; --border-color: #e2e8f0; --shadow-md: 0 4px 6px rgba(0, 0, 0, 0.05);
            --shadow-lg: 0 10px 15px rgba(0, 0, 0, 0.05); --radius: 12px; --sidebar-width: 280px;
        }
        body.dark-mode {
            --text-primary: #f7fafc; --text-secondary: #a0aec0; --bg-light: #1a202c;
            --bg-white: #2d3748; --border-color: #4a5568;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Inter', sans-serif; background-color: var(--bg-light); color: var(--text-primary); display: flex; min-height: 100vh; }
        .sidebar { width: var(--sidebar-width); background: var(--bg-white); border-right: 1px solid var(--border-color); display: flex; flex-direction: column; position: fixed; height: 100vh; left: 0; top: 0; z-index: 1000; transition: transform 0.3s ease; }
        .sidebar.open { transform: translateX(0); }
        .sidebar-header { padding: 2rem; border-bottom: 1px solid var(--border-color); }
        .brand-logo { display: flex; align-items: center; gap: 0.75rem; font-size: 1.5rem; font-weight: 800; color: var(--primary-color); text-decoration: none; }
        .sidebar-menu { list-style: none; padding: 1rem 0; margin: 0; flex-grow: 1; }
        .menu-item a { display: flex; align-items: center; gap: 1rem; padding: 1rem 2rem; color: var(--text-secondary); text-decoration: none; transition: all 0.3s ease; border-left: 4px solid transparent; }
        .menu-item a:hover { color: var(--primary-color); background: var(--bg-light); }
        .menu-item.active a { color: var(--primary-color); border-left-color: var(--primary-color); font-weight: 600; background: var(--bg-light); }
        .sidebar-footer { padding: 1.5rem; border-top: 1px solid var(--border-color); }
        .main-content { flex: 1; margin-left: var(--sidebar-width); padding: 2rem; }
        .page-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 2rem; }
        .page-header h1 { font-size: 2rem; font-weight: 800; }
        .header-actions { display: flex; gap: 1rem; align-items: center; }
        .btn { padding: 0.75rem 1.5rem; border-radius: 8px; border: none; font-weight: 600; cursor: pointer; transition: all 0.3s ease; display: inline-flex; align-items: center; gap: 0.5rem; text-decoration: none; font-size: 0.9rem; }
        .btn-primary { background: linear-gradient(45deg, var(--primary-color), var(--secondary-color)); color: white; }
        .theme-toggle { background: var(--bg-white); border: 1px solid var(--border-color); border-radius: 8px; padding: 0.75rem; cursor: pointer; color: var(--text-secondary); }
        .search-box { position: relative; flex-grow: 1; }
        .search-box i { position: absolute; left: 1rem; top: 50%; transform: translateY(-50%); color: var(--text-secondary); }
        .search-box input { width: 100%; padding: 0.75rem 1rem 0.75rem 2.5rem; border: 1px solid var(--border-color); border-radius: 8px; background: var(--bg-white); color: var(--text-primary); }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1.5rem; margin: 2rem 0; }
        .stat-card { background: var(--bg-white); padding: 1.5rem; border-radius: var(--radius); border: 1px solid var(--border-color); }
        .stat-card h3 { font-size: 0.9rem; color: var(--text-secondary); margin-bottom: 0.5rem; }
        .stat-value { font-size: 1.8rem; font-weight: 800; }
        .vault-container { background: var(--bg-white); border-radius: var(--radius); border: 1px solid var(--border-color); overflow: hidden; }
        .password-list { display: flex; flex-direction: column; }
        .password-item { padding: 1rem 1.5rem; border-bottom: 1px solid var(--border-color); display: grid; grid-template-columns: 40px 1fr auto auto auto; align-items: center; gap: 1rem; transition: background-color 0.2s; }
        .password-icon { width: 40px; height: 40px; border-radius: 8px; background: var(--bg-light); display: flex; align-items: center; justify-content: center; font-size: 1.2rem; color: var(--primary-color); flex-shrink: 0; }
        .password-info { flex-grow: 1; }
        .password-info h4 { font-size: 1rem; font-weight: 600; margin-bottom: 0.25rem; }
        .password-info span { font-size: 0.8rem; color: var(--text-secondary); }
        .password-strength { justify-self: end; }
        .strength-badge { padding: 0.2rem 0.6rem; border-radius: 20px; font-size: 0.75rem; font-weight: 600; color: white; white-space: nowrap; }
        .password-actions { display: flex; gap: 0.5rem; justify-self: end; }
        .action-btn { background: none; border: none; padding: 0.5rem; border-radius: 6px; cursor: pointer; color: var(--text-secondary); }
        .empty-state { text-align: center; padding: 4rem 2rem; }
        .notification-container { position: fixed; top: 1.5rem; right: 1.5rem; z-index: 3001; }
        .notification { background: var(--bg-white); padding: 1rem 1.5rem; border-radius: var(--radius); box-shadow: var(--shadow-lg); display: flex; align-items: center; gap: 1rem; opacity: 0; transform: translateX(100%); animation: slideIn 0.5s forwards, fadeOut 0.5s 4.5s forwards; border-left: 5px solid var(--primary-color); }
        .notification.success { border-left-color: var(--success-color); } .notification.error { border-left-color: var(--error-color); }
        @keyframes slideIn { to { opacity: 1; transform: translateX(0); } } @keyframes fadeOut { to { opacity: 0; transform: translateX(100%); } }
        .modal-overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0, 0, 0, 0.6); display: none; align-items: center; justify-content: center; z-index: 3000; backdrop-filter: blur(5px); }
        .modal-content { background: var(--bg-white); padding: 2rem; border-radius: var(--radius); width: 90%; max-width: 400px; }
        .modal-header { margin-bottom: 1rem; }
        .modal-header h3 { margin: 0; font-size: 1.25rem; }
        .form-group { margin-bottom: 1rem; }
        .form-group label { font-weight: 600; display: block; margin-bottom: 0.5rem; }
        .form-group input { width: 100%; padding: 0.75rem; border: 1px solid var(--border-color); border-radius: 8px; }
        .modal-actions { margin-top: 1.5rem; display: flex; justify-content: flex-end; gap: 0.75rem; }
        .btn-secondary { background: var(--bg-light); color: var(--text-primary); border: 1px solid var(--border-color); }
        .mobile-menu-btn { display: none; }
        @media (max-width: 768px) { .sidebar { transform: translateX(-100%); } .main-content { margin-left: 0; } .mobile-menu-btn { display: block; /* ... */ } }
    </style>
</head>
<body>
    <button class="mobile-menu-btn" onclick="toggleSidebar()"><i class="fas fa-bars"></i></button>
    <nav class="sidebar">
        <div class="sidebar-header"><a href="dashboard.php" class="brand-logo"><i class="fas fa-shield-alt"></i><span>SecurePass</span></a></div>
        <ul class="sidebar-menu">
            <li class="menu-item"><a href="dashboard.php"><i class="fas fa-home"></i> <span>Dashboard</span></a></li>
            <li class="menu-item"><a href="../includes/password_generator.php"><i class="fas fa-key"></i> <span>Générateur</span></a></li>
            <li class="menu-item active"><a href="vault.php"><i class="fas fa-lock"></i> <span>Mes mots de passe</span></a></li>
            <li class="menu-item"><a href="dashboard.php#security"><i class="fas fa-shield-virus"></i> <span>Analyse sécurité</span></a></li>
        </ul>
        <div class="sidebar-footer">
             <a href="../includes/auth.php?action=logout" class="btn btn-secondary" style="width: 100%; background: var(--bg-light);">
                <i class="fas fa-sign-out-alt"></i> Déconnexion
             </a>
        </div>
    </nav>
    <main class="main-content">
        <div class="page-header">
            <div><h1>Mon Coffre-fort</h1><p>Retrouvez tous vos identifiants enregistrés, <?php echo $username; ?>.</p></div>
            <div class="header-actions">
                <a href="../includes/password_generator.php" class="btn btn-primary" id="newPasswordBtn"><i class="fas fa-plus"></i> Ajouter un identifiant</a>
                <button class="theme-toggle" id="themeToggle" title="Changer le thème"><i class="fas fa-moon" id="themeIcon"></i></button>
            </div>
        </div>
        <div class="stats-grid">
            <div class="stat-card"><h3>Total</h3><div class="stat-value"><?php echo $total_passwords; ?></div></div>
            <div class="stat-card"><h3>Faibles</h3><div class="stat-value" style="color: <?php echo $weak_passwords_count > 0 ? 'var(--warning-color)' : 'inherit'; ?>;"><?php echo $weak_passwords_count; ?></div></div>
            <div class="stat-card"><h3>Compromis</h3><div class="stat-value" style="color: <?php echo $compromised_count > 0 ? 'var(--danger-color)' : 'inherit'; ?>;"><?php echo $compromised_count; ?></div></div>
            <div class="stat-card"><h3>Doublons</h3><div class="stat-value" style="color: <?php echo $duplicate_count > 0 ? 'var(--warning-color)' : 'inherit'; ?>;"><?php echo $duplicate_count; ?></div></div>
        </div>
        <div class="vault-container">
            <div style="padding: 1.5rem;"><div class="search-box"><i class="fas fa-search"></i><input type="text" id="searchVault" placeholder="Rechercher par nom de site ou email..."></div></div>
            <div class="password-list" id="passwordList">
                <?php if (empty($all_passwords)): ?>
                    <div class="empty-state"><i class="fas fa-key" style="font-size: 3rem; color: var(--text-secondary); margin-bottom: 1rem;"></i><h3>Votre coffre-fort est vide</h3><p>Commencez par ajouter un nouvel identifiant.</p></div>
                <?php else: ?>
                    <?php foreach ($all_passwords as $password): ?>
                        <div class="password-item" data-search-term="<?php echo strtolower(htmlspecialchars($password['site_name'] . ' ' . $password['username'] . ' ' . $password['email'])); ?>">
                            <div class="password-icon"><i class="fas fa-globe-americas"></i></div>
                            <div class="password-info">
                                <h4><?php echo htmlspecialchars($password['site_name']); ?></h4>
                                <span><?php echo htmlspecialchars($password['username'] ?: $password['email']); ?></span>
                            </div>
                            <div class="password-info" style="flex: 0.5; text-align: right; color: var(--text-secondary);"><span style="font-size: 0.8rem;">Modifié <?php echo format_time_ago($password['updated_at']); ?></span></div>
                            <div class="password-strength">
                                <?php $strength = get_strength_display($password['strength_score']); ?>
                                <span class="strength-badge" style="background-color: <?php echo $strength['color']; ?>">
                                    <?php echo $strength['label']; ?>
                                </span>
                            </div>
                            <div class="password-actions">
                                <button class="action-btn" title="Copier le mot de passe" onclick="requestMasterPassword('<?php echo $password['id']; ?>')"><i class="fas fa-copy"></i></button>
                                <button class="action-btn" title="Modifier"><i class="fas fa-edit"></i></button>
                                <button class="action-btn" title="Supprimer" style="color:var(--danger-color);"><i class="fas fa-trash"></i></button>
                            </div>
                        </div>
                    <?php endforeach; ?>
                <?php endif; ?>
            </div>
        </div>
    </main>

    <div class="notification-container"></div>

    <div class="modal-overlay" id="masterPasswordModal">
        <div class="modal-content">
            <div class="modal-header"><h3>Vérification de sécurité</h3></div>
            <form id="masterPasswordForm">
                <div class="form-group"><label for="masterPasswordInput">Mot de Passe Maître</label><input type="password" id="masterPasswordInput" required></div>
                <div class="modal-actions">
                    <button type="button" class="btn btn-secondary" id="cancelMasterPassword">Annuler</button>
                    <button type="submit" class="btn btn-primary">Déchiffrer et Copier</button>
                </div>
            </form>
        </div>
    </div>

    <script>
        let currentPasswordId = null;
        function showNotification(message, type = 'info') {
            const container = document.querySelector('.notification-container');
            if (!container) return;
            const notif = document.createElement('div'); notif.className = `notification ${type}`;
            const iconMap = { success: 'fa-check-circle', error: 'fa-times-circle', info: 'fa-info-circle' };
            notif.innerHTML = `<i class="fas ${iconMap[type]}"></i> <span>${message}</span>`;
            container.appendChild(notif);
            setTimeout(() => { notif.remove(); }, 5000);
        }
        function requestMasterPassword(passwordId) {
            const modal = document.getElementById('masterPasswordModal');
            const masterPasswordInput = document.getElementById('masterPasswordInput');
            currentPasswordId = passwordId;
            modal.style.display = 'flex';
            masterPasswordInput.focus();
        }
        document.addEventListener('DOMContentLoaded', function() {
            const modal = document.getElementById('masterPasswordModal');
            const masterPasswordForm = document.getElementById('masterPasswordForm');
            const masterPasswordInput = document.getElementById('masterPasswordInput');
            const cancelBtn = document.getElementById('cancelMasterPassword');
            const themeToggle = document.getElementById('themeToggle');
            const searchInput = document.getElementById('searchVault');
            if (masterPasswordForm) {
                masterPasswordForm.addEventListener('submit', async function(event) {
                    event.preventDefault();
                    const masterPassword = masterPasswordInput.value;
                    const idToDecrypt = currentPasswordId;
                    if (!masterPassword || !idToDecrypt) { showNotification('Informations manquantes', 'error'); return; }
                    showNotification('Déchiffrement en cours...', 'info');
                    closeModal();
                    try {
                        const response = await fetch('/securePass_projet_techno/SecurePass/includes/api_decrypt_password.php', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                            body: `password_id=${idToDecrypt}&master_password=${encodeURIComponent(masterPassword)}`
                        });
                        const data = await response.json();
                        if (data.success && data.password) {
                            await navigator.clipboard.writeText(data.password);
                            showNotification('Mot de passe copié !', 'success');
                        } else {
                            showNotification(data.error || 'Une erreur est survenue.', 'error');
                        }
                    } catch (error) {
                        showNotification(`Erreur réseau : ${error.message}`, 'error');
                    }
                });
            }
            function closeModal() {
                if(modal) modal.style.display = 'none';
                if(masterPasswordInput) masterPasswordInput.value = '';
                currentPasswordId = null;
            }
            if(cancelBtn) cancelBtn.addEventListener('click', closeModal);
            if(modal) modal.addEventListener('click', function(event) { if (event.target === modal) closeModal(); });
            if (themeToggle) {
                themeToggle.addEventListener('click', function() {
                    document.body.classList.toggle('dark-mode');
                    const isDarkMode = document.body.classList.contains('dark-mode');
                    document.getElementById('themeIcon').className = isDarkMode ? 'fas fa-sun' : 'fas fa-moon';
                    localStorage.setItem('theme', isDarkMode ? 'dark' : 'light');
                });
            }
            if (localStorage.getItem('theme') === 'dark') {
                document.body.classList.add('dark-mode');
                if(document.getElementById('themeIcon')) document.getElementById('themeIcon').className = 'fas fa-sun';
            }
            if(searchInput) {
                searchInput.addEventListener('input', function(e) {
                    const searchTerm = e.target.value.toLowerCase();
                    document.querySelectorAll('#passwordList .password-item').forEach(item => {
                        item.style.display = item.dataset.searchTerm.includes(searchTerm) ? 'flex' : 'none';
                    });
                });
            }
            <?php if (isset($_SESSION['success_message'])): ?>
                showNotification('<?php echo addslashes($_SESSION['success_message']); ?>', 'success');
                <?php unset($_SESSION['success_message']); ?>
            <?php endif; ?>
            <?php if (isset($_SESSION['error_message'])): ?>
                showNotification('<?php echo addslashes($_SESSION['error_message']); ?>', 'error');
                <?php unset($_SESSION['error_message']); ?>
            <?php endif; ?>
        });
        function toggleSidebar() { document.querySelector('.sidebar').classList.toggle('open'); }
        document.addEventListener('keydown', function(event) {
            if (event.ctrlKey && event.key.toLowerCase() === 'n') { event.preventDefault(); document.getElementById('newPasswordBtn').click(); }
            if (event.ctrlKey && event.key.toLowerCase() === 'f') { event.preventDefault(); document.getElementById('searchVault').focus(); }
            if (event.ctrlKey && event.key.toLowerCase() === 't') { event.preventDefault(); document.getElementById('themeToggle').click(); }
        });
    </script>
</body>
</html>