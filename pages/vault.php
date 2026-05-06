<?php
session_start();
require_once __DIR__ . '/../config/database.php';

header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('X-XSS-Protection: 1; mode=block');
header('Referrer-Policy: strict-origin-when-cross-origin');

if (!isset($_SESSION['user_id']) || !$_SESSION['user_id']) {
    $_SESSION['error_message'] = "Veuillez vous connecter pour accéder à votre coffre-fort.";
    header('Location: login.php');
    exit();
}

$user_id = (int) $_SESSION['user_id'];

// CSRF token
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Récupérer l'utilisateur
$stmt = mysqli_prepare($link, "SELECT prenom FROM users WHERE id = ?");
mysqli_stmt_bind_param($stmt, "i", $user_id);
mysqli_stmt_execute($stmt);
$user_data = mysqli_fetch_assoc(mysqli_stmt_get_result($stmt));
$username  = $user_data ? htmlspecialchars($user_data['prenom']) : 'Utilisateur';
mysqli_stmt_close($stmt);

// Récupérer les mots de passe
$all_passwords = [];
$stmt = mysqli_prepare($link,
    "SELECT id, site_name, site_url, username, email, category, is_favorite, updated_at, strength_score
     FROM saved_passwords WHERE user_id = ? ORDER BY is_favorite DESC, site_name ASC");
mysqli_stmt_bind_param($stmt, "i", $user_id);
mysqli_stmt_execute($stmt);
$all_passwords = mysqli_fetch_all(mysqli_stmt_get_result($stmt), MYSQLI_ASSOC);
mysqli_stmt_close($stmt);

// Stats
$total_passwords  = count($all_passwords);
$weak_count       = count(array_filter($all_passwords, fn($p) => ($p['strength_score'] ?? 0) <= 2));
$strong_count     = count(array_filter($all_passwords, fn($p) => ($p['strength_score'] ?? 0) >= 5));
$compromised_count = (int) mysqli_fetch_assoc(mysqli_query($link,
    "SELECT COUNT(*) c FROM saved_passwords WHERE user_id=$user_id AND is_compromised=1"))['c'];

// Catégories
$stmt = mysqli_prepare($link, "SELECT DISTINCT category FROM saved_passwords WHERE user_id = ? ORDER BY category");
mysqli_stmt_bind_param($stmt, "i", $user_id);
mysqli_stmt_execute($stmt);
$cats_raw   = mysqli_fetch_all(mysqli_stmt_get_result($stmt), MYSQLI_ASSOC);
$categories = array_column($cats_raw, 'category');
mysqli_stmt_close($stmt);

function format_time_ago($d) {
    if (!$d) return 'jamais';
    $diff = (new DateTime())->diff(new DateTime($d));
    if ($diff->y) return 'il y a ' . $diff->y . ' an(s)';
    if ($diff->m) return 'il y a ' . $diff->m . ' mois';
    if ($diff->d) return 'il y a ' . $diff->d . ' jour(s)';
    if ($diff->h) return 'il y a ' . $diff->h . 'h';
    if ($diff->i) return 'il y a ' . $diff->i . ' min';
    return "à l'instant";
}

function strength_badge($score) {
    $s = (int)($score ?? 0);
    if ($s >= 6) return ['Très fort', '#38a169'];
    if ($s >= 5) return ['Fort',      '#48bb78'];
    if ($s >= 3) return ['Moyen',     '#ed8936'];
    return              ['Faible',    '#f56565'];
}
?>
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Mon Coffre-fort — SecurePass</title>
<link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
<style>
:root {
    --primary: #667eea; --primary-dark: #764ba2;
    --success: #48bb78; --danger: #f56565; --warning: #ed8936;
    --text: #2d3748; --muted: #718096;
    --bg: #f7fafc; --white: #fff; --border: #e2e8f0;
    --shadow: 0 4px 12px rgba(0,0,0,.08);
    --radius: 12px; --sidebar: 270px;
}
body.dark-mode {
    --text: #f7fafc; --muted: #a0aec0;
    --bg: #1a202c; --white: #2d3748; --border: #4a5568;
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Inter',sans-serif;background:var(--bg);color:var(--text);display:flex;min-height:100vh}

/* SIDEBAR */
.sidebar{width:var(--sidebar);background:var(--white);border-right:1px solid var(--border);display:flex;flex-direction:column;position:fixed;height:100vh;left:0;top:0;z-index:200;transition:.3s}
.sidebar-logo{padding:1.75rem 1.5rem;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:.75rem;font-size:1.3rem;font-weight:800;color:var(--primary);text-decoration:none}
.sidebar-nav{flex:1;padding:1rem 0;overflow-y:auto}
.nav-item a{display:flex;align-items:center;gap:.9rem;padding:.85rem 1.5rem;color:var(--muted);text-decoration:none;transition:.2s;border-left:3px solid transparent;font-size:.9rem}
.nav-item a:hover{color:var(--primary);background:var(--bg)}
.nav-item.active a{color:var(--primary);border-left-color:var(--primary);font-weight:600;background:var(--bg)}
.sidebar-footer{padding:1.25rem 1.5rem;border-top:1px solid var(--border)}
.logout-btn{display:flex;align-items:center;gap:.75rem;color:var(--danger);text-decoration:none;font-size:.9rem;padding:.5rem;border-radius:8px;transition:.2s}
.logout-btn:hover{background:rgba(245,101,101,.08)}

/* MAIN */
.main{flex:1;margin-left:var(--sidebar);padding:2rem;max-width:100%}

/* TOPBAR */
.topbar{display:flex;align-items:center;justify-content:space-between;margin-bottom:2rem;gap:1rem;flex-wrap:wrap}
.topbar-left h1{font-size:1.75rem;font-weight:800}
.topbar-left p{color:var(--muted);font-size:.9rem;margin-top:.25rem}
.topbar-right{display:flex;gap:.75rem;align-items:center}
.btn{display:inline-flex;align-items:center;gap:.5rem;padding:.7rem 1.25rem;border-radius:8px;border:none;font-weight:600;font-size:.875rem;cursor:pointer;transition:.2s;text-decoration:none}
.btn-primary{background:linear-gradient(135deg,var(--primary),var(--primary-dark));color:#fff}
.btn-primary:hover{transform:translateY(-1px);box-shadow:0 4px 15px rgba(102,126,234,.4)}
.btn-ghost{background:var(--white);border:1px solid var(--border);color:var(--text)}
.btn-ghost:hover{border-color:var(--primary);color:var(--primary)}
.btn-danger{background:rgba(245,101,101,.1);color:var(--danger);border:1px solid rgba(245,101,101,.3)}
.btn-danger:hover{background:var(--danger);color:#fff}

/* STATS */
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:1rem;margin-bottom:2rem}
.stat-card{background:var(--white);border:1px solid var(--border);border-radius:var(--radius);padding:1.25rem;display:flex;align-items:center;gap:1rem}
.stat-icon{width:44px;height:44px;border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:1.1rem;flex-shrink:0}
.stat-icon.blue{background:rgba(102,126,234,.1);color:var(--primary)}
.stat-icon.green{background:rgba(72,187,120,.1);color:var(--success)}
.stat-icon.red{background:rgba(245,101,101,.1);color:var(--danger)}
.stat-icon.orange{background:rgba(237,137,54,.1);color:var(--warning)}
.stat-label{font-size:.78rem;color:var(--muted);margin-bottom:.2rem}
.stat-value{font-size:1.5rem;font-weight:800}

/* TOOLBAR */
.toolbar{background:var(--white);border:1px solid var(--border);border-radius:var(--radius);padding:1rem 1.25rem;margin-bottom:1rem;display:flex;gap:1rem;align-items:center;flex-wrap:wrap}
.search-wrap{flex:1;min-width:200px;position:relative}
.search-wrap i{position:absolute;left:.9rem;top:50%;transform:translateY(-50%);color:var(--muted);font-size:.85rem}
.search-wrap input{width:100%;padding:.65rem .9rem .65rem 2.4rem;border:1.5px solid var(--border);border-radius:8px;font-size:.875rem;background:var(--bg);color:var(--text);outline:none;transition:.2s}
.search-wrap input:focus{border-color:var(--primary);background:var(--white)}
.filter-select{padding:.65rem .9rem;border:1.5px solid var(--border);border-radius:8px;font-size:.875rem;background:var(--bg);color:var(--text);cursor:pointer}

/* VAULT TABLE */
.vault{background:var(--white);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden}
.vault-header{display:grid;grid-template-columns:1fr 140px 120px 120px;padding:.75rem 1.5rem;background:var(--bg);border-bottom:1px solid var(--border);font-size:.78rem;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.05em}
.pwd-row{display:grid;grid-template-columns:1fr 140px 120px 120px;padding:1rem 1.5rem;border-bottom:1px solid var(--border);align-items:center;transition:.15s}
.pwd-row:last-child{border-bottom:none}
.pwd-row:hover{background:var(--bg)}
.site-info{display:flex;align-items:center;gap:.9rem}
.site-favicon{width:38px;height:38px;border-radius:8px;background:var(--bg);border:1px solid var(--border);display:flex;align-items:center;justify-content:center;font-size:1rem;color:var(--primary);flex-shrink:0;overflow:hidden}
.site-favicon img{width:100%;height:100%;object-fit:cover}
.site-name{font-weight:600;font-size:.9rem}
.site-meta{font-size:.78rem;color:var(--muted);margin-top:.1rem}
.strength-badge{padding:.2rem .65rem;border-radius:20px;font-size:.73rem;font-weight:700;color:#fff;white-space:nowrap}
.actions-cell{display:flex;gap:.3rem;justify-content:flex-end}
.action-btn{width:32px;height:32px;border-radius:7px;border:1px solid var(--border);background:var(--white);cursor:pointer;display:flex;align-items:center;justify-content:center;font-size:.8rem;color:var(--muted);transition:.15s}
.action-btn:hover{border-color:var(--primary);color:var(--primary);background:var(--bg)}
.action-btn.del:hover{border-color:var(--danger);color:var(--danger)}
.fav-btn.active{color:#f6ad55}
.empty-state{text-align:center;padding:4rem 2rem;color:var(--muted)}
.empty-state i{font-size:3rem;margin-bottom:1rem;display:block}
.empty-state h3{font-size:1.1rem;font-weight:700;margin-bottom:.5rem;color:var(--text)}

/* MODAL */
.overlay{position:fixed;inset:0;background:rgba(0,0,0,.5);display:none;align-items:center;justify-content:center;z-index:1000;padding:1rem;backdrop-filter:blur(4px)}
.overlay.open{display:flex}
.modal{background:var(--white);border-radius:var(--radius);width:100%;max-width:560px;max-height:90vh;overflow-y:auto;box-shadow:0 20px 60px rgba(0,0,0,.2)}
.modal-head{padding:1.5rem;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;position:sticky;top:0;background:var(--white);z-index:1}
.modal-head h2{font-size:1.1rem;font-weight:700}
.modal-close{background:none;border:none;cursor:pointer;color:var(--muted);font-size:1.1rem;padding:.3rem;border-radius:6px;transition:.2s}
.modal-close:hover{background:var(--bg);color:var(--text)}
.modal-body{padding:1.5rem;display:flex;flex-direction:column;gap:1rem}
.form-row{display:grid;grid-template-columns:1fr 1fr;gap:1rem}
.field{display:flex;flex-direction:column;gap:.4rem}
.field label{font-size:.85rem;font-weight:600}
.field input,.field select,.field textarea{padding:.7rem .9rem;border:1.5px solid var(--border);border-radius:8px;font-size:.875rem;background:var(--bg);color:var(--text);outline:none;transition:.2s;font-family:inherit}
.field input:focus,.field select:focus,.field textarea:focus{border-color:var(--primary);background:var(--white);box-shadow:0 0 0 3px rgba(102,126,234,.1)}
.field textarea{resize:vertical;min-height:80px}
.pw-wrap{position:relative}
.pw-wrap input{padding-right:2.75rem}
.pw-toggle{position:absolute;right:.75rem;top:50%;transform:translateY(-50%);background:none;border:none;cursor:pointer;color:var(--muted);transition:.2s}
.pw-toggle:hover{color:var(--primary)}
.pw-gen-btn{position:absolute;right:2.5rem;top:50%;transform:translateY(-50%);background:none;border:none;cursor:pointer;color:var(--muted);transition:.2s;font-size:.8rem}
.pw-gen-btn:hover{color:var(--primary)}
.strength-inline{margin-top:.4rem}
.modal-foot{padding:1.25rem 1.5rem;border-top:1px solid var(--border);display:flex;justify-content:flex-end;gap:.75rem;background:var(--white);position:sticky;bottom:0}
.master-section{background:rgba(102,126,234,.05);border:1px solid rgba(102,126,234,.2);border-radius:8px;padding:1rem}
.master-section .field label{color:var(--primary)}
.separator{border:none;border-top:1px solid var(--border)}

/* CONFIRM DELETE MODAL */
.confirm-modal{max-width:420px}
.confirm-icon{text-align:center;padding:1rem 0;font-size:2.5rem;color:var(--danger)}

/* NOTIFICATIONS */
.notif-container{position:fixed;top:1.5rem;right:1.5rem;z-index:9999;display:flex;flex-direction:column;gap:.5rem}
.notif{background:var(--white);border-radius:10px;padding:.85rem 1.25rem;box-shadow:0 4px 20px rgba(0,0,0,.12);display:flex;align-items:center;gap:.75rem;transform:translateX(120%);transition:.35s cubic-bezier(.34,1.56,.64,1);border-left:4px solid var(--primary);font-size:.875rem;max-width:320px}
.notif.show{transform:translateX(0)}
.notif.success{border-left-color:var(--success)}
.notif.error{border-left-color:var(--danger)}
.notif.warning{border-left-color:var(--warning)}

@media(max-width:768px){
    .sidebar{transform:translateX(-100%)}
    .sidebar.open{transform:none}
    .main{margin-left:0}
    .vault-header,.pwd-row{grid-template-columns:1fr 100px}
    .col-date,.col-strength{display:none}
    .form-row{grid-template-columns:1fr}
}
</style>
</head>
<body>
<!-- SIDEBAR -->
<nav class="sidebar" id="sidebar">
    <a href="dashboard.php" class="sidebar-logo"><i class="fas fa-shield-alt"></i>SecurePass</a>
    <div class="sidebar-nav">
        <ul style="list-style:none">
            <li class="nav-item"><a href="dashboard.php"><i class="fas fa-home"></i>Dashboard</a></li>
            <li class="nav-item active"><a href="vault.php"><i class="fas fa-lock"></i>Coffre-fort</a></li>
            <li class="nav-item"><a href="../includes/password_generator.php"><i class="fas fa-key"></i>Générateur</a></li>
            <li class="nav-item"><a href="settings.php"><i class="fas fa-cog"></i>Paramètres</a></li>
        </ul>
    </div>
    <div class="sidebar-footer">
        <a href="../includes/auth.php?action=logout" class="logout-btn"><i class="fas fa-sign-out-alt"></i>Déconnexion</a>
    </div>
</nav>

<!-- MAIN -->
<main class="main">
    <div class="topbar">
        <div class="topbar-left">
            <h1>🔐 Mon Coffre-fort</h1>
            <p>Bonjour <?= $username ?>, vous avez <?= $total_passwords ?> identifiant(s) enregistré(s).</p>
        </div>
        <div class="topbar-right">
            <button id="themeToggle" class="btn btn-ghost" title="Thème"><i class="fas fa-moon" id="themeIcon"></i></button>
            <button class="btn btn-primary" onclick="openAddModal()"><i class="fas fa-plus"></i>Ajouter</button>
        </div>
    </div>

    <!-- STATS -->
    <div class="stats">
        <div class="stat-card">
            <div class="stat-icon blue"><i class="fas fa-key"></i></div>
            <div><div class="stat-label">Total</div><div class="stat-value"><?= $total_passwords ?></div></div>
        </div>
        <div class="stat-card">
            <div class="stat-icon green"><i class="fas fa-shield-alt"></i></div>
            <div><div class="stat-label">Forts</div><div class="stat-value"><?= $strong_count ?></div></div>
        </div>
        <div class="stat-card">
            <div class="stat-icon orange"><i class="fas fa-exclamation-triangle"></i></div>
            <div><div class="stat-label">Faibles</div><div class="stat-value"><?= $weak_count ?></div></div>
        </div>
        <div class="stat-card">
            <div class="stat-icon red"><i class="fas fa-virus"></i></div>
            <div><div class="stat-label">Compromis</div><div class="stat-value"><?= $compromised_count ?></div></div>
        </div>
    </div>

    <!-- TOOLBAR -->
    <div class="toolbar">
        <div class="search-wrap">
            <i class="fas fa-search"></i>
            <input type="text" id="searchInput" placeholder="Rechercher un site, login, email…">
        </div>
        <select id="catFilter" class="filter-select">
            <option value="">Toutes les catégories</option>
            <?php foreach ($categories as $cat): ?>
                <option value="<?= htmlspecialchars($cat) ?>"><?= htmlspecialchars($cat) ?></option>
            <?php endforeach ?>
        </select>
        <select id="sortSelect" class="filter-select">
            <option value="name">Trier : Nom A→Z</option>
            <option value="date">Trier : Plus récent</option>
            <option value="strength">Trier : Force</option>
        </select>
    </div>

    <!-- VAULT -->
    <div class="vault">
        <div class="vault-header">
            <div>Site / Service</div>
            <div class="col-date">Modifié</div>
            <div class="col-strength">Force</div>
            <div style="text-align:right">Actions</div>
        </div>
        <div id="pwdList">
        <?php if (empty($all_passwords)): ?>
            <div class="empty-state">
                <i class="fas fa-lock-open"></i>
                <h3>Votre coffre-fort est vide</h3>
                <p>Cliquez sur <strong>Ajouter</strong> pour enregistrer votre premier identifiant.</p>
            </div>
        <?php else: ?>
            <?php foreach ($all_passwords as $p):
                [$label, $color] = strength_badge($p['strength_score']);
                $domain = '';
                if (!empty($p['site_url'])) {
                    $host = parse_url($p['site_url'], PHP_URL_HOST);
                    $domain = $host ? $host : '';
                }
            ?>
            <div class="pwd-row"
                 data-id="<?= $p['id'] ?>"
                 data-name="<?= strtolower(htmlspecialchars($p['site_name'])) ?>"
                 data-cat="<?= htmlspecialchars($p['category'] ?? '') ?>"
                 data-strength="<?= (int)($p['strength_score'] ?? 0) ?>"
                 data-date="<?= $p['updated_at'] ?>">
                <div class="site-info">
                    <div class="site-favicon">
                        <?php if ($domain): ?>
                            <img src="https://www.google.com/s2/favicons?domain=<?= urlencode($domain) ?>&sz=32"
                                 onerror="this.style.display='none';this.nextElementSibling.style.display='flex'"
                                 alt="">
                            <span style="display:none"><i class="fas fa-globe"></i></span>
                        <?php else: ?>
                            <i class="fas fa-globe"></i>
                        <?php endif ?>
                    </div>
                    <div>
                        <div class="site-name"><?= htmlspecialchars($p['site_name']) ?></div>
                        <div class="site-meta"><?= htmlspecialchars($p['username'] ?: $p['email'] ?: '—') ?></div>
                    </div>
                </div>
                <div class="col-date" style="font-size:.8rem;color:var(--muted)"><?= format_time_ago($p['updated_at']) ?></div>
                <div class="col-strength"><span class="strength-badge" style="background:<?= $color ?>"><?= $label ?></span></div>
                <div class="actions-cell">
                    <button class="action-btn fav-btn <?= $p['is_favorite'] ? 'active' : '' ?>"
                            onclick="toggleFavorite(<?= $p['id'] ?>, this)" title="Favori">
                        <i class="fas fa-star"></i>
                    </button>
                    <button class="action-btn" onclick="copyPassword(<?= $p['id'] ?>)" title="Copier le mot de passe">
                        <i class="fas fa-copy"></i>
                    </button>
                    <button class="action-btn" onclick="openEditModal(<?= $p['id'] ?>)" title="Modifier">
                        <i class="fas fa-edit"></i>
                    </button>
                    <button class="action-btn del" onclick="openDeleteModal(<?= $p['id'] ?>, '<?= addslashes(htmlspecialchars($p['site_name'])) ?>')" title="Supprimer">
                        <i class="fas fa-trash"></i>
                    </button>
                </div>
            </div>
            <?php endforeach ?>
        <?php endif ?>
        </div>
    </div>
</main>

<!-- MODAL AJOUTER / MODIFIER -->
<div class="overlay" id="formOverlay">
<div class="modal">
    <div class="modal-head">
        <h2 id="modalTitle">Ajouter un identifiant</h2>
        <button class="modal-close" onclick="closeFormModal()"><i class="fas fa-times"></i></button>
    </div>
    <div class="modal-body">
        <input type="hidden" id="entryId" value="">
        <div class="form-row">
            <div class="field">
                <label>Site / Service *</label>
                <input type="text" id="fSiteName" placeholder="Google, GitHub…" required>
            </div>
            <div class="field">
                <label>URL</label>
                <input type="url" id="fSiteUrl" placeholder="https://example.com">
            </div>
        </div>
        <div class="form-row">
            <div class="field">
                <label>Identifiant / Login</label>
                <input type="text" id="fUsername" placeholder="jean.dupont" autocomplete="off">
            </div>
            <div class="field">
                <label>Email</label>
                <input type="email" id="fEmail" placeholder="jean@example.com" autocomplete="off">
            </div>
        </div>
        <div class="field">
            <label>Mot de passe *</label>
            <div class="pw-wrap">
                <input type="password" id="fPassword" placeholder="••••••••••••" autocomplete="new-password">
                <button type="button" class="pw-gen-btn" onclick="generateAndFill()" title="Générer un mot de passe">
                    <i class="fas fa-magic"></i>
                </button>
                <button type="button" class="pw-toggle" onclick="togglePw('fPassword', this)" title="Afficher">
                    <i class="fas fa-eye"></i>
                </button>
            </div>
            <div id="strengthContainer" class="strength-inline"></div>
        </div>
        <div class="form-row">
            <div class="field">
                <label>Catégorie</label>
                <select id="fCategory">
                    <option>Général</option>
                    <option>Réseaux sociaux</option>
                    <option>Banque & Finance</option>
                    <option>Travail</option>
                    <option>Shopping</option>
                    <option>Email</option>
                    <option>Autre</option>
                </select>
            </div>
        </div>
        <div class="field">
            <label>Notes</label>
            <textarea id="fNotes" placeholder="Informations supplémentaires (optionnel)"></textarea>
        </div>
        <hr class="separator">
        <div class="master-section">
            <div class="field">
                <label><i class="fas fa-shield-alt"></i> Mot de passe maître <small>(requis pour chiffrer)</small></label>
                <div class="pw-wrap">
                    <input type="password" id="fMasterPw" placeholder="Votre mot de passe de connexion" autocomplete="current-password">
                    <button type="button" class="pw-toggle" onclick="togglePw('fMasterPw', this)">
                        <i class="fas fa-eye"></i>
                    </button>
                </div>
            </div>
        </div>
    </div>
    <div class="modal-foot">
        <button class="btn btn-ghost" onclick="closeFormModal()">Annuler</button>
        <button class="btn btn-primary" id="saveBtn" onclick="saveEntry()">
            <i class="fas fa-save"></i> Enregistrer
        </button>
    </div>
</div>
</div>

<!-- MODAL COPIER (master password) -->
<div class="overlay" id="copyOverlay">
<div class="modal" style="max-width:420px">
    <div class="modal-head">
        <h2>Vérification de sécurité</h2>
        <button class="modal-close" onclick="closeCopyModal()"><i class="fas fa-times"></i></button>
    </div>
    <div class="modal-body">
        <p style="color:var(--muted);font-size:.875rem">Entrez votre mot de passe maître pour déchiffrer et copier ce mot de passe.</p>
        <div class="field">
            <label>Mot de passe maître</label>
            <div class="pw-wrap">
                <input type="password" id="copyMasterPw" placeholder="••••••••" autocomplete="current-password">
                <button type="button" class="pw-toggle" onclick="togglePw('copyMasterPw',this)"><i class="fas fa-eye"></i></button>
            </div>
        </div>
    </div>
    <div class="modal-foot">
        <button class="btn btn-ghost" onclick="closeCopyModal()">Annuler</button>
        <button class="btn btn-primary" onclick="submitCopy()"><i class="fas fa-copy"></i> Copier</button>
    </div>
</div>
</div>

<!-- MODAL SUPPRIMER -->
<div class="overlay" id="deleteOverlay">
<div class="modal confirm-modal">
    <div class="modal-head">
        <h2>Confirmer la suppression</h2>
        <button class="modal-close" onclick="closeDeleteModal()"><i class="fas fa-times"></i></button>
    </div>
    <div class="modal-body">
        <div class="confirm-icon"><i class="fas fa-exclamation-triangle"></i></div>
        <p style="text-align:center;color:var(--muted)">
            Voulez-vous vraiment supprimer l'entrée <strong id="deleteEntryName"></strong> ?<br>
            <small>Cette action est irréversible.</small>
        </p>
    </div>
    <div class="modal-foot">
        <button class="btn btn-ghost" onclick="closeDeleteModal()">Annuler</button>
        <button class="btn btn-danger" onclick="submitDelete()"><i class="fas fa-trash"></i> Supprimer</button>
    </div>
</div>
</div>

<!-- NOTIFICATIONS -->
<div class="notif-container" id="notifContainer"></div>

<!-- DONNÉES PHP pour JS -->
<script>
const CSRF_TOKEN = <?= json_encode($_SESSION['csrf_token']) ?>;
const API_SAVE   = '../api/save_password.php';
const API_DECRYPT = '../includes/api_decrypt_password.php';
</script>
<script>
/* ============================================================
   THÈME
============================================================ */
(function(){
    const dark = localStorage.getItem('theme') === 'dark';
    if (dark) document.body.classList.add('dark-mode');
    document.getElementById('themeIcon').className = dark ? 'fas fa-sun' : 'fas fa-moon';
})();
document.getElementById('themeToggle').addEventListener('click', () => {
    const d = document.body.classList.toggle('dark-mode');
    document.getElementById('themeIcon').className = d ? 'fas fa-sun' : 'fas fa-moon';
    localStorage.setItem('theme', d ? 'dark' : 'light');
});

/* ============================================================
   NOTIFICATIONS
============================================================ */
function notify(msg, type='info') {
    const icons = {success:'fa-check-circle',error:'fa-exclamation-circle',warning:'fa-exclamation-triangle',info:'fa-info-circle'};
    const el = document.createElement('div');
    el.className = `notif ${type}`;
    el.innerHTML = `<i class="fas ${icons[type]||icons.info}" style="color:var(--${type==='info'?'primary':type})"></i><span>${msg}</span>`;
    document.getElementById('notifContainer').appendChild(el);
    requestAnimationFrame(() => el.classList.add('show'));
    setTimeout(() => { el.classList.remove('show'); setTimeout(()=>el.remove(), 400); }, 4000);
}

/* ============================================================
   UTILITAIRES
============================================================ */
function togglePw(id, btn) {
    const inp = document.getElementById(id);
    const show = inp.type === 'password';
    inp.type = show ? 'text' : 'password';
    btn.innerHTML = `<i class="fas fa-eye${show?'-slash':''}"></i>`;
}

async function apiPost(url, body) {
    const r = await fetch(url, {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({csrf_token: CSRF_TOKEN, ...body})
    });
    return r.json();
}

/* ============================================================
   RECHERCHE / FILTRES
============================================================ */
function applyFilters() {
    const q     = document.getElementById('searchInput').value.toLowerCase();
    const cat   = document.getElementById('catFilter').value;
    const sort  = document.getElementById('sortSelect').value;
    const rows  = [...document.querySelectorAll('.pwd-row')];

    rows.forEach(row => {
        const nameMatch = row.dataset.name.includes(q);
        const catMatch  = !cat || row.dataset.cat === cat;
        row.style.display = (nameMatch && catMatch) ? '' : 'none';
    });

    const visible = rows.filter(r => r.style.display !== 'none');
    visible.sort((a,b) => {
        if (sort === 'name') return a.dataset.name.localeCompare(b.dataset.name);
        if (sort === 'date') return new Date(b.dataset.date) - new Date(a.dataset.date);
        if (sort === 'strength') return b.dataset.strength - a.dataset.strength;
    });
    const list = document.getElementById('pwdList');
    visible.forEach(r => list.appendChild(r));
}
['searchInput','catFilter','sortSelect'].forEach(id =>
    document.getElementById(id).addEventListener('input', applyFilters)
);

/* ============================================================
   JAUGE DE FORCE INLINE (sans dépendance externe)
============================================================ */
const LEVELS = [
    {label:'Très faible',color:'#e53e3e',w:'10%'},
    {label:'Faible',     color:'#f56565',w:'25%'},
    {label:'Moyen',      color:'#ed8936',w:'50%'},
    {label:'Fort',       color:'#48bb78',w:'75%'},
    {label:'Très fort',  color:'#38a169',w:'100%'},
];
function scorePassword(p) {
    if (!p) return -1;
    let s = 0;
    if (p.length >= 16) s += 2; else if (p.length >= 12) s += 1;
    if (/[a-z]/.test(p)) s++; if (/[A-Z]/.test(p)) s++;
    if (/[0-9]/.test(p)) s++; if (/[^a-zA-Z0-9]/.test(p)) s++;
    if (/(.)\1{2,}/.test(p)) s--;
    if (/^(123|abc|qwerty|password|azerty)/i.test(p)) s -= 2;
    return Math.min(4, Math.max(0, Math.round((s/7)*4)));
}
function renderStrength(pw, containerId) {
    const c = document.getElementById(containerId);
    if (!c) return;
    if (!pw) { c.innerHTML=''; return; }
    const idx = scorePassword(pw);
    const lvl = LEVELS[Math.max(0,idx)];
    c.innerHTML = `<div style="margin-top:.4rem">
      <div style="height:5px;background:#e2e8f0;border-radius:99px;overflow:hidden">
        <div style="width:${lvl.w};height:100%;background:${lvl.color};transition:.3s"></div>
      </div>
      <span style="font-size:.75rem;color:${lvl.color};font-weight:700">${lvl.label}</span>
    </div>`;
}
document.getElementById('fPassword').addEventListener('input', function() {
    renderStrength(this.value, 'strengthContainer');
});

/* ============================================================
   GÉNÉRATEUR RAPIDE
============================================================ */
function generateAndFill() {
    const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=';
    const arr = new Uint8Array(20);
    crypto.getRandomValues(arr);
    const pwd = Array.from(arr, b => chars[b % chars.length]).join('');
    const inp = document.getElementById('fPassword');
    inp.type = 'text';
    inp.value = pwd;
    renderStrength(pwd, 'strengthContainer');
    notify('Mot de passe généré !', 'success');
}

/* ============================================================
   MODAL AJOUTER
============================================================ */
function openAddModal() {
    document.getElementById('modalTitle').textContent = 'Ajouter un identifiant';
    document.getElementById('entryId').value = '';
    ['fSiteName','fSiteUrl','fUsername','fEmail','fPassword','fNotes','fMasterPw'].forEach(id => {
        document.getElementById(id).value = '';
    });
    document.getElementById('fCategory').value = 'Général';
    document.getElementById('strengthContainer').innerHTML = '';
    document.getElementById('formOverlay').classList.add('open');
    document.getElementById('fSiteName').focus();
}

function closeFormModal() {
    document.getElementById('formOverlay').classList.remove('open');
}

/* ============================================================
   MODAL MODIFIER
============================================================ */
const rowData = {};
<?php foreach ($all_passwords as $p): ?>
rowData[<?= $p['id'] ?>] = {
    site_name: <?= json_encode($p['site_name']) ?>,
    site_url:  <?= json_encode($p['site_url'] ?? '') ?>,
    username:  <?= json_encode($p['username'] ?? '') ?>,
    email:     <?= json_encode($p['email'] ?? '') ?>,
    notes:     <?= json_encode($p['notes'] ?? '') ?>,
    category:  <?= json_encode($p['category'] ?? 'Général') ?>,
};
<?php endforeach ?>

function openEditModal(id) {
    const d = rowData[id];
    if (!d) return;
    document.getElementById('modalTitle').textContent = 'Modifier l\'identifiant';
    document.getElementById('entryId').value = id;
    document.getElementById('fSiteName').value  = d.site_name;
    document.getElementById('fSiteUrl').value   = d.site_url;
    document.getElementById('fUsername').value  = d.username;
    document.getElementById('fEmail').value     = d.email;
    document.getElementById('fPassword').value  = '';
    document.getElementById('fNotes').value     = d.notes;
    document.getElementById('fMasterPw').value  = '';
    document.getElementById('fCategory').value  = d.category || 'Général';
    document.getElementById('strengthContainer').innerHTML = '';
    document.getElementById('formOverlay').classList.add('open');
    document.getElementById('fSiteName').focus();
}

/* ============================================================
   SAUVEGARDER (add ou edit)
============================================================ */
async function saveEntry() {
    const id          = document.getElementById('entryId').value;
    const site_name   = document.getElementById('fSiteName').value.trim();
    const password    = document.getElementById('fPassword').value;
    const master_password = document.getElementById('fMasterPw').value;

    if (!site_name) { notify('Le nom du site est obligatoire.', 'warning'); return; }
    if (!id && !password) { notify('Le mot de passe est obligatoire.', 'warning'); return; }
    if (!id && !master_password) { notify('Le mot de passe maître est requis.', 'warning'); return; }
    if (password && !master_password) { notify('Entrez votre mot de passe maître pour chiffrer.', 'warning'); return; }

    const btn = document.getElementById('saveBtn');
    btn.disabled = true;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Enregistrement…';

    const payload = {
        action: id ? 'edit' : 'add',
        site_name,
        site_url:        document.getElementById('fSiteUrl').value.trim(),
        username:        document.getElementById('fUsername').value.trim(),
        email:           document.getElementById('fEmail').value.trim(),
        password,
        notes:           document.getElementById('fNotes').value.trim(),
        category:        document.getElementById('fCategory').value,
        master_password,
    };
    if (id) payload.id = parseInt(id);

    try {
        const data = await apiPost(API_SAVE, payload);
        if (data.success) {
            notify(data.message, 'success');
            closeFormModal();
            setTimeout(() => location.reload(), 800);
        } else {
            notify(data.message || 'Erreur.', 'error');
        }
    } catch(e) {
        notify('Erreur réseau : ' + e.message, 'error');
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<i class="fas fa-save"></i> Enregistrer';
    }
}

/* ============================================================
   COPIER UN MOT DE PASSE
============================================================ */
let pendingCopyId = null;
function copyPassword(id) {
    pendingCopyId = id;
    document.getElementById('copyMasterPw').value = '';
    document.getElementById('copyOverlay').classList.add('open');
    setTimeout(() => document.getElementById('copyMasterPw').focus(), 100);
}
function closeCopyModal() {
    document.getElementById('copyOverlay').classList.remove('open');
    pendingCopyId = null;
}
async function submitCopy() {
    const master = document.getElementById('copyMasterPw').value;
    if (!master) { notify('Entrez votre mot de passe maître.', 'warning'); return; }
    try {
        const r = await fetch(API_DECRYPT, {
            method: 'POST',
            headers: {'Content-Type':'application/x-www-form-urlencoded'},
            body: `password_id=${pendingCopyId}&master_password=${encodeURIComponent(master)}`
        });
        const data = await r.json();
        if (data.success && data.password) {
            await navigator.clipboard.writeText(data.password);
            notify('Mot de passe copié dans le presse-papiers !', 'success');
            closeCopyModal();
        } else {
            notify(data.error || 'Mot de passe maître incorrect.', 'error');
        }
    } catch(e) { notify('Erreur réseau.', 'error'); }
}
document.getElementById('copyMasterPw').addEventListener('keydown', e => {
    if (e.key === 'Enter') submitCopy();
});

/* ============================================================
   SUPPRIMER
============================================================ */
let pendingDeleteId = null;
function openDeleteModal(id, name) {
    pendingDeleteId = id;
    document.getElementById('deleteEntryName').textContent = name;
    document.getElementById('deleteOverlay').classList.add('open');
}
function closeDeleteModal() {
    document.getElementById('deleteOverlay').classList.remove('open');
    pendingDeleteId = null;
}
async function submitDelete() {
    if (!pendingDeleteId) return;
    try {
        const data = await apiPost(API_SAVE, {action:'delete', id: pendingDeleteId});
        if (data.success) {
            closeDeleteModal();
            const row = document.querySelector(`.pwd-row[data-id="${pendingDeleteId}"]`);
            if (row) { row.style.opacity='0'; row.style.transform='translateX(20px)'; setTimeout(()=>row.remove(), 300); }
            notify('Entrée supprimée.', 'success');
        } else {
            notify(data.message || 'Erreur lors de la suppression.', 'error');
        }
    } catch(e) { notify('Erreur réseau.', 'error'); }
}

/* ============================================================
   FAVORIS (toggle rapide sans rechiffrement)
============================================================ */
async function toggleFavorite(id, btn) {
    const isActive = btn.classList.contains('active');
    // Pas d'API dédiée, on passe par save_password avec un champ spécial — 
    // on fait un POST direct SQL light via un endpoint dédié ou on recharge
    try {
        const r = await fetch('../api/toggle_favorite.php', {
            method: 'POST',
            headers: {'Content-Type':'application/json'},
            body: JSON.stringify({csrf_token: CSRF_TOKEN, id, favorite: !isActive})
        });
        const data = await r.json();
        if (data.success) {
            btn.classList.toggle('active');
        }
    } catch(e) { /* ignore */ }
}

/* FERMETURE overlay au clic extérieur */
['formOverlay','copyOverlay','deleteOverlay'].forEach(id => {
    document.getElementById(id).addEventListener('click', function(e) {
        if (e.target === this) this.classList.remove('open');
    });
});
document.addEventListener('keydown', e => {
    if (e.key === 'Escape') {
        ['formOverlay','copyOverlay','deleteOverlay'].forEach(id =>
            document.getElementById(id).classList.remove('open')
        );
    }
});

/* Messages de session */
<?php if (!empty($_SESSION['success_message'])): ?>
    notify(<?= json_encode($_SESSION['success_message']) ?>, 'success');
    <?php unset($_SESSION['success_message']); ?>
<?php endif ?>
<?php if (!empty($_SESSION['error_message'])): ?>
    notify(<?= json_encode($_SESSION['error_message']) ?>, 'error');
    <?php unset($_SESSION['error_message']); ?>
<?php endif ?>
</script>
</body>
</html>
