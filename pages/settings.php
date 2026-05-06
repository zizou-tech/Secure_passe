<?php
session_start();
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../includes/crypto.php';

header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');

if (!isset($_SESSION['user_id'])) {
    header('Location: login.php'); exit();
}
$user_id = (int) $_SESSION['user_id'];

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Charger l'utilisateur
$stmt = mysqli_prepare($link, "SELECT prenom, nom, email FROM users WHERE id = ?");
mysqli_stmt_bind_param($stmt,'i',$user_id);
mysqli_stmt_execute($stmt);
$user = mysqli_fetch_assoc(mysqli_stmt_get_result($stmt));
mysqli_stmt_close($stmt);
if (!$user) { header('Location: login.php'); exit(); }

$aes = new AES256Encryption();
$msg_type = '';
$msg_text = '';

// Consommer messages session
if (!empty($_SESSION['success_message'])) { $msg_type='success'; $msg_text=$_SESSION['success_message']; unset($_SESSION['success_message']); }
if (!empty($_SESSION['error_message']))   { $msg_type='error';   $msg_text=$_SESSION['error_message'];   unset($_SESSION['error_message']); }

/* ============================================================
   TRAITEMENT FORMULAIRES (POST)
============================================================ */
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $csrf = $_POST['csrf_token'] ?? '';
    if (!hash_equals($_SESSION['csrf_token'], $csrf)) {
        $msg_type='error'; $msg_text='Token CSRF invalide.';
    } else {
        $form = $_POST['form'] ?? '';

        // --- PROFIL ---
        if ($form === 'profile') {
            $prenom = trim($_POST['prenom'] ?? '');
            $nom    = trim($_POST['nom'] ?? '');
            if (empty($prenom) || empty($nom)) {
                $msg_type='error'; $msg_text='Prénom et nom obligatoires.';
            } elseif (!preg_match('/^[a-zA-ZÀ-ÿ\s\-\']{2,100}$/', $prenom) || !preg_match('/^[a-zA-ZÀ-ÿ\s\-\']{2,100}$/', $nom)) {
                $msg_type='error'; $msg_text='Nom ou prénom invalide.';
            } else {
                $stmt = mysqli_prepare($link,"UPDATE users SET prenom=?, nom=?, updated_at=NOW() WHERE id=?");
                mysqli_stmt_bind_param($stmt,'ssi',$prenom,$nom,$user_id);
                mysqli_stmt_execute($stmt);
                $user['prenom'] = $prenom; $user['nom'] = $nom;
                $_SESSION['username'] = $prenom;
                $msg_type='success'; $msg_text='Profil mis à jour.';
            }
        }

        // --- EMAIL ---
        if ($form === 'email') {
            $new_email  = trim($_POST['new_email'] ?? '');
            $cur_pw     = $_POST['current_password'] ?? '';
            if (!filter_var($new_email, FILTER_VALIDATE_EMAIL)) {
                $msg_type='error'; $msg_text='Adresse email invalide.';
            } else {
                // Vérifier mot de passe
                $stmt = mysqli_prepare($link,"SELECT password_hash FROM users WHERE id=?");
                mysqli_stmt_bind_param($stmt,'i',$user_id);
                mysqli_stmt_execute($stmt);
                $row = mysqli_fetch_assoc(mysqli_stmt_get_result($stmt));
                if (!$row || !password_verify($cur_pw,$row['password_hash'])) {
                    $msg_type='error'; $msg_text='Mot de passe actuel incorrect.';
                } else {
                    // Vérifier unicité email
                    $stmt2 = mysqli_prepare($link,"SELECT id FROM users WHERE email=? AND id!=?");
                    mysqli_stmt_bind_param($stmt2,'si',$new_email,$user_id);
                    mysqli_stmt_execute($stmt2);
                    mysqli_stmt_store_result($stmt2);
                    if (mysqli_stmt_num_rows($stmt2) > 0) {
                        $msg_type='error'; $msg_text='Cet email est déjà utilisé par un autre compte.';
                    } else {
                        $stmt3 = mysqli_prepare($link,"UPDATE users SET email=?, updated_at=NOW() WHERE id=?");
                        mysqli_stmt_bind_param($stmt3,'si',$new_email,$user_id);
                        mysqli_stmt_execute($stmt3);
                        $user['email'] = $new_email;
                        $_SESSION['user_email'] = $new_email;
                        $msg_type='success'; $msg_text='Email mis à jour.';
                    }
                }
            }
        }

        // --- MOT DE PASSE MAÎTRE ---
        if ($form === 'password') {
            $cur_pw  = $_POST['current_password'] ?? '';
            $new_pw  = $_POST['new_password'] ?? '';
            $conf_pw = $_POST['confirm_password'] ?? '';
            // Vérifications
            $stmt = mysqli_prepare($link,"SELECT password_hash FROM users WHERE id=?");
            mysqli_stmt_bind_param($stmt,'i',$user_id);
            mysqli_stmt_execute($stmt);
            $row = mysqli_fetch_assoc(mysqli_stmt_get_result($stmt));
            if (!$row || !password_verify($cur_pw,$row['password_hash'])) {
                $msg_type='error'; $msg_text='Mot de passe actuel incorrect.';
            } elseif ($new_pw !== $conf_pw) {
                $msg_type='error'; $msg_text='Les nouveaux mots de passe ne correspondent pas.';
            } elseif (strlen($new_pw) < 12 || !preg_match('/[A-Z]/',$new_pw) || !preg_match('/[a-z]/',$new_pw) || !preg_match('/\d/',$new_pw) || !preg_match('/[^a-zA-Z0-9]/',$new_pw)) {
                $msg_type='error'; $msg_text='Le nouveau mot de passe doit contenir au moins 12 caractères, une majuscule, un chiffre et un caractère spécial.';
            } else {
                // ⚠️ Note : changer le mot de passe maître invalide tous les mots de passe chiffrés.
                // Pour une vraie app, il faudrait rechiffrer toutes les entrées.
                // Ici on avertit l'utilisateur et on met à jour uniquement le hash de connexion.
                $new_hash = password_hash($new_pw, PASSWORD_BCRYPT, ['cost' => 12]);
                $stmt2 = mysqli_prepare($link,"UPDATE users SET password_hash=?, updated_at=NOW() WHERE id=?");
                mysqli_stmt_bind_param($stmt2,'si',$new_hash,$user_id);
                mysqli_stmt_execute($stmt2);
                $msg_type='success'; $msg_text='Mot de passe mis à jour. ⚠️ Attention : les mots de passe déjà enregistrés dans le coffre devront être re-saisis car ils étaient chiffrés avec l\'ancien mot de passe.';
            }
        }

        // --- SUPPRIMER LE COMPTE ---
        if ($form === 'delete_account') {
            $confirm_pw = $_POST['confirm_delete_password'] ?? '';
            $stmt = mysqli_prepare($link,"SELECT password_hash FROM users WHERE id=?");
            mysqli_stmt_bind_param($stmt,'i',$user_id);
            mysqli_stmt_execute($stmt);
            $row = mysqli_fetch_assoc(mysqli_stmt_get_result($stmt));
            if (!$row || !password_verify($confirm_pw,$row['password_hash'])) {
                $msg_type='error'; $msg_text='Mot de passe incorrect. Suppression annulée.';
            } else {
                $stmt2 = mysqli_prepare($link,"DELETE FROM users WHERE id=?");
                mysqli_stmt_bind_param($stmt2,'i',$user_id);
                mysqli_stmt_execute($stmt2);
                session_destroy();
                header('Location: login.php?deleted=1'); exit();
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Paramètres — SecurePass</title>
<link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
<style>
:root{--primary:#667eea;--primary-dark:#764ba2;--success:#48bb78;--danger:#f56565;--warning:#ed8936;--text:#2d3748;--muted:#718096;--bg:#f7fafc;--white:#fff;--border:#e2e8f0;--radius:12px;--sidebar:270px}
body.dark-mode{--text:#f7fafc;--muted:#a0aec0;--bg:#1a202c;--white:#2d3748;--border:#4a5568}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Inter',sans-serif;background:var(--bg);color:var(--text);display:flex;min-height:100vh}
.sidebar{width:var(--sidebar);background:var(--white);border-right:1px solid var(--border);display:flex;flex-direction:column;position:fixed;height:100vh;left:0;top:0;z-index:200}
.sidebar-logo{padding:1.75rem 1.5rem;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:.75rem;font-size:1.3rem;font-weight:800;color:var(--primary);text-decoration:none}
.sidebar-nav{flex:1;padding:1rem 0}
.nav-item a{display:flex;align-items:center;gap:.9rem;padding:.85rem 1.5rem;color:var(--muted);text-decoration:none;transition:.2s;border-left:3px solid transparent;font-size:.9rem}
.nav-item a:hover{color:var(--primary);background:var(--bg)}
.nav-item.active a{color:var(--primary);border-left-color:var(--primary);font-weight:600;background:var(--bg)}
.sidebar-footer{padding:1.25rem 1.5rem;border-top:1px solid var(--border)}
.logout-btn{display:flex;align-items:center;gap:.75rem;color:var(--danger);text-decoration:none;font-size:.9rem;padding:.5rem;border-radius:8px;transition:.2s}
.logout-btn:hover{background:rgba(245,101,101,.08)}
.main{flex:1;margin-left:var(--sidebar);padding:2.5rem;max-width:900px}
h1{font-size:1.75rem;font-weight:800;margin-bottom:.25rem}
.page-sub{color:var(--muted);margin-bottom:2rem;font-size:.9rem}
.section{background:var(--white);border:1px solid var(--border);border-radius:var(--radius);margin-bottom:1.5rem;overflow:hidden}
.section-head{padding:1.25rem 1.5rem;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:.75rem}
.section-icon{width:36px;height:36px;border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:.9rem;flex-shrink:0}
.section-icon.blue{background:rgba(102,126,234,.1);color:var(--primary)}
.section-icon.red{background:rgba(245,101,101,.1);color:var(--danger)}
.section-icon.green{background:rgba(72,187,120,.1);color:var(--success)}
.section-icon.orange{background:rgba(237,137,54,.1);color:var(--warning)}
.section-title{font-weight:700;font-size:.95rem}
.section-body{padding:1.5rem}
.form-row{display:grid;grid-template-columns:1fr 1fr;gap:1rem;margin-bottom:1rem}
.field{display:flex;flex-direction:column;gap:.4rem;margin-bottom:.75rem}
.field label{font-size:.85rem;font-weight:600}
.field input{padding:.7rem .9rem;border:1.5px solid var(--border);border-radius:8px;font-size:.875rem;background:var(--bg);color:var(--text);outline:none;transition:.2s}
.field input:focus{border-color:var(--primary);background:var(--white);box-shadow:0 0 0 3px rgba(102,126,234,.1)}
.pw-wrap{position:relative}
.pw-wrap input{padding-right:2.75rem;width:100%}
.pw-toggle{position:absolute;right:.75rem;top:50%;transform:translateY(-50%);background:none;border:none;cursor:pointer;color:var(--muted)}
.btn{display:inline-flex;align-items:center;gap:.5rem;padding:.7rem 1.25rem;border-radius:8px;border:none;font-weight:600;font-size:.875rem;cursor:pointer;transition:.2s;text-decoration:none}
.btn-primary{background:linear-gradient(135deg,var(--primary),var(--primary-dark));color:#fff}
.btn-primary:hover{transform:translateY(-1px);box-shadow:0 4px 15px rgba(102,126,234,.4)}
.btn-danger{background:rgba(245,101,101,.1);color:var(--danger);border:1px solid rgba(245,101,101,.3)}
.btn-danger:hover{background:var(--danger);color:#fff}
.btn-ghost{background:var(--white);border:1px solid var(--border);color:var(--text)}
.alert{padding:1rem 1.25rem;border-radius:8px;margin-bottom:1.5rem;display:flex;align-items:flex-start;gap:.75rem;font-size:.875rem}
.alert.success{background:rgba(72,187,120,.08);border:1px solid rgba(72,187,120,.3);color:#276749}
.alert.error{background:rgba(245,101,101,.08);border:1px solid rgba(245,101,101,.3);color:#c53030}
.alert.warning{background:rgba(237,137,54,.08);border:1px solid rgba(237,137,54,.3);color:#9c4221}
.danger-zone{border-color:rgba(245,101,101,.3)}
.danger-zone .section-head{background:rgba(245,101,101,.04)}
.strength-bar{height:4px;background:#e2e8f0;border-radius:99px;margin-top:.5rem;overflow:hidden}
.strength-fill{height:100%;border-radius:99px;transition:.3s}
.export-info{font-size:.8rem;color:var(--muted);margin-top:.5rem}
@media(max-width:768px){.sidebar{display:none}.main{margin-left:0}.form-row{grid-template-columns:1fr}}
</style>
</head>
<body>
<nav class="sidebar">
    <a href="dashboard.php" class="sidebar-logo"><i class="fas fa-shield-alt"></i>SecurePass</a>
    <div class="sidebar-nav">
        <ul style="list-style:none">
            <li class="nav-item"><a href="dashboard.php"><i class="fas fa-home"></i>Dashboard</a></li>
            <li class="nav-item"><a href="vault.php"><i class="fas fa-lock"></i>Coffre-fort</a></li>
            <li class="nav-item"><a href="../includes/password_generator.php"><i class="fas fa-key"></i>Générateur</a></li>
            <li class="nav-item active"><a href="settings.php"><i class="fas fa-cog"></i>Paramètres</a></li>
        </ul>
    </div>
    <div class="sidebar-footer">
        <a href="../includes/auth.php?action=logout" class="logout-btn"><i class="fas fa-sign-out-alt"></i>Déconnexion</a>
    </div>
</nav>
<main class="main">
    <h1><i class="fas fa-cog" style="color:var(--primary)"></i> Paramètres</h1>
    <p class="page-sub">Gérez votre compte, votre sécurité et vos préférences.</p>

    <?php if ($msg_text): ?>
    <div class="alert <?= $msg_type ?>">
        <i class="fas <?= $msg_type==='success'?'fa-check-circle':'fa-exclamation-circle' ?>"></i>
        <span><?= htmlspecialchars($msg_text) ?></span>
    </div>
    <?php endif ?>

    <!-- PROFIL -->
    <div class="section">
        <div class="section-head">
            <div class="section-icon blue"><i class="fas fa-user"></i></div>
            <div><div class="section-title">Informations personnelles</div></div>
        </div>
        <div class="section-body">
            <form method="POST">
                <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">
                <input type="hidden" name="form" value="profile">
                <div class="form-row">
                    <div class="field">
                        <label>Prénom</label>
                        <input type="text" name="prenom" value="<?= htmlspecialchars($user['prenom']) ?>" required>
                    </div>
                    <div class="field">
                        <label>Nom</label>
                        <input type="text" name="nom" value="<?= htmlspecialchars($user['nom']) ?>" required>
                    </div>
                </div>
                <button type="submit" class="btn btn-primary"><i class="fas fa-save"></i> Mettre à jour</button>
            </form>
        </div>
    </div>

    <!-- EMAIL -->
    <div class="section">
        <div class="section-head">
            <div class="section-icon green"><i class="fas fa-envelope"></i></div>
            <div><div class="section-title">Adresse email</div></div>
        </div>
        <div class="section-body">
            <p style="font-size:.85rem;color:var(--muted);margin-bottom:1rem">Email actuel : <strong><?= htmlspecialchars($user['email']) ?></strong></p>
            <form method="POST">
                <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">
                <input type="hidden" name="form" value="email">
                <div class="field">
                    <label>Nouvel email</label>
                    <input type="email" name="new_email" placeholder="nouveau@email.com" required>
                </div>
                <div class="field">
                    <label>Mot de passe actuel (confirmation)</label>
                    <div class="pw-wrap">
                        <input type="password" name="current_password" id="ep_cur" placeholder="••••••••" required>
                        <button type="button" class="pw-toggle" onclick="tpw('ep_cur',this)"><i class="fas fa-eye"></i></button>
                    </div>
                </div>
                <button type="submit" class="btn btn-primary"><i class="fas fa-envelope"></i> Changer l'email</button>
            </form>
        </div>
    </div>

    <!-- MOT DE PASSE -->
    <div class="section">
        <div class="section-head">
            <div class="section-icon orange"><i class="fas fa-shield-alt"></i></div>
            <div><div class="section-title">Changer le mot de passe maître</div></div>
        </div>
        <div class="section-body">
            <div class="alert warning">
                <i class="fas fa-exclamation-triangle"></i>
                <span>Changer le mot de passe maître invalide le déchiffrement de vos mots de passe enregistrés. Vous devrez les re-saisir après le changement.</span>
            </div>
            <form method="POST">
                <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">
                <input type="hidden" name="form" value="password">
                <div class="field">
                    <label>Mot de passe actuel</label>
                    <div class="pw-wrap">
                        <input type="password" name="current_password" id="mp_cur" placeholder="••••••••" required>
                        <button type="button" class="pw-toggle" onclick="tpw('mp_cur',this)"><i class="fas fa-eye"></i></button>
                    </div>
                </div>
                <div class="field">
                    <label>Nouveau mot de passe</label>
                    <div class="pw-wrap">
                        <input type="password" name="new_password" id="mp_new" placeholder="••••••••" required oninput="checkStr(this.value)">
                        <button type="button" class="pw-toggle" onclick="tpw('mp_new',this)"><i class="fas fa-eye"></i></button>
                    </div>
                    <div class="strength-bar"><div class="strength-fill" id="strFill"></div></div>
                    <span id="strLabel" style="font-size:.75rem;color:var(--muted)"></span>
                </div>
                <div class="field">
                    <label>Confirmer le nouveau mot de passe</label>
                    <div class="pw-wrap">
                        <input type="password" name="confirm_password" id="mp_conf" placeholder="••••••••" required>
                        <button type="button" class="pw-toggle" onclick="tpw('mp_conf',this)"><i class="fas fa-eye"></i></button>
                    </div>
                </div>
                <button type="submit" class="btn btn-primary"><i class="fas fa-lock"></i> Mettre à jour le mot de passe</button>
            </form>
        </div>
    </div>

    <!-- EXPORT -->
    <div class="section">
        <div class="section-head">
            <div class="section-icon blue"><i class="fas fa-download"></i></div>
            <div><div class="section-title">Exporter le coffre-fort</div></div>
        </div>
        <div class="section-body">
            <p style="font-size:.875rem;color:var(--muted);margin-bottom:1rem">
                Téléchargez une copie de vos identifiants (hors mots de passe chiffrés) au format JSON.
            </p>
            <form method="POST" action="../api/export_vault.php">
                <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">
                <div class="field">
                    <label>Mot de passe maître (requis pour déchiffrer)</label>
                    <div class="pw-wrap">
                        <input type="password" name="master_password" id="exp_pw" placeholder="••••••••" required>
                        <button type="button" class="pw-toggle" onclick="tpw('exp_pw',this)"><i class="fas fa-eye"></i></button>
                    </div>
                </div>
                <button type="submit" class="btn btn-ghost"><i class="fas fa-download"></i> Télécharger en JSON</button>
                <p class="export-info">⚠️ Conservez ce fichier dans un endroit sécurisé. Il contient vos mots de passe en clair.</p>
            </form>
        </div>
    </div>

    <!-- SUPPRIMER LE COMPTE -->
    <div class="section danger-zone">
        <div class="section-head">
            <div class="section-icon red"><i class="fas fa-trash"></i></div>
            <div><div class="section-title" style="color:var(--danger)">Zone dangereuse</div></div>
        </div>
        <div class="section-body">
            <p style="font-size:.875rem;color:var(--muted);margin-bottom:1rem">
                La suppression de votre compte est <strong>irréversible</strong>. Tous vos mots de passe enregistrés seront définitivement effacés.
            </p>
            <form method="POST" onsubmit="return confirm('Êtes-vous ABSOLUMENT sûr(e) de vouloir supprimer votre compte ? Cette action est irréversible.')">
                <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">
                <input type="hidden" name="form" value="delete_account">
                <div class="field">
                    <label>Mot de passe maître (confirmation)</label>
                    <div class="pw-wrap">
                        <input type="password" name="confirm_delete_password" id="del_pw" placeholder="••••••••" required>
                        <button type="button" class="pw-toggle" onclick="tpw('del_pw',this)"><i class="fas fa-eye"></i></button>
                    </div>
                </div>
                <button type="submit" class="btn btn-danger"><i class="fas fa-trash"></i> Supprimer définitivement mon compte</button>
            </form>
        </div>
    </div>
</main>
<script>
function tpw(id,btn){const i=document.getElementById(id);const s=i.type==='password';i.type=s?'text':'password';btn.innerHTML=`<i class="fas fa-eye${s?'-slash':''}"></i>`}

const LEVELS=[
    {l:'Très faible',c:'#e53e3e',w:'10%'},
    {l:'Faible',     c:'#f56565',w:'25%'},
    {l:'Moyen',      c:'#ed8936',w:'50%'},
    {l:'Fort',       c:'#48bb78',w:'75%'},
    {l:'Très fort',  c:'#38a169',w:'100%'},
];
function checkStr(p){
    let s=0;
    if(p.length>=16)s+=2;else if(p.length>=12)s+=1;
    if(/[a-z]/.test(p))s++;if(/[A-Z]/.test(p))s++;
    if(/[0-9]/.test(p))s++;if(/[^a-zA-Z0-9]/.test(p))s++;
    if(/(.)\1{2,}/.test(p))s--;
    const idx=Math.min(4,Math.max(0,Math.round((s/7)*4)));
    const lvl=LEVELS[idx];
    const fill=document.getElementById('strFill');
    const lbl=document.getElementById('strLabel');
    fill.style.width=p?lvl.w:'0';
    fill.style.background=lvl.c;
    lbl.textContent=p?lvl.l:'';
    lbl.style.color=lvl.c;
}
(function(){
    const dark=localStorage.getItem('theme')==='dark';
    if(dark)document.body.classList.add('dark-mode');
})();
</script>
</body>
</html>
