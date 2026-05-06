<?php
ini_set('display_errors', 0);
session_start();

header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('X-XSS-Protection: 1; mode=block');
header('Referrer-Policy: strict-origin-when-cross-origin');

// Déjà connecté → dashboard
if (isset($_SESSION['user_id'])) {
    header('Location: dashboard.php'); exit();
}

// Token CSRF
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

require_once __DIR__ . '/../config/database.php';

$token = trim($_GET['token'] ?? '');
$email = trim($_GET['email'] ?? '');

$error_message   = '';
$success_message = '';
$token_valid     = false;

if (!empty($_SESSION['error_message']))   { $error_message   = $_SESSION['error_message'];   unset($_SESSION['error_message']); }
if (!empty($_SESSION['success_message'])) { $success_message = $_SESSION['success_message']; unset($_SESSION['success_message']); }

// Vérifier le token en base
if ($token && $email) {
    $token_hash = hash('sha256', $token);
    $stmt = mysqli_prepare($link,
        "SELECT id, prenom FROM users WHERE email = ? AND reset_token = ? AND reset_token_expires > NOW()");
    mysqli_stmt_bind_param($stmt, 'ss', $email, $token_hash);
    mysqli_stmt_execute($stmt);
    mysqli_stmt_store_result($stmt);
    $token_valid = mysqli_stmt_num_rows($stmt) > 0;
    mysqli_stmt_close($stmt);
}

if (!$token_valid && empty($error_message)) {
    $error_message = "Ce lien de réinitialisation est invalide ou a expiré.";
}
?>
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Réinitialiser le mot de passe — SecurePass</title>
<link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
:root{--primary:#667eea;--primary-dark:#764ba2;--success:#48bb78;--danger:#f56565;--warning:#ed8936;--text:#2d3748;--muted:#718096;--bg:#f7fafc;--white:#fff;--border:#e2e8f0;--radius:12px}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Inter',sans-serif;min-height:100vh;background:linear-gradient(135deg,var(--primary) 0%,var(--primary-dark) 100%);display:flex;align-items:center;justify-content:center;padding:1.5rem}
.card{background:var(--white);border-radius:var(--radius);width:100%;max-width:480px;box-shadow:0 25px 60px rgba(0,0,0,.2);overflow:hidden;animation:slideUp .5s ease}
@keyframes slideUp{from{opacity:0;transform:translateY(24px)}to{opacity:1;transform:translateY(0)}}
.card-header{padding:2rem 2rem 1.25rem;text-align:center}
.brand{display:inline-flex;align-items:center;gap:.6rem;font-size:1.25rem;font-weight:800;color:var(--primary);margin-bottom:1.25rem}
.card-header h1{font-size:1.5rem;font-weight:800;color:var(--text);margin-bottom:.4rem}
.card-header p{color:var(--muted);font-size:.9rem}
.card-body{padding:0 2rem 2rem}
.alert{padding:.9rem 1.1rem;border-radius:8px;margin-bottom:1.25rem;display:flex;align-items:flex-start;gap:.7rem;font-size:.875rem;font-weight:500}
.alert.error{background:rgba(245,101,101,.08);border:1px solid rgba(245,101,101,.3);color:#c53030}
.alert.success{background:rgba(72,187,120,.08);border:1px solid rgba(72,187,120,.3);color:#276749}
.alert.info{background:rgba(102,126,234,.08);border:1px solid rgba(102,126,234,.3);color:#434190}
.field{margin-bottom:1rem}
.field label{display:block;font-size:.85rem;font-weight:600;margin-bottom:.45rem;color:var(--text)}
.pw-wrap{position:relative}
.pw-wrap input{width:100%;padding:.75rem 2.75rem .75rem .9rem;border:1.5px solid var(--border);border-radius:8px;font-size:.9rem;color:var(--text);background:var(--bg);outline:none;transition:.2s;font-family:inherit}
.pw-wrap input:focus{border-color:var(--primary);background:var(--white);box-shadow:0 0 0 3px rgba(102,126,234,.12)}
.pw-toggle{position:absolute;right:.8rem;top:50%;transform:translateY(-50%);background:none;border:none;cursor:pointer;color:var(--muted);font-size:.9rem;transition:.2s}
.pw-toggle:hover{color:var(--primary)}
/* Jauge force */
.str-bar{height:5px;background:#e2e8f0;border-radius:99px;margin:.5rem 0 .3rem;overflow:hidden}
.str-fill{height:100%;border-radius:99px;transition:.35s}
.str-label{font-size:.75rem;font-weight:700}
/* Checklist */
.req-list{list-style:none;display:grid;grid-template-columns:1fr 1fr;gap:.3rem .75rem;margin:.75rem 0;font-size:.78rem;color:var(--muted)}
.req-list li{display:flex;align-items:center;gap:.35rem;transition:.2s}
.req-list li.ok{color:var(--success)}
.req-list li i{width:12px;text-align:center}
.btn{display:flex;align-items:center;justify-content:center;gap:.5rem;width:100%;padding:.85rem;border-radius:8px;border:none;font-weight:700;font-size:.95rem;cursor:pointer;transition:.2s;margin-top:.5rem}
.btn-primary{background:linear-gradient(135deg,var(--primary),var(--primary-dark));color:#fff}
.btn-primary:hover:not(:disabled){transform:translateY(-2px);box-shadow:0 6px 20px rgba(102,126,234,.4)}
.btn-primary:disabled{opacity:.6;cursor:not-allowed;transform:none}
.btn-ghost{background:var(--bg);border:1.5px solid var(--border);color:var(--text);margin-top:.75rem}
.btn-ghost:hover{border-color:var(--primary);color:var(--primary)}
.spinner{display:none;width:18px;height:18px;border:2px solid rgba(255,255,255,.3);border-top-color:#fff;border-radius:50%;animation:spin .8s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
/* État invalide */
.invalid-state{text-align:center;padding:1rem 0 .5rem}
.invalid-icon{font-size:3rem;color:var(--danger);margin-bottom:1rem}
.invalid-state h2{font-size:1.25rem;font-weight:700;margin-bottom:.5rem}
.invalid-state p{color:var(--muted);font-size:.875rem;margin-bottom:1.5rem}
</style>
</head>
<body>
<div class="card">
    <div class="card-header">
        <div class="brand"><i class="fas fa-shield-alt"></i>SecurePass</div>
        <?php if ($token_valid): ?>
            <h1>Nouveau mot de passe</h1>
            <p>Choisissez un mot de passe fort pour sécuriser votre compte.</p>
        <?php else: ?>
            <h1>Lien invalide</h1>
        <?php endif ?>
    </div>
    <div class="card-body">

        <?php if ($error_message): ?>
        <div class="alert error"><i class="fas fa-exclamation-circle"></i><span><?= htmlspecialchars($error_message) ?></span></div>
        <?php endif ?>
        <?php if ($success_message): ?>
        <div class="alert success"><i class="fas fa-check-circle"></i><span><?= htmlspecialchars($success_message) ?></span></div>
        <?php endif ?>

        <?php if ($token_valid): ?>
        <!-- FORMULAIRE RESET -->
        <div class="alert info"><i class="fas fa-info-circle"></i>
            <span>Votre mot de passe maître est utilisé pour chiffrer votre coffre-fort. Choisissez-le bien.</span>
        </div>

        <form id="resetForm" method="POST" action="../includes/auth.php">
            <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">
            <input type="hidden" name="action"     value="reset_password">
            <input type="hidden" name="token"      value="<?= htmlspecialchars($token) ?>">
            <input type="hidden" name="email"      value="<?= htmlspecialchars($email) ?>">

            <div class="field">
                <label>Nouveau mot de passe</label>
                <div class="pw-wrap">
                    <input type="password" name="new_password" id="newPw" placeholder="••••••••••••"
                           autocomplete="new-password" required oninput="evalPw(this.value)">
                    <button type="button" class="pw-toggle" onclick="tpw('newPw',this)" title="Afficher/masquer">
                        <i class="fas fa-eye"></i>
                    </button>
                </div>
                <div class="str-bar"><div class="str-fill" id="strFill"></div></div>
                <span class="str-label" id="strLabel"></span>
            </div>

            <ul class="req-list" id="reqList">
                <li id="req-len"><i class="fas fa-circle"></i>12 caractères min.</li>
                <li id="req-upper"><i class="fas fa-circle"></i>Une majuscule</li>
                <li id="req-lower"><i class="fas fa-circle"></i>Une minuscule</li>
                <li id="req-num"><i class="fas fa-circle"></i>Un chiffre</li>
                <li id="req-sym"><i class="fas fa-circle"></i>Un caractère spécial</li>
            </ul>

            <div class="field">
                <label>Confirmer le mot de passe</label>
                <div class="pw-wrap">
                    <input type="password" name="confirm_password" id="confPw" placeholder="••••••••••••"
                           autocomplete="new-password" required oninput="checkMatch()">
                    <button type="button" class="pw-toggle" onclick="tpw('confPw',this)" title="Afficher/masquer">
                        <i class="fas fa-eye"></i>
                    </button>
                </div>
                <span id="matchMsg" style="font-size:.75rem"></span>
            </div>

            <button type="submit" class="btn btn-primary" id="submitBtn" disabled>
                <span class="spinner" id="spinner"></span>
                <i class="fas fa-lock" id="submitIcon"></i>
                <span id="submitText">Réinitialiser le mot de passe</span>
            </button>
        </form>

        <?php else: ?>
        <!-- TOKEN INVALIDE -->
        <div class="invalid-state">
            <div class="invalid-icon"><i class="fas fa-times-circle"></i></div>
            <h2>Lien expiré ou invalide</h2>
            <p>Ce lien de réinitialisation n'est plus valide. Les liens expirent après <strong>1 heure</strong>.</p>
            <a href="forgot_password.php" class="btn btn-primary">
                <i class="fas fa-paper-plane"></i> Faire une nouvelle demande
            </a>
        </div>
        <?php endif ?>

        <a href="login.php" class="btn btn-ghost"><i class="fas fa-arrow-left"></i> Retour à la connexion</a>
    </div>
</div>

<script>
/* Toggle affichage mot de passe */
function tpw(id, btn) {
    const inp = document.getElementById(id);
    const show = inp.type === 'password';
    inp.type = show ? 'text' : 'password';
    btn.innerHTML = `<i class="fas fa-eye${show ? '-slash' : ''}"></i>`;
}

/* Évaluation force */
const LEVELS = [
    {l:'Très faible',c:'#e53e3e',w:'10%'},
    {l:'Faible',     c:'#f56565',w:'25%'},
    {l:'Moyen',      c:'#ed8936',w:'50%'},
    {l:'Fort',       c:'#48bb78',w:'75%'},
    {l:'Très fort',  c:'#38a169',w:'100%'},
];

function evalPw(p) {
    const fill  = document.getElementById('strFill');
    const label = document.getElementById('strLabel');

    // Checklist
    const checks = {
        'req-len':   p.length >= 12,
        'req-upper': /[A-Z]/.test(p),
        'req-lower': /[a-z]/.test(p),
        'req-num':   /[0-9]/.test(p),
        'req-sym':   /[^a-zA-Z0-9]/.test(p),
    };
    Object.entries(checks).forEach(([id, ok]) => {
        const li = document.getElementById(id);
        li.classList.toggle('ok', ok);
        li.querySelector('i').className = ok ? 'fas fa-check-circle' : 'fas fa-circle';
    });

    // Score
    let s = 0;
    if (p.length >= 16) s += 2; else if (p.length >= 12) s += 1;
    if (/[a-z]/.test(p)) s++; if (/[A-Z]/.test(p)) s++;
    if (/[0-9]/.test(p)) s++; if (/[^a-zA-Z0-9]/.test(p)) s++;
    if (/(.)\1{2,}/.test(p)) s--;

    const idx = p ? Math.min(4, Math.max(0, Math.round((s / 7) * 4))) : -1;
    if (idx >= 0) {
        const lvl = LEVELS[idx];
        fill.style.width = lvl.w;
        fill.style.background = lvl.c;
        label.textContent = lvl.l;
        label.style.color = lvl.c;
    } else {
        fill.style.width = '0';
        label.textContent = '';
    }

    checkMatch();
}

function checkMatch() {
    const pw   = document.getElementById('newPw').value;
    const conf = document.getElementById('confPw').value;
    const msg  = document.getElementById('matchMsg');
    const btn  = document.getElementById('submitBtn');

    const allOk = pw.length >= 12 && /[A-Z]/.test(pw) && /[a-z]/.test(pw) && /\d/.test(pw) && /[^a-zA-Z0-9]/.test(pw);

    if (!conf) {
        msg.textContent = '';
    } else if (pw === conf) {
        msg.textContent = '✅ Les mots de passe correspondent.';
        msg.style.color = '#276749';
    } else {
        msg.textContent = '❌ Les mots de passe ne correspondent pas.';
        msg.style.color = '#c53030';
    }

    btn.disabled = !(allOk && pw === conf && conf.length > 0);
}

document.getElementById('resetForm')?.addEventListener('submit', function() {
    const btn     = document.getElementById('submitBtn');
    const spinner = document.getElementById('spinner');
    const icon    = document.getElementById('submitIcon');
    const text    = document.getElementById('submitText');
    btn.disabled      = true;
    spinner.style.display = 'block';
    icon.style.display    = 'none';
    text.textContent      = 'Réinitialisation…';
});
</script>
</body>
</html>
