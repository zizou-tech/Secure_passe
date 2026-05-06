/**
 * SecurePass — main.js
 * Utilitaires partagés par toutes les pages de l'application.
 */

'use strict';

/* ============================================================
   THÈME SOMBRE (dark mode)
   ============================================================ */
const ThemeManager = (() => {
    const KEY = 'securepass_theme';

    function apply(dark) {
        document.body.classList.toggle('dark-mode', dark);
        const icon = document.getElementById('themeIcon');
        if (icon) icon.className = dark ? 'fas fa-sun' : 'fas fa-moon';
    }

    function init() {
        const saved = localStorage.getItem(KEY);
        const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
        apply(saved ? saved === 'dark' : prefersDark);

        const btn = document.getElementById('themeToggle');
        if (btn) {
            btn.addEventListener('click', () => {
                const isDark = document.body.classList.toggle('dark-mode');
                localStorage.setItem(KEY, isDark ? 'dark' : 'light');
                const icon = document.getElementById('themeIcon');
                if (icon) icon.className = isDark ? 'fas fa-sun' : 'fas fa-moon';
            });
        }
    }

    return { init, apply };
})();

/* ============================================================
   NOTIFICATIONS TOAST
   ============================================================ */
const Notify = (() => {
    let container;

    function getContainer() {
        if (!container) {
            container = document.querySelector('.notification-container');
            if (!container) {
                container = document.createElement('div');
                container.className = 'notification-container';
                document.body.appendChild(container);
            }
        }
        return container;
    }

    function show(message, type = 'info', duration = 4500) {
        const icons = {
            success: 'fa-check-circle',
            error: 'fa-exclamation-circle',
            warning: 'fa-exclamation-triangle',
            info: 'fa-info-circle',
        };
        const toast = document.createElement('div');
        toast.className = `notification ${type}`;
        toast.innerHTML = `
            <i class="fas ${icons[type] || icons.info}"></i>
            <span>${message}</span>
            <button class="notif-close" aria-label="Fermer">&times;</button>`;

        toast.querySelector('.notif-close').addEventListener('click', () => dismiss(toast));
        getContainer().appendChild(toast);
        requestAnimationFrame(() => toast.classList.add('visible'));
        setTimeout(() => dismiss(toast), duration);
        return toast;
    }

    function dismiss(toast) {
        toast.classList.remove('visible');
        toast.addEventListener('transitionend', () => toast.remove(), { once: true });
    }

    return { show };
})();

/* ============================================================
   PRESSE-PAPIERS
   ============================================================ */
async function copyToClipboard(text, feedbackEl) {
    try {
        await navigator.clipboard.writeText(text);
        if (feedbackEl) {
            const orig = feedbackEl.innerHTML;
            feedbackEl.innerHTML = '<i class="fas fa-check"></i>';
            feedbackEl.classList.add('copied');
            setTimeout(() => {
                feedbackEl.innerHTML = orig;
                feedbackEl.classList.remove('copied');
            }, 1500);
        }
        Notify.show('Copié dans le presse-papiers !', 'success', 2000);
        return true;
    } catch {
        Notify.show('Impossible de copier automatiquement.', 'warning');
        return false;
    }
}

/* ============================================================
   SIDEBAR MOBILE
   ============================================================ */
function toggleSidebar() {
    const sidebar = document.querySelector('.sidebar');
    if (sidebar) sidebar.classList.toggle('open');
}

/* ============================================================
   UTILITAIRES
   ============================================================ */
function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

function debounce(fn, delay = 300) {
    let timer;
    return (...args) => {
        clearTimeout(timer);
        timer = setTimeout(() => fn(...args), delay);
    };
}

/* ============================================================
   INIT AUTO
   ============================================================ */
document.addEventListener('DOMContentLoaded', () => {
    ThemeManager.init();

    // Fermer sidebar en dehors
    document.addEventListener('click', (e) => {
        const sidebar = document.querySelector('.sidebar');
        const menuBtn = document.querySelector('.menu-toggle');
        if (sidebar && sidebar.classList.contains('open') &&
            !sidebar.contains(e.target) &&
            menuBtn && !menuBtn.contains(e.target)) {
            sidebar.classList.remove('open');
        }
    });

    // Echap = ferme les modales
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            document.querySelectorAll('.modal-overlay').forEach(m => {
                if (m.style.display !== 'none') m.style.display = 'none';
            });
        }
    });

    // Toggle show/hide password
    document.querySelectorAll('.toggle-password').forEach(btn => {
        btn.addEventListener('click', () => {
            const input = btn.closest('.password-wrapper')?.querySelector('input');
            if (!input) return;
            const show = input.type === 'password';
            input.type = show ? 'text' : 'password';
            btn.innerHTML = `<i class="fas fa-eye${show ? '-slash' : ''}"></i>`;
        });
    });
});
