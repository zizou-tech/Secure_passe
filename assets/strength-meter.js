/**
 * SecurePass — strength-meter.js
 * Jauge de force de mot de passe côté client.
 * Usage : StrengthMeter.init(inputEl, containerEl)
 */

'use strict';

const StrengthMeter = (() => {

    const LEVELS = [
        { label: 'Très faible', color: '#e53e3e', width: '10%' },
        { label: 'Faible',      color: '#f56565', width: '25%' },
        { label: 'Moyen',       color: '#ed8936', width: '50%' },
        { label: 'Fort',        color: '#48bb78', width: '75%' },
        { label: 'Très fort',   color: '#38a169', width: '100%' },
    ];

    /**
     * Analyse la force d'un mot de passe sans appel serveur.
     * Retourne un objet { score (0-4), level, feedback[] }
     */
    function analyze(password) {
        if (!password) return { score: -1, level: null, feedback: [] };

        let score = 0;
        const feedback = [];

        // Longueur
        if (password.length >= 16) score += 2;
        else if (password.length >= 12) score += 1;
        else feedback.push('Utilisez au moins 12 caractères');

        // Complexité
        if (/[a-z]/.test(password)) score += 1;
        else feedback.push('Ajoutez des minuscules');

        if (/[A-Z]/.test(password)) score += 1;
        else feedback.push('Ajoutez des majuscules');

        if (/[0-9]/.test(password)) score += 1;
        else feedback.push('Ajoutez des chiffres');

        if (/[^a-zA-Z0-9]/.test(password)) score += 1;
        else feedback.push('Ajoutez des caractères spéciaux (!@#$…)');

        // Pénalités
        if (/(.)\1{2,}/.test(password)) {
            score = Math.max(0, score - 1);
            feedback.push('Évitez les caractères répétés');
        }
        if (/^(123|abc|qwerty|password|azerty|admin)/i.test(password)) {
            score = Math.max(0, score - 2);
            feedback.push('Évitez les séquences communes');
        }

        // Calcul entropie pour bonus
        let charsetSize = 0;
        if (/[a-z]/.test(password)) charsetSize += 26;
        if (/[A-Z]/.test(password)) charsetSize += 26;
        if (/[0-9]/.test(password)) charsetSize += 10;
        if (/[^a-zA-Z0-9]/.test(password)) charsetSize += 32;
        const entropy = charsetSize > 0 ? password.length * Math.log2(charsetSize) : 0;

        // Normaliser score sur 0-4
        let idx = Math.min(4, Math.max(0, Math.round((score / 7) * 4)));
        if (entropy > 80 && idx < 4) idx = Math.min(4, idx + 1);

        return {
            score: idx,
            level: LEVELS[idx],
            entropy: Math.round(entropy),
            feedback,
        };
    }

    /**
     * Estime le temps de crack (1 milliard de tentatives/s).
     */
    function crackTime(entropy) {
        if (!entropy) return 'Instantané';
        const combinations = Math.pow(2, entropy);
        const seconds = combinations / 1e9;
        if (seconds < 1)       return 'Moins d\'une seconde';
        if (seconds < 60)      return Math.round(seconds) + ' secondes';
        if (seconds < 3600)    return Math.round(seconds / 60) + ' minutes';
        if (seconds < 86400)   return Math.round(seconds / 3600) + ' heures';
        if (seconds < 2592000) return Math.round(seconds / 86400) + ' jours';
        if (seconds < 31536000) return Math.round(seconds / 2592000) + ' mois';
        const years = seconds / 31536000;
        if (years > 1e6)  return 'Des millions d\'années';
        if (years > 1000) return 'Des milliers d\'années';
        return Math.round(years) + ' années';
    }

    /**
     * Crée et insère le HTML de la jauge dans containerEl.
     */
    function buildUI(containerEl) {
        containerEl.innerHTML = `
            <div class="strength-meter-wrap">
                <div class="strength-bar-track">
                    <div class="strength-bar-fill" id="smFill"></div>
                </div>
                <div class="strength-meta">
                    <span class="strength-label" id="smLabel">—</span>
                    <span class="strength-entropy" id="smEntropy"></span>
                </div>
                <div class="strength-feedback" id="smFeedback"></div>
                <div class="strength-crack" id="smCrack"></div>
            </div>`;
    }

    /**
     * Met à jour la jauge en fonction du mot de passe courant.
     */
    function update(password, containerEl) {
        const fill    = containerEl.querySelector('#smFill');
        const label   = containerEl.querySelector('#smLabel');
        const entropy = containerEl.querySelector('#smEntropy');
        const feedDiv = containerEl.querySelector('#smFeedback');
        const crackDiv = containerEl.querySelector('#smCrack');

        if (!fill) return;

        if (!password) {
            fill.style.width = '0%';
            fill.style.background = '#e2e8f0';
            label.textContent = '—';
            entropy.textContent = '';
            feedDiv.innerHTML = '';
            crackDiv.innerHTML = '';
            return;
        }

        const result = analyze(password);
        const lvl = result.level;

        fill.style.width = lvl.width;
        fill.style.background = lvl.color;
        fill.style.transition = 'width .4s ease, background .4s ease';

        label.textContent = lvl.label;
        label.style.color = lvl.color;

        entropy.textContent = `Entropie : ${result.entropy} bits`;

        if (result.feedback.length) {
            feedDiv.innerHTML = '<ul class="strength-tips">' +
                result.feedback.map(f => `<li>${f}</li>`).join('') +
                '</ul>';
        } else {
            feedDiv.innerHTML = '<p class="strength-ok">✅ Excellent mot de passe !</p>';
        }

        crackDiv.innerHTML = `<small>⏱ Temps estimé pour cracker : <strong>${crackTime(result.entropy)}</strong></small>`;
    }

    /**
     * Initialise la jauge sur un champ de saisie.
     * @param {HTMLInputElement} inputEl   Champ mot de passe
     * @param {HTMLElement}      containerEl  Conteneur où injecter la jauge
     */
    function init(inputEl, containerEl) {
        if (!inputEl || !containerEl) return;
        buildUI(containerEl);

        const onInput = debounce ? debounce(() => update(inputEl.value, containerEl), 150)
                                 : () => update(inputEl.value, containerEl);
        inputEl.addEventListener('input', onInput);
        // Mise à jour initiale si pré-rempli
        if (inputEl.value) update(inputEl.value, containerEl);
    }

    // Styles injectés une seule fois
    function injectStyles() {
        if (document.getElementById('sm-styles')) return;
        const style = document.createElement('style');
        style.id = 'sm-styles';
        style.textContent = `
            .strength-meter-wrap { margin-top: .75rem; }
            .strength-bar-track {
                height: 6px; background: #e2e8f0; border-radius: 99px; overflow: hidden; margin-bottom: .5rem;
            }
            .strength-bar-fill { height: 100%; width: 0; border-radius: 99px; }
            .strength-meta { display: flex; justify-content: space-between; align-items: center; font-size: .8rem; margin-bottom: .4rem; }
            .strength-label { font-weight: 700; }
            .strength-entropy { color: #718096; }
            .strength-feedback { font-size: .8rem; margin-bottom: .3rem; }
            .strength-tips { padding-left: 1.25rem; color: #c05621; }
            .strength-tips li { margin-bottom: .15rem; }
            .strength-ok { color: #276749; font-weight: 600; }
            .strength-crack { font-size: .78rem; color: #718096; }
            .strength-crack strong { color: #2d3748; }
        `;
        document.head.appendChild(style);
    }

    document.addEventListener('DOMContentLoaded', injectStyles);

    return { init, analyze, crackTime };
})();
