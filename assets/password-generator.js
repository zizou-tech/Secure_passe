/**
 * SecurePass — password-generator.js
 * Générateur de mots de passe côté client avec UI interactive.
 * Dépendance optionnelle : strength-meter.js pour afficher la force.
 */

'use strict';

const PasswordGenerator = (() => {

    const CHARSETS = {
        lowercase: 'abcdefghijklmnopqrstuvwxyz',
        uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
        numbers:   '0123456789',
        symbols:   '!@#$%^&*()_+-=[]{}|;:,.<>?',
        ambiguous: '0Ol1Ib',
    };

    const PASSPHRASE_WORDS = [
        'cheval','batterie','agrafe','correct','maison','bleu','chat','soleil',
        'livre','voiture','arbre','fleur','montagne','rivière','étoile','lune',
        'océan','forêt','jardin','nuage','pierre','feu','eau','terre','vent',
        'numéro','tableau','rapide','calme','brillant','robuste','léger','profond',
    ];

    /* -------------------------------------------------------
       GÉNÉRATION CRYPTOGRAPHIQUE
    ------------------------------------------------------- */

    /**
     * Génère un entier aléatoire dans [0, max[ avec crypto.getRandomValues.
     */
    function cryptoRandInt(max) {
        const arr = new Uint32Array(1);
        let result;
        do {
            crypto.getRandomValues(arr);
            result = arr[0];
        } while (result >= Math.floor(0xFFFFFFFF / max) * max); // évite le biais modulo
        return result % max;
    }

    /**
     * Génère un mot de passe selon les options données.
     * @param {Object} opts
     * @param {number}  opts.length         Longueur (12-128)
     * @param {boolean} opts.uppercase
     * @param {boolean} opts.lowercase
     * @param {boolean} opts.numbers
     * @param {boolean} opts.symbols
     * @param {boolean} opts.excludeAmbiguous  Exclure 0, O, l, 1, I, b
     * @returns {string}
     */
    function generate(opts = {}) {
        const {
            length = 16,
            uppercase = true,
            lowercase = true,
            numbers = true,
            symbols = true,
            excludeAmbiguous = false,
        } = opts;

        let charset = '';
        const guaranteed = [];

        if (lowercase) {
            let cs = CHARSETS.lowercase;
            if (excludeAmbiguous) cs = cs.split('').filter(c => !CHARSETS.ambiguous.includes(c)).join('');
            charset += cs;
            guaranteed.push(cs[cryptoRandInt(cs.length)]);
        }
        if (uppercase) {
            let cs = CHARSETS.uppercase;
            if (excludeAmbiguous) cs = cs.split('').filter(c => !CHARSETS.ambiguous.includes(c)).join('');
            charset += cs;
            guaranteed.push(cs[cryptoRandInt(cs.length)]);
        }
        if (numbers) {
            let cs = CHARSETS.numbers;
            if (excludeAmbiguous) cs = cs.split('').filter(c => !CHARSETS.ambiguous.includes(c)).join('');
            charset += cs;
            guaranteed.push(cs[cryptoRandInt(cs.length)]);
        }
        if (symbols) {
            const cs = CHARSETS.symbols;
            charset += cs;
            guaranteed.push(cs[cryptoRandInt(cs.length)]);
        }

        if (!charset) throw new Error('Sélectionnez au moins un type de caractère.');

        const clampedLength = Math.max(12, Math.min(128, length));

        // Remplir le reste aléatoirement
        const remaining = clampedLength - guaranteed.length;
        const pool = [];
        for (let i = 0; i < Math.max(0, remaining); i++) {
            pool.push(charset[cryptoRandInt(charset.length)]);
        }

        // Mélanger guaranteed + pool avec Fisher-Yates
        const all = [...guaranteed, ...pool];
        for (let i = all.length - 1; i > 0; i--) {
            const j = cryptoRandInt(i + 1);
            [all[i], all[j]] = [all[j], all[i]];
        }

        return all.join('');
    }

    /**
     * Génère une phrase de passe (passphrase).
     * @param {number}  wordCount    Nombre de mots (3-8)
     * @param {string}  separator    Séparateur (défaut '-')
     * @param {boolean} capitalize   Mettre en majuscule la 1ère lettre de chaque mot
     * @param {boolean} addNumber    Ajouter un nombre aléatoire à la fin
     * @returns {string}
     */
    function passphrase(wordCount = 4, separator = '-', capitalize = true, addNumber = true) {
        const count = Math.max(3, Math.min(8, wordCount));
        const pool  = [...PASSPHRASE_WORDS];
        const words = [];

        for (let i = 0; i < count; i++) {
            const idx  = cryptoRandInt(pool.length);
            let word   = pool.splice(idx, 1)[0];
            if (capitalize) word = word.charAt(0).toUpperCase() + word.slice(1);
            words.push(word);
        }

        let result = words.join(separator);
        if (addNumber) result += separator + (cryptoRandInt(900) + 100); // 100-999
        return result;
    }

    /* -------------------------------------------------------
       UI INTERACTIVE
    ------------------------------------------------------- */

    /**
     * Monte l'UI du générateur dans containerEl.
     * @param {HTMLElement} containerEl
     * @param {Function}    [onGenerate]  Callback appelé avec le mot de passe généré.
     */
    function mountUI(containerEl, onGenerate) {
        if (!containerEl) return;

        containerEl.innerHTML = `
<div class="pg-wrapper">
  <!-- RÉSULTAT -->
  <div class="pg-output-wrap">
    <input type="text" id="pgOutput" class="pg-output" readonly placeholder="Cliquez sur Générer…" aria-label="Mot de passe généré">
    <button class="pg-copy-btn" id="pgCopy" title="Copier" aria-label="Copier le mot de passe">
      <i class="fas fa-copy"></i>
    </button>
  </div>

  <!-- JAUGE DE FORCE -->
  <div id="pgStrengthContainer"></div>

  <!-- ONGLETS MODE -->
  <div class="pg-tabs">
    <button class="pg-tab active" data-tab="random">Aléatoire</button>
    <button class="pg-tab" data-tab="passphrase">Phrase de passe</button>
  </div>

  <!-- PANNEAU : MOT DE PASSE ALÉATOIRE -->
  <div class="pg-panel" id="panelRandom">
    <div class="pg-option-row">
      <label for="pgLength">Longueur : <strong id="pgLengthVal">16</strong></label>
      <input type="range" id="pgLength" min="12" max="64" value="16" step="1">
    </div>
    <div class="pg-checkboxes">
      <label><input type="checkbox" id="pgUppercase" checked> Majuscules (A-Z)</label>
      <label><input type="checkbox" id="pgLowercase" checked> Minuscules (a-z)</label>
      <label><input type="checkbox" id="pgNumbers" checked> Chiffres (0-9)</label>
      <label><input type="checkbox" id="pgSymbols" checked> Symboles (!@#…)</label>
      <label><input type="checkbox" id="pgExcludeAmb"> Exclure les ambigus (0, O, l, 1…)</label>
    </div>
    <div class="pg-option-row">
      <label for="pgQuantity">Quantité :</label>
      <select id="pgQuantity">
        <option value="1">1</option>
        <option value="3">3</option>
        <option value="5">5</option>
        <option value="10">10</option>
      </select>
    </div>
  </div>

  <!-- PANNEAU : PASSPHRASE -->
  <div class="pg-panel" id="panelPassphrase" style="display:none;">
    <div class="pg-option-row">
      <label for="ppWordCount">Nombre de mots : <strong id="ppWordVal">4</strong></label>
      <input type="range" id="ppWordCount" min="3" max="8" value="4" step="1">
    </div>
    <div class="pg-option-row">
      <label for="ppSeparator">Séparateur :</label>
      <select id="ppSeparator">
        <option value="-">Tiret ( - )</option>
        <option value="_">Underscore ( _ )</option>
        <option value=".">Point ( . )</option>
        <option value=" ">Espace</option>
        <option value="">Aucun</option>
      </select>
    </div>
    <div class="pg-checkboxes">
      <label><input type="checkbox" id="ppCapitalize" checked> Mettre en majuscule</label>
      <label><input type="checkbox" id="ppNumber" checked> Ajouter un nombre</label>
    </div>
  </div>

  <!-- MULTI-RÉSULTATS -->
  <div id="pgMultiList" class="pg-multi-list" style="display:none;"></div>

  <!-- ACTIONS -->
  <div class="pg-actions">
    <button class="btn btn-primary" id="pgGenerate">
      <i class="fas fa-sync-alt"></i> Générer
    </button>
    ${onGenerate ? `<button class="btn btn-secondary" id="pgUse">
      <i class="fas fa-check"></i> Utiliser ce mot de passe
    </button>` : ''}
  </div>
</div>`;

        injectStyles();
        _bindEvents(containerEl, onGenerate);
    }

    function _bindEvents(containerEl, onGenerate) {
        const get = id => containerEl.querySelector('#' + id);

        // Slider longueur
        get('pgLength').addEventListener('input', function() {
            get('pgLengthVal').textContent = this.value;
        });

        // Slider nb mots
        get('ppWordCount').addEventListener('input', function() {
            get('ppWordVal').textContent = this.value;
        });

        // Onglets
        containerEl.querySelectorAll('.pg-tab').forEach(tab => {
            tab.addEventListener('click', () => {
                containerEl.querySelectorAll('.pg-tab').forEach(t => t.classList.remove('active'));
                tab.classList.add('active');
                const isPassphrase = tab.dataset.tab === 'passphrase';
                get('panelRandom').style.display     = isPassphrase ? 'none' : '';
                get('panelPassphrase').style.display = isPassphrase ? '' : 'none';
            });
        });

        // Générer
        get('pgGenerate').addEventListener('click', () => {
            const isPassphrase = containerEl.querySelector('.pg-tab.active')?.dataset.tab === 'passphrase';
            const outputEl = get('pgOutput');
            const multiEl  = get('pgMultiList');
            const quantity = parseInt(get('pgQuantity')?.value || '1', 10);

            try {
                if (isPassphrase) {
                    const pwd = passphrase(
                        parseInt(get('ppWordCount').value, 10),
                        get('ppSeparator').value,
                        get('ppCapitalize').checked,
                        get('ppNumber').checked,
                    );
                    outputEl.value = pwd;
                    multiEl.style.display = 'none';
                    _updateStrength(pwd, containerEl);
                } else {
                    const opts = {
                        length:          parseInt(get('pgLength').value, 10),
                        uppercase:       get('pgUppercase').checked,
                        lowercase:       get('pgLowercase').checked,
                        numbers:         get('pgNumbers').checked,
                        symbols:         get('pgSymbols').checked,
                        excludeAmbiguous: get('pgExcludeAmb').checked,
                    };

                    if (!opts.uppercase && !opts.lowercase && !opts.numbers && !opts.symbols) {
                        if (typeof Notify !== 'undefined') Notify.show('Sélectionnez au moins un type de caractère.', 'warning');
                        return;
                    }

                    if (quantity === 1) {
                        const pwd = generate(opts);
                        outputEl.value = pwd;
                        multiEl.style.display = 'none';
                        _updateStrength(pwd, containerEl);
                    } else {
                        const passwords = Array.from({ length: quantity }, () => generate(opts));
                        outputEl.value = passwords[0];
                        _updateStrength(passwords[0], containerEl);
                        multiEl.style.display = '';
                        multiEl.innerHTML = passwords.map((p, i) => `
                            <div class="pg-multi-item">
                                <span>${i + 1}. <code>${p}</code></span>
                                <button class="pg-copy-small" data-pwd="${p.replace(/"/g,'&quot;')}" title="Copier">
                                    <i class="fas fa-copy"></i>
                                </button>
                            </div>`).join('');

                        multiEl.querySelectorAll('.pg-copy-small').forEach(btn => {
                            btn.addEventListener('click', () => {
                                copyToClipboard(btn.dataset.pwd, btn);
                                outputEl.value = btn.dataset.pwd;
                                _updateStrength(btn.dataset.pwd, containerEl);
                            });
                        });
                    }
                }
            } catch(e) {
                if (typeof Notify !== 'undefined') Notify.show(e.message, 'error');
            }
        });

        // Copier
        get('pgCopy').addEventListener('click', () => {
            const val = get('pgOutput').value;
            if (val) copyToClipboard(val, get('pgCopy'));
        });

        // "Utiliser" callback
        if (onGenerate) {
            get('pgUse')?.addEventListener('click', () => {
                const val = get('pgOutput').value;
                if (val) onGenerate(val);
            });
        }

        // Jauge de force (si strength-meter.js chargé)
        if (typeof StrengthMeter !== 'undefined') {
            StrengthMeter.init(get('pgOutput'), get('pgStrengthContainer'));
        }
    }

    function _updateStrength(password, containerEl) {
        const sc = containerEl.querySelector('#pgStrengthContainer');
        if (sc && typeof StrengthMeter !== 'undefined') {
            // StrengthMeter.init crée déjà la liaison; on force une mise à jour
            if (sc.querySelector('#smFill')) {
                // Le conteneur est déjà initialisé, mise à jour via l'événement input
                const input = containerEl.querySelector('#pgOutput');
                if (input) input.dispatchEvent(new Event('input'));
            } else {
                StrengthMeter.init(containerEl.querySelector('#pgOutput'), sc);
            }
        }
    }

    /* -------------------------------------------------------
       STYLES INJECTÉS
    ------------------------------------------------------- */
    function injectStyles() {
        if (document.getElementById('pg-styles')) return;
        const style = document.createElement('style');
        style.id = 'pg-styles';
        style.textContent = `
            .pg-wrapper { font-family: 'Inter', sans-serif; }
            .pg-output-wrap { display: flex; gap: .5rem; margin-bottom: .75rem; }
            .pg-output {
                flex: 1; padding: .75rem 1rem; border: 1.5px solid #e2e8f0; border-radius: 8px;
                font-family: 'Courier New', monospace; font-size: 1rem; background: #f7fafc;
                color: #2d3748; outline: none; transition: border-color .3s;
            }
            .pg-output:focus { border-color: #667eea; box-shadow: 0 0 0 3px rgba(102,126,234,.15); }
            .pg-copy-btn {
                padding: .75rem 1rem; border: 1.5px solid #e2e8f0; border-radius: 8px;
                background: #fff; cursor: pointer; color: #718096; transition: all .3s;
                font-size: 1rem;
            }
            .pg-copy-btn:hover, .pg-copy-btn.copied { background: #667eea; color: #fff; border-color: #667eea; }
            .pg-tabs { display: flex; gap: .5rem; margin: 1rem 0 .75rem; border-bottom: 2px solid #e2e8f0; }
            .pg-tab {
                padding: .5rem 1rem; border: none; background: none; cursor: pointer; font-size: .9rem;
                font-weight: 600; color: #718096; border-bottom: 2px solid transparent; margin-bottom: -2px;
                transition: all .25s;
            }
            .pg-tab.active { color: #667eea; border-bottom-color: #667eea; }
            .pg-panel { padding: .5rem 0; }
            .pg-option-row { display: flex; align-items: center; justify-content: space-between; margin-bottom: .75rem; gap: 1rem; }
            .pg-option-row label { font-size: .9rem; font-weight: 500; color: #2d3748; }
            .pg-option-row input[type=range] { flex: 1; max-width: 200px; accent-color: #667eea; }
            .pg-option-row select {
                padding: .4rem .75rem; border: 1.5px solid #e2e8f0; border-radius: 6px;
                font-size: .85rem; background: #fff; color: #2d3748; cursor: pointer;
            }
            .pg-checkboxes { display: flex; flex-direction: column; gap: .4rem; margin-bottom: .75rem; }
            .pg-checkboxes label { display: flex; align-items: center; gap: .5rem; font-size: .875rem; color: #4a5568; cursor: pointer; }
            .pg-checkboxes input[type=checkbox] { accent-color: #667eea; width: 15px; height: 15px; }
            .pg-actions { display: flex; gap: .75rem; margin-top: 1rem; flex-wrap: wrap; }
            .pg-multi-list { margin-top: .75rem; border: 1px solid #e2e8f0; border-radius: 8px; overflow: hidden; }
            .pg-multi-item {
                display: flex; align-items: center; justify-content: space-between;
                padding: .5rem 1rem; border-bottom: 1px solid #e2e8f0; font-size: .85rem;
            }
            .pg-multi-item:last-child { border-bottom: none; }
            .pg-multi-item code { font-family: monospace; color: #2d3748; }
            .pg-copy-small {
                background: none; border: none; cursor: pointer; color: #718096; font-size: .9rem; padding: .2rem .4rem;
                border-radius: 4px; transition: all .2s;
            }
            .pg-copy-small:hover { background: #667eea; color: #fff; }
        `;
        document.head.appendChild(style);
    }

    return { generate, passphrase, mountUI };
})();
