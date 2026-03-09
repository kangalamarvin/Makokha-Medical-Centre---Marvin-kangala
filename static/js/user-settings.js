/**
 * User Settings Manager
 * Handles timezone, mode (light/dark), theme color, and wallpaper.
 * Persists to localStorage; applies on every page load.
 */
(function () {
    'use strict';

    const STORAGE_KEY = 'mmc_user_settings';

    const DEFAULTS = {
        timezone: 'Africa/Nairobi',
        mode: 'light',         // 'light' | 'dark'
        theme: 'blue',         // 'blue' | 'green' | 'purple' | 'red' | 'orange' | 'teal'
        wallpaper: 'none'      // 'none' | 'geometric' | 'medical' | 'gradient' | 'dots'
    };

    const THEME_COLORS = {
        blue:   { primary: '#0d6efd', primaryDark: '#0a58ca', accent: '#0d6efd' },
        green:  { primary: '#198754', primaryDark: '#146c43', accent: '#198754' },
        purple: { primary: '#6f42c1', primaryDark: '#59359a', accent: '#6f42c1' },
        red:    { primary: '#dc3545', primaryDark: '#b02a37', accent: '#dc3545' },
        orange: { primary: '#fd7e14', primaryDark: '#ca6510', accent: '#fd7e14' },
        teal:   { primary: '#20c997', primaryDark: '#1aa179', accent: '#20c997' }
    };

    const WALLPAPERS = {
        none: '',
        geometric: 'url("data:image/svg+xml,%3Csvg width=\'60\' height=\'60\' viewBox=\'0 0 60 60\' xmlns=\'http://www.w3.org/2000/svg\'%3E%3Cg fill=\'none\' fill-rule=\'evenodd\'%3E%3Cg fill=\'%239C92AC\' fill-opacity=\'0.06\'%3E%3Cpath d=\'M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z\'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E")',
        medical: 'url("data:image/svg+xml,%3Csvg width=\'40\' height=\'40\' viewBox=\'0 0 40 40\' xmlns=\'http://www.w3.org/2000/svg\'%3E%3Cg fill=\'%230d6efd\' fill-opacity=\'0.05\' fill-rule=\'evenodd\'%3E%3Cpath d=\'M20 18h-2v-4h-4v-2h4V8h2v4h4v2h-4v4z\'/%3E%3C/g%3E%3C/svg%3E")',
        gradient: 'linear-gradient(135deg, rgba(13,110,253,0.03) 0%, rgba(111,66,193,0.03) 100%)',
        dots: 'url("data:image/svg+xml,%3Csvg width=\'20\' height=\'20\' viewBox=\'0 0 20 20\' xmlns=\'http://www.w3.org/2000/svg\'%3E%3Cg fill=\'%239C92AC\' fill-opacity=\'0.08\' fill-rule=\'evenodd\'%3E%3Ccircle cx=\'3\' cy=\'3\' r=\'1.5\'/%3E%3C/g%3E%3C/svg%3E")'
    };

    const TIMEZONES = [
        { value: 'Africa/Nairobi', label: 'East Africa Time (EAT) UTC+3' },
        { value: 'Africa/Lagos', label: 'West Africa Time (WAT) UTC+1' },
        { value: 'Africa/Johannesburg', label: 'South Africa (SAST) UTC+2' },
        { value: 'Africa/Cairo', label: 'Egypt (EET) UTC+2' },
        { value: 'UTC', label: 'UTC' },
        { value: 'Europe/London', label: 'London (GMT/BST)' },
        { value: 'America/New_York', label: 'New York (EST/EDT)' },
        { value: 'Asia/Dubai', label: 'Dubai (GST) UTC+4' },
        { value: 'Asia/Kolkata', label: 'India (IST) UTC+5:30' },
        { value: 'Asia/Shanghai', label: 'China (CST) UTC+8' }
    ];

    /* ---- Storage ---- */
    function load() {
        try {
            const raw = localStorage.getItem(STORAGE_KEY);
            if (raw) return { ...DEFAULTS, ...JSON.parse(raw) };
        } catch (_) {}
        return { ...DEFAULTS };
    }

    function save(settings) {
        try {
            localStorage.setItem(STORAGE_KEY, JSON.stringify(settings));
        } catch (_) {}
    }

    /* ---- Apply ---- */
    function applySettings(settings) {
        const root = document.documentElement;

        // Mode
        if (settings.mode === 'dark') {
            root.setAttribute('data-bs-theme', 'dark');
            root.classList.add('mmc-dark');
        } else {
            root.removeAttribute('data-bs-theme');
            root.classList.remove('mmc-dark');
        }

        // Theme color
        const colors = THEME_COLORS[settings.theme] || THEME_COLORS.blue;
        root.style.setProperty('--primary-color', colors.primary);
        root.style.setProperty('--primary-dark', colors.primaryDark);
        root.style.setProperty('--bs-primary', colors.primary);
        root.style.setProperty('--accent-color', colors.accent);

        // Wallpaper
        const wp = WALLPAPERS[settings.wallpaper] || '';
        document.body.style.backgroundImage = wp || '';
        if (settings.wallpaper === 'gradient') {
            document.body.style.backgroundImage = wp;
        }

        // Timezone — expose for communication.js
        window.__mmcTimezone = settings.timezone || 'Africa/Nairobi';

        // Dispatch event so other components can react
        try {
            window.dispatchEvent(new CustomEvent('mmc-settings-changed', { detail: settings }));
        } catch (_) {}
    }

    /* ---- Dark mode CSS injection (only once) ---- */
    function injectDarkCSS() {
        if (document.getElementById('mmc-dark-mode-css')) return;
        const style = document.createElement('style');
        style.id = 'mmc-dark-mode-css';
        style.textContent = `
            .mmc-dark body, .mmc-dark {
                background-color: #1a1a2e !important;
                color: #e0e0e0 !important;
            }
            .mmc-dark .card, .mmc-dark .modal-content, .mmc-dark .dropdown-menu {
                background-color: #16213e !important;
                color: #e0e0e0 !important;
                border-color: #2a2a4a !important;
            }
            .mmc-dark .card-header {
                background-color: #1a1a3e !important;
                color: #e0e0e0 !important;
                border-color: #2a2a4a !important;
            }
            .mmc-dark .table { color: #e0e0e0 !important; }
            .mmc-dark .table th {
                background-color: #1a1a3e !important;
                color: #e0e0e0 !important;
            }
            .mmc-dark .table td { border-color: #2a2a4a !important; }
            .mmc-dark .table-striped > tbody > tr:nth-of-type(odd) > * {
                background-color: rgba(255,255,255,0.03) !important;
                color: #e0e0e0 !important;
            }
            .mmc-dark .form-control, .mmc-dark .form-select {
                background-color: #1a1a3e !important;
                color: #e0e0e0 !important;
                border-color: #2a2a4a !important;
            }
            .mmc-dark .sidebar {
                background: linear-gradient(180deg, #0f0f23, #1a1a3e) !important;
            }
            .mmc-dark .header, .mmc-dark .navbar {
                background-color: #16213e !important;
                border-color: #2a2a4a !important;
            }
            .mmc-dark a:not(.btn):not(.nav-link) { color: #82b1ff; }
            .mmc-dark .text-muted { color: #8a8aa0 !important; }
            .mmc-dark .bg-white { background-color: #16213e !important; }
            .mmc-dark .bg-light { background-color: #1a1a2e !important; }
            .mmc-dark .border { border-color: #2a2a4a !important; }
            .mmc-dark input, .mmc-dark textarea, .mmc-dark select {
                background-color: #1a1a3e !important;
                color: #e0e0e0 !important;
                border-color: #2a2a4a !important;
            }
            /* Communication modal dark */
            .mmc-dark .communication-modal { background: #16213e !important; }
            .mmc-dark .communication-header { background: #1a1a3e !important; border-color: #2a2a4a !important; }
            .mmc-dark .users-sidebar { background: #16213e !important; }
            .mmc-dark .user-item { border-color: #2a2a4a !important; }
            .mmc-dark .user-item:hover { background: #1a1a3e !important; }
            .mmc-dark .chat-header { background: #16213e !important; border-color: #2a2a4a !important; }
            .mmc-dark .messages-container { background: #0f0f23 !important; }
            .mmc-dark .message.sent .message-bubble { background: #1a3a5c !important; color: #e0e0e0 !important; }
            .mmc-dark .message.received .message-bubble { background: #1a1a3e !important; color: #e0e0e0 !important; }
            .mmc-dark .message-input { background: #16213e !important; border-color: #2a2a4a !important; }
            .mmc-dark .message-input-field { background: #1a1a3e !important; color: #e0e0e0 !important; }
            .mmc-dark .no-chat-selected { color: #8a8aa0 !important; }
        `;
        document.head.appendChild(style);
    }

    /* ---- Render settings panel (for profile page) ---- */
    function renderSettingsPanel(container) {
        const s = load();
        container.innerHTML = `
            <div class="settings-panel" style="max-width:600px;">
                <h3 style="margin-bottom:1rem;"><i class="bi bi-gear"></i> System Settings</h3>

                <div class="mb-3">
                    <label class="form-label fw-bold">Timezone</label>
                    <select id="mmc-setting-timezone" class="form-select">
                        ${TIMEZONES.map(tz =>
                            `<option value="${tz.value}" ${s.timezone === tz.value ? 'selected' : ''}>${tz.label}</option>`
                        ).join('')}
                    </select>
                </div>

                <div class="mb-3">
                    <label class="form-label fw-bold">Mode</label>
                    <div class="d-flex gap-2">
                        <button class="btn ${s.mode === 'light' ? 'btn-primary' : 'btn-outline-secondary'} flex-fill mmc-mode-btn" data-mode="light">
                            <i class="bi bi-sun"></i> Light
                        </button>
                        <button class="btn ${s.mode === 'dark' ? 'btn-primary' : 'btn-outline-secondary'} flex-fill mmc-mode-btn" data-mode="dark">
                            <i class="bi bi-moon-stars"></i> Dark
                        </button>
                    </div>
                </div>

                <div class="mb-3">
                    <label class="form-label fw-bold">Theme Color</label>
                    <div class="d-flex gap-2 flex-wrap">
                        ${Object.keys(THEME_COLORS).map(key => `
                            <button class="mmc-theme-btn ${s.theme === key ? 'active' : ''}" data-theme="${key}"
                                style="width:40px;height:40px;border-radius:50%;border:3px solid ${s.theme === key ? '#333' : 'transparent'};
                                background:${THEME_COLORS[key].primary};cursor:pointer;transition:all .2s;"
                                title="${key}"></button>
                        `).join('')}
                    </div>
                </div>

                <div class="mb-3">
                    <label class="form-label fw-bold">Background Pattern</label>
                    <div class="d-flex gap-2 flex-wrap">
                        ${Object.keys(WALLPAPERS).map(key => `
                            <button class="btn ${s.wallpaper === key ? 'btn-primary' : 'btn-outline-secondary'} btn-sm mmc-wallpaper-btn" data-wallpaper="${key}">
                                ${key === 'none' ? 'None' : key.charAt(0).toUpperCase() + key.slice(1)}
                            </button>
                        `).join('')}
                    </div>
                </div>

                <button class="btn btn-success" id="mmc-save-settings"><i class="bi bi-check-lg"></i> Save Settings</button>
                <button class="btn btn-outline-secondary ms-2" id="mmc-reset-settings"><i class="bi bi-arrow-counterclockwise"></i> Reset to Defaults</button>
            </div>
        `;

        // Wire up interactivity
        container.querySelectorAll('.mmc-mode-btn').forEach(btn => {
            btn.addEventListener('click', function () {
                container.querySelectorAll('.mmc-mode-btn').forEach(b => {
                    b.classList.remove('btn-primary');
                    b.classList.add('btn-outline-secondary');
                });
                this.classList.remove('btn-outline-secondary');
                this.classList.add('btn-primary');
            });
        });

        container.querySelectorAll('.mmc-theme-btn').forEach(btn => {
            btn.addEventListener('click', function () {
                container.querySelectorAll('.mmc-theme-btn').forEach(b => {
                    b.style.borderColor = 'transparent';
                    b.classList.remove('active');
                });
                this.style.borderColor = '#333';
                this.classList.add('active');
            });
        });

        container.querySelectorAll('.mmc-wallpaper-btn').forEach(btn => {
            btn.addEventListener('click', function () {
                container.querySelectorAll('.mmc-wallpaper-btn').forEach(b => {
                    b.classList.remove('btn-primary');
                    b.classList.add('btn-outline-secondary');
                });
                this.classList.remove('btn-outline-secondary');
                this.classList.add('btn-primary');
            });
        });

        document.getElementById('mmc-save-settings').addEventListener('click', function () {
            const tz = document.getElementById('mmc-setting-timezone').value;
            const mode = container.querySelector('.mmc-mode-btn.btn-primary')?.dataset.mode || 'light';
            const theme = container.querySelector('.mmc-theme-btn.active')?.dataset.theme || 'blue';
            const wallpaper = container.querySelector('.mmc-wallpaper-btn.btn-primary')?.dataset.wallpaper || 'none';

            const newSettings = { timezone: tz, mode, theme, wallpaper };
            save(newSettings);
            applySettings(newSettings);
            injectDarkCSS();

            // Visual feedback
            const btn = this;
            const orig = btn.innerHTML;
            btn.innerHTML = '<i class="bi bi-check-circle"></i> Saved!';
            btn.classList.replace('btn-success', 'btn-outline-success');
            setTimeout(() => { btn.innerHTML = orig; btn.classList.replace('btn-outline-success', 'btn-success'); }, 1500);
        });

        document.getElementById('mmc-reset-settings').addEventListener('click', function () {
            save(DEFAULTS);
            applySettings(DEFAULTS);
            renderSettingsPanel(container); // re-render with defaults
        });
    }

    /* ---- Init on DOM ready ---- */
    function init() {
        injectDarkCSS();
        applySettings(load());

        // Auto-render into #mmc-settings-root if it exists (profile page)
        const root = document.getElementById('mmc-settings-root');
        if (root) renderSettingsPanel(root);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

    // Expose for external use
    window.MMCSettings = { load, save, applySettings, renderSettingsPanel, TIMEZONES };
})();
