(function () {
    const storageKey = 'audit-tracker-theme';

    function preferredTheme() {
        const saved = localStorage.getItem(storageKey);
        if (saved === 'light' || saved === 'dark') return saved;
        return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
    }

    function updateControls(theme) {
        document.querySelectorAll('[data-theme-toggle]').forEach((button) => {
            const nextTheme = theme === 'dark' ? 'light' : 'dark';
            button.setAttribute('aria-label', `Switch to ${nextTheme} mode`);
            button.setAttribute('title', `Switch to ${nextTheme} mode`);
            button.querySelector('[data-theme-sun]')?.classList.toggle('hidden', theme !== 'dark');
            button.querySelector('[data-theme-moon]')?.classList.toggle('hidden', theme !== 'light');
        });
    }

    function applyTheme(theme, persist) {
        document.documentElement.dataset.theme = theme;
        document.documentElement.style.colorScheme = theme;
        if (persist) localStorage.setItem(storageKey, theme);
        updateControls(theme);
    }

    applyTheme(preferredTheme(), false);

    document.addEventListener('DOMContentLoaded', () => {
        if (!document.querySelector('[data-theme-toggle]')) {
            const button = document.createElement('button');
            button.type = 'button';
            button.className = 'theme-toggle theme-toggle-floating';
            button.dataset.themeToggle = '';
            button.innerHTML = '<span data-theme-sun aria-hidden="true">&#9728;</span><span data-theme-moon aria-hidden="true">&#9790;</span>';
            document.body.appendChild(button);
        }

        updateControls(document.documentElement.dataset.theme);
        document.querySelectorAll('[data-theme-toggle]').forEach((button) => {
            button.addEventListener('click', () => {
                const next = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
                applyTheme(next, true);
            });
        });
    });
}());
