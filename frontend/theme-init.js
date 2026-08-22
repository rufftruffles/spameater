'use strict';

// Sets the theme attribute before first paint. Loaded in <head> on purpose:
// running it after the stylesheet would flash the wrong theme.
// Saved preference wins; otherwise the OS preference; the brand default is dark.
(function () {
    let theme = null;
    try {
        theme = localStorage.getItem('spameater_theme');
    } catch (err) {
        // Storage can be unavailable (private mode); fall through to the OS hint
    }
    if (theme !== 'light' && theme !== 'dark') {
        theme = window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches
            ? 'light'
            : 'dark';
    }
    document.documentElement.setAttribute('data-theme', theme);
})();
