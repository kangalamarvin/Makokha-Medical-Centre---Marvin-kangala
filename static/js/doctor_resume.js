(function () {
    'use strict';

    const LAST_URL_KEY = 'mmc.doctor.last_url';
    const LAST_SCROLL_KEY_PREFIX = 'mmc.doctor.scroll:';

    function safeGetItem(key) {
        try {
            return window.localStorage.getItem(key);
        } catch {
            return null;
        }
    }

    function safeSetItem(key, value) {
        try {
            window.localStorage.setItem(key, value);
        } catch {
            // ignore storage errors (quota, disabled, etc.)
        }
    }

    function isDoctorPath(pathname) {
        return typeof pathname === 'string' && pathname.startsWith('/doctor');
    }

    function currentUrl() {
        return window.location.pathname + window.location.search + window.location.hash;
    }

    function saveLastDoctorLocation() {
        if (!isDoctorPath(window.location.pathname)) return;
        const url = currentUrl();
        safeSetItem(LAST_URL_KEY, url);
        safeSetItem(LAST_SCROLL_KEY_PREFIX + window.location.pathname, String(window.scrollY || 0));
    }

    function restoreScrollPosition() {
        if (!isDoctorPath(window.location.pathname)) return;
        const raw = safeGetItem(LAST_SCROLL_KEY_PREFIX + window.location.pathname);
        const y = raw ? Number(raw) : 0;
        if (!Number.isFinite(y) || y <= 0) return;

        // Delay to allow layout to settle
        window.setTimeout(() => {
            try {
                window.scrollTo(0, y);
            } catch {
                // ignore
            }
        }, 50);
    }

    document.addEventListener('DOMContentLoaded', function () {
        restoreScrollPosition();
        saveLastDoctorLocation();

        // Keep updating while navigating around doctor pages.
        window.addEventListener('hashchange', saveLastDoctorLocation);
        window.addEventListener('scroll', function () {
            // light throttling
            if (window.__mmcDoctorScrollTimer) return;
            window.__mmcDoctorScrollTimer = window.setTimeout(() => {
                window.__mmcDoctorScrollTimer = null;
                saveLastDoctorLocation();
            }, 250);
        }, { passive: true });

        // pagehide works better than beforeunload for bfcache
        window.addEventListener('pagehide', saveLastDoctorLocation);
        document.addEventListener('visibilitychange', function () {
            if (document.visibilityState === 'hidden') saveLastDoctorLocation();
        });
    });
})();
