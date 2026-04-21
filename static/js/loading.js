/**
 * MMC Loading Indicator Utility
 * Provides global loading state management with multiple status states
 * 
 * Usage:
 *   MMCLoader.show('Uploading...', 'Please wait');
 *   MMCLoader.setStatus('complete'); // Shows green checkmark
 *   MMCLoader.setStatus('done', 2000); // Shows cyan checkmark, auto-hides after 2s
 *   MMCLoader.hide();
 */

const MMCLoader = (() => {
    const STATES = {
        LOADING: 'loading',
        COMPLETE: 'complete',
        DONE: 'done'
    };

    const SPINNER_CLASSES = {
        loading: 'mmc-spinner--loading',
        complete: 'mmc-spinner--complete',
        done: 'mmc-spinner--done'
    };

    let currentState = STATES.LOADING;
    let hideTimeoutId = null;
    let autoHideTimeoutId = null;

    /**
     * Get the loading overlay elements
     */
    function getElements() {
        return {
            overlay: document.getElementById('mmc-loading-overlay'),
            container: document.querySelector('.mmc-loading-container'),
            spinner: document.querySelector('.mmc-spinner'),
            title: document.getElementById('mmc-loading-title'),
            message: document.getElementById('mmc-loading-message')
        };
    }

    /**
     * Show the loading overlay with initial message
     * @param {string} title - Main title/status text
     * @param {string} message - Subtitle message (optional)
     */
    function show(title = 'Loading...', message = '') {
        const elements = getElements();
        if (!elements.overlay) return;

        // Clear any pending timeouts
        if (hideTimeoutId) {
            clearTimeout(hideTimeoutId);
            hideTimeoutId = null;
        }
        if (autoHideTimeoutId) {
            clearTimeout(autoHideTimeoutId);
            autoHideTimeoutId = null;
        }

        // Reset to loading state
        setCurrentState(STATES.LOADING);

        // Update content
        if (elements.title) elements.title.textContent = title;
        if (elements.message) elements.message.textContent = message;

        // Show overlay
        elements.overlay.classList.add('active');
        elements.overlay.style.display = 'flex';
    }

    /**
     * Hide the loading overlay with optional fade delay
     * @param {number} delay - Delay in milliseconds before hiding
     */
    function hide(delay = 0) {
        if (hideTimeoutId) {
            clearTimeout(hideTimeoutId);
            hideTimeoutId = null;
        }

        if (autoHideTimeoutId) {
            clearTimeout(autoHideTimeoutId);
            autoHideTimeoutId = null;
        }

        const elements = getElements();
        if (!elements.overlay) return;

        if (delay > 0) {
            hideTimeoutId = setTimeout(() => {
                elements.overlay.classList.remove('active');
                elements.overlay.style.display = 'none';
                hideTimeoutId = null;
            }, delay);
        } else {
            elements.overlay.classList.remove('active');
            elements.overlay.style.display = 'none';
        }
    }

    /**
     * Update just the title text
     * @param {string} title - New title text
     */
    function setTitle(title) {
        const elements = getElements();
        if (elements.title) {
            elements.title.textContent = title;
        }
    }

    /**
     * Update just the message text
     * @param {string} message - New message text
     */
    function setMessage(message) {
        const elements = getElements();
        if (elements.message) {
            elements.message.textContent = message;
        }
    }

    /**
     * Update both title and message
     * @param {string} title - New title text
     * @param {string} message - New message text
     */
    function updateText(title, message = '') {
        setTitle(title);
        setMessage(message);
    }

    /**
     * Set the loading state (loading, complete, done)
     * @param {string} state - One of: 'loading', 'complete', 'done'
     * @param {number} autoHideAfter - Auto-hide after N milliseconds (optional)
     */
    function setStatus(state, autoHideAfter = null) {
        if (!Object.values(STATES).includes(state)) {
            console.warn(`MMCLoader: Unknown state "${state}". Use one of: ${Object.values(STATES).join(', ')}`);
            return;
        }

        setCurrentState(state);

        // Clear any pending auto-hide
        if (autoHideTimeoutId) {
            clearTimeout(autoHideTimeoutId);
            autoHideTimeoutId = null;
        }

        // Auto-hide if specified
        if (autoHideAfter && autoHideAfter > 0) {
            autoHideTimeoutId = setTimeout(() => {
                hide(300); // Fade out before hiding
            }, autoHideAfter);
        }
    }

    /**
     * Internal function to update state and UI
     * @param {string} state - One of: 'loading', 'complete', 'done'
     */
    function setCurrentState(state) {
        const elements = getElements();
        if (!elements.container) return;

        // Remove all status classes
        Object.values(STATES).forEach(s => {
            elements.container.classList.remove(`status-${s}`);
        });

        // Remove all spinner classes
        Object.values(SPINNER_CLASSES).forEach(cls => {
            elements.spinner.classList.remove(cls);
        });

        // Add new classes
        currentState = state;
        elements.container.classList.add(`status-${state}`);
        elements.spinner.classList.add(SPINNER_CLASSES[state]);
    }

    /**
     * Convenience: Show loading → complete → done sequence
     * @param {string} title - Title for loading state
     * @param {string} message - Message for loading state
     */
    function executeSequence(title = 'Processing...', message = '') {
        show(title, message);
        
        // Auto-transition to complete after 1.5s
        setTimeout(() => {
            setStatus(STATES.COMPLETE);
        }, 1500);

        // Auto-transition to done after 2.5s total
        setTimeout(() => {
            setStatus(STATES.DONE);
        }, 2500);

        // Auto-hide after 4s total
        setTimeout(() => {
            hide();
        }, 4000);
    }

    /**
     * Quick status check (for debugging)
     */
    function getStatus() {
        return {
            isVisible: document.getElementById('mmc-loading-overlay')?.classList.contains('active') || false,
            currentState: currentState,
            title: document.getElementById('mmc-loading-title')?.textContent || '',
            message: document.getElementById('mmc-loading-message')?.textContent || ''
        };
    }

    // Public API
    return {
        show,
        hide,
        setTitle,
        setMessage,
        updateText,
        setStatus,
        executeSequence,
        getStatus,
        // State constants for external use
        STATES
    };
})();

// Optional: Make globally accessible without MMCLoader prefix
// window.showLoader = (title, msg) => MMCLoader.show(title, msg);
// window.hideLoader = () => MMCLoader.hide();
// window.setLoaderStatus = (status) => MMCLoader.setStatus(status);
