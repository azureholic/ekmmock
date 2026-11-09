// Small helpers for the console. Served from this process (no CDN). No secret ever passes through here: copy is offered for ids and for masked JSON only.
window.ekmConsole = {
    copyText: async function (text) {
        if (navigator.clipboard && window.isSecureContext) {
            await navigator.clipboard.writeText(text);
            return;
        }

        // Fallback for contexts without the async clipboard API.
        const area = document.createElement('textarea');
        area.value = text;
        area.setAttribute('readonly', '');
        area.style.position = 'fixed';
        area.style.opacity = '0';
        document.body.appendChild(area);
        area.select();
        try {
            if (!document.execCommand('copy')) {
                throw new Error('copy failed');
            }
        } finally {
            document.body.removeChild(area);
        }
    },

    scrollToTop: function (element) {
        if (element) {
            element.scrollTop = 0;
        }
    },
};

// The skip link ("Skip to main content"): focus the main landmark itself. The Blazor router would otherwise treat the fragment link as a navigation and move the focus to the page
// heading's start; handling it in the capture phase keeps the behaviour the link promises.
document.addEventListener('click', function (event) {
    const target = event.target;
    if (target instanceof Element && target.closest('a.skip-link')) {
        const main = document.getElementById('console-main');
        if (main) {
            event.preventDefault();
            event.stopPropagation();
            main.focus();
        }
    }
}, true);

// The reconnect dialog's "Reload page" button. An inline onclick would be blocked by the console's CSP (script-src 'self'), so the handler lives here.
document.addEventListener('click', function (event) {
    const target = event.target;
    if (target instanceof Element && target.closest('[data-reload]')) {
        window.location.reload();
    }
});
