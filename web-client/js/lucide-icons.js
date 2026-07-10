/**
 * lucide-icons.js — a tiny, self-contained, offline replacement for the
 * lucide icon library.
 *
 * Why this exists: the app previously loaded lucide from
 * https://unpkg.com/lucide@latest at page load, and called
 * lucide.createIcons() from the load handler of every page. If unpkg was
 * unreachable (CDN outage, offline, restricted network) the script 404'd,
 * `lucide` was undefined, and the createIcons() call threw in the load
 * handler — aborting page setup (including key-vault unlock). A third-party
 * CDN was a single point of failure for the entire app loading.
 *
 * This file vendors ONLY the ~dozen icons the app actually references via
 * `data-lucide="…"`, and reimplements createIcons() with the same public
 * shape (window.lucide.createIcons()). No network dependency; identical
 * call sites and markup. Icon path geometry is from the lucide project
 * (ISC-licensed, https://lucide.dev).
 */
(function () {
  // Inner SVG markup for each icon used in the app. All lucide icons share
  // viewBox 0 0 24 24, no fill, currentColor stroke, width 2, round caps.
  const ICONS = {
    'x':
      '<path d="M18 6 6 18"/><path d="m6 6 12 12"/>',
    'lock':
      '<rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
    'lock-keyhole':
      '<circle cx="12" cy="16" r="1"/><rect x="3" y="10" width="18" height="12" rx="2"/><path d="M7 10V7a5 5 0 0 1 10 0v3"/>',
    'log-out':
      '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" x2="9" y1="12" y2="12"/>',
    'settings':
      '<path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z"/><circle cx="12" cy="12" r="3"/>',
    'upload':
      '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" x2="12" y1="3" y2="15"/>',
    'shield':
      '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
    'shield-check':
      '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/>',
    'shield-alert':
      '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M12 8v4"/><path d="M12 16h.01"/>',
    'paperclip':
      '<path d="m21.44 11.05-9.19 9.19a6 6 0 0 1-8.49-8.49l8.57-8.57A4 4 0 1 1 18 8.84l-8.59 8.57a2 2 0 0 1-2.83-2.83l8.49-8.48"/>',
    'link':
      '<path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>',
    'key-round':
      '<path d="M2.586 17.414A2 2 0 0 0 2 18.828V21a1 1 0 0 0 1 1h3a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h1a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h.172a2 2 0 0 0 1.414-.586l.814-.814a6.5 6.5 0 1 0-4-4z"/><circle cx="16.5" cy="7.5" r=".5" fill="currentColor"/>',
    'triangle-alert':
      '<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><path d="M12 9v4"/><path d="M12 17h.01"/>',
    // Icons generated dynamically by files.js file rows (were served by the
    // full unpkg bundle before it was vendored locally):
    'download':
      '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" x2="12" y1="15" y2="3"/>',
    'forward':
      '<polyline points="15 17 20 12 15 7"/><path d="M4 18v-2a4 4 0 0 1 4-4h12"/>',
    'trash-2':
      '<path d="M3 6h18"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><line x1="10" x2="10" y1="11" y2="17"/><line x1="14" x2="14" y1="11" y2="17"/>',
    'folder-open':
      '<path d="m6 14 1.5-2.9A2 2 0 0 1 9.24 10H20a2 2 0 0 1 1.94 2.5l-1.54 6a2 2 0 0 1-1.95 1.5H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h3.9a2 2 0 0 1 1.69.9l.81 1.2a2 2 0 0 0 1.67.9H18a2 2 0 0 1 2 2v2"/>',
    'shield-off':
      '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m2 2 20 20"/>',
    // Compound file icons — a file body plus a distinguishing inner mark.
    'file-lock-2':
      '<path d="M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7z"/><path d="M14 2v4a2 2 0 0 0 2 2h4"/><rect width="8" height="5" x="8" y="12.5" rx="1"/><path d="M10 12.5v-1a2 2 0 0 1 4 0v1"/>',
    'file-key-2':
      '<path d="M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7z"/><path d="M14 2v4a2 2 0 0 0 2 2h4"/><circle cx="9" cy="15" r="2"/><path d="m11 15 4 4"/><path d="m14 18 1-1"/>',
    // B4 on-chain evidence badges:
    'circle-check':
      '<circle cx="12" cy="12" r="10"/><path d="m9 12 2 2 4-4"/>',
    'clock':
      '<circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>',
    'external-link':
      '<path d="M15 3h6v6"/><path d="M10 14 21 3"/><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>',
  };

  function buildSvg(name, sourceEl) {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('fill', 'none');
    svg.setAttribute('stroke', 'currentColor');
    svg.setAttribute('stroke-width', '2');
    svg.setAttribute('stroke-linecap', 'round');
    svg.setAttribute('stroke-linejoin', 'round');
    svg.setAttribute('width', '24');
    svg.setAttribute('height', '24');
    svg.classList.add('lucide', 'lucide-' + name);
    // Carry over the placeholder's class + inline style (several icons set
    // an explicit width/height via style).
    if (sourceEl.getAttribute('class')) {
      sourceEl.getAttribute('class').split(/\s+/).forEach((c) => c && svg.classList.add(c));
    }
    if (sourceEl.getAttribute('style')) svg.setAttribute('style', sourceEl.getAttribute('style'));
    svg.innerHTML = ICONS[name];
    return svg;
  }

  function createIcons() {
    document.querySelectorAll('[data-lucide]').forEach((el) => {
      const name = el.getAttribute('data-lucide');
      if (!ICONS[name]) {
        // Unknown icon: leave the placeholder rather than throw, and make
        // the gap visible in dev without breaking the page.
        console.warn('lucide-icons: no vendored icon for', name);
        return;
      }
      el.replaceWith(buildSvg(name, el));
    });
  }

  window.lucide = { createIcons };
})();
