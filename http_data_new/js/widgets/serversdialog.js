// The list of Kismet servers the app knows, to switch between them and add
// or forget servers.  See js/core/servers.js.

import { el } from '../core/dom.js';
import * as servers from '../core/servers.js';
import { dialog } from './dialog.js';

// Whether a server answers this app at all: a server that doesn't allow
// requests from this app's address looks the same as one that's down
async function reachable(url) {
    if (servers.blockedMixed(url))
        return 'blocked';
    try {
        await fetch(new URL('session/check_setup_ok', url), { credentials: 'omit', signal: AbortSignal.timeout(4000) });
        return 'ok';
    } catch {
        return 'unreachable';
    }
}

const statusText = {
    ok: 'reachable',
    unreachable: 'can\'t reach it, or it doesn\'t allow this app',
    blocked: 'needs https: this app was loaded over https',
};

let open = null;

export function openServers() {
    if (open)
        return;

    const current = servers.current();
    const listEl = el('div', { class: 'server-list' });

    function row(s) {
        const isCurrent = s ? current?.id === s.id : current === null;
        const url = s ? s.url : servers.home.href;
        const status = el('span', { class: 'muted' }, 'checking…');
        reachable(url).then((r) => {
            status.textContent = statusText[r];
            status.className = r === 'ok' ? 'server-ok' : 'form-error';
        });

        return el('div', { class: ['server-item', isCurrent && 'current'] },
            el('div', { class: 'server-info' },
                el('strong', {}, s ? s.name : 'This server'),
                isCurrent ? el('span', { class: 'badge' }, 'in use') : null,
                el('div', { class: 'muted mono' }, url),
                status,
                s && !s.token ? el('div', { class: 'muted' }, 'Not logged in yet') : null,
                s ? el('label', { class: 'check-item', title: 'A server\'s plugins run inside this app, where they could read its keys for your other servers' },
                    el('input', { type: 'checkbox', checked: s.trustPlugins === true, onchange: (e) => {
                        if (e.target.checked && !confirm(`Run ${s.name}'s UI plugins?  Only do this for a server you trust: ` +
                            'its plugins could read this app\'s keys for your other servers.')) {
                            e.target.checked = false;
                            return;
                        }
                        servers.setTrustPlugins(s.id, e.target.checked);
                        if (isCurrent)
                            location.reload();
                    } }), ' Run its UI plugins') : null),
            el('div', { class: 'server-actions' },
                isCurrent ? null : el('button', { type: 'button', class: 'primary', onclick: () => servers.select(s ? s.id : null) }, 'Connect'),
                s ? el('button', { type: 'button', onclick: async () => {
                    if (!confirm(`Forget ${s.name}?  The app's key there is revoked if the server can be reached.`))
                        return;
                    await servers.remove(s.id);
                    if (isCurrent)
                        location.reload();
                    else
                        fill();
                } }, 'Forget') : null));
    }

    function fill() {
        listEl.replaceChildren(row(null), ...servers.list().map(row));
    }

    const name = el('input', { name: 'server-name', placeholder: 'Name (optional)', autocomplete: 'off' });
    const address = el('input', { name: 'server-url', placeholder: 'https://kismet.example:2501/', required: true,
        autocomplete: 'off', autocapitalize: 'off', spellcheck: false, inputmode: 'url' });
    const error = el('p', { class: 'form-error' });

    const form = el('form', { class: 'form server-add' },
        el('h3', {}, 'Add a server'),
        el('label', {}, 'Address', address),
        el('label', {}, 'Name', name),
        error,
        el('div', { class: 'form-buttons' }, el('button', { type: 'submit', class: 'primary' }, 'Add')));

    form.addEventListener('submit', (e) => {
        e.preventDefault();
        error.textContent = '';
        try {
            servers.add(name.value, address.value);
            name.value = '';
            address.value = '';
            fill();
        } catch (err) {
            error.textContent = err.message;
        }
    });

    const help = el('p', { class: 'muted' },
        'Other servers have to allow this app.  In their kismet_site.conf, set ',
        el('code', {}, 'httpd_allow_cors=true'), ' and ',
        el('code', {}, `httpd_allowed_origin=${location.origin}`), '.');

    fill();
    const d = dialog({ title: 'Servers', body: el('div', { class: 'servers' }, listEl, form, help), className: 'servers-dialog',
        onClose: () => { open = null; } });
    open = d;
}
