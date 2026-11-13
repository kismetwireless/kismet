// The API keys of the Kismet server in use: list, show, copy, revoke, and
// create them.  Keys stay hidden until asked for, and are only put in the page
// while shown.  A server with httpd_allow_auth_view=false never sends them, so
// a key made here is kept until the window closes, to show or copy it once.

import { el } from '../core/dom.js';
import { icon } from '../core/icons.js';
import * as api from '../core/api.js';
import * as servers from '../core/servers.js';
import * as format from '../core/format.js';
import { dialog, confirm } from './dialog.js';

const roles = [
    { id: 'readonly', title: 'Read-only', help: 'Any endpoint which doesn\'t change devices, sources or settings' },
    { id: 'admin', title: 'Admin', help: 'Every endpoint, as a logged in user' },
    { id: 'datasource', title: 'Data source', help: 'Remote capture over websockets only' },
    { id: 'scanreport', title: 'Scan report', help: 'Device scan reports only' },
    { id: 'ADSB', title: 'ADSB', help: 'The ADSB feeds only' },
    { id: 'datalog', title: 'Data log', help: 'Saving tagged data records to the kismetdb log only' },
];

const durations = [
    ['Never', 0], ['1 hour', 3600], ['1 day', 86400], ['1 week', 7 * 86400],
    ['30 days', 30 * 86400], ['1 year', 365 * 86400],
];

const maxName = 64;
const customRole = /^[A-Za-z0-9_.-]{1,32}$/;
const hiddenKey = '•'.repeat(16);

const roleTitle = (id) => roles.find((r) => r.id === id)?.title ?? id;
const roleHelp = (id) => roles.find((r) => r.id === id)?.help ?? 'A role defined by a plugin';

// Without a secure context there's no clipboard API: show and select the key
// so it can be copied by hand
async function copyKey(token, keyEl, reveal) {
    if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(token);
        return 'Copied';
    }
    reveal();
    const range = document.createRange();
    range.selectNodeContents(keyEl);
    const sel = window.getSelection();
    sel.removeAllRanges();
    sel.addRange(range);
    return 'Selected; copy it with Ctrl+C';
}

let open = null;

export function openApiKeys() {
    if (open)
        return;

    // This app's own key when it's on another server: revoking it logs the app out there
    const ownName = servers.current()?.tokenName ?? null;
    // Keys made in this window, by name, for servers which don't list them
    const made = new Map();
    // Names whose keys are shown
    const shown = new Set();

    const listEl = el('div', { class: 'apikey-list' }, el('p', { class: 'muted' }, 'Loading…'));
    const listError = el('p', { class: 'form-error' });

    function row(rec) {
        const name = String(rec['kismet.httpd.auth.name'] ?? '');
        const role = String(rec['kismet.httpd.auth.role'] ?? '');
        const expires = Number(rec['kismet.httpd.auth.expiration'] ?? 0);
        const listed = typeof rec['kismet.httpd.auth.token'] === 'string' ? rec['kismet.httpd.auth.token'] : null;
        const token = listed ?? made.get(name) ?? null;
        const expired = expires > 0 && expires * 1000 < Date.now();

        const keyEl = el('span', { class: 'mono apikey-key' });
        const status = el('span', { class: 'muted apikey-status', 'aria-live': 'polite' });
        const showButton = el('button', { type: 'button' });

        function draw() {
            const visible = shown.has(name);
            keyEl.textContent = visible ? token : hiddenKey;
            showButton.replaceChildren(visible ? 'Hide' : 'Show');
            showButton.setAttribute('aria-pressed', visible ? 'true' : 'false');
        }

        const reveal = () => {
            shown.add(name);
            draw();
        };

        showButton.addEventListener('click', () => {
            shown.has(name) ? shown.delete(name) : shown.add(name);
            draw();
        });

        let keyPart;
        if (token) {
            draw();
            keyPart = el('div', { class: 'apikey-keyrow' }, keyEl,
                showButton,
                el('button', { type: 'button', title: 'Copy the key', onclick: async () => {
                    try {
                        status.textContent = await copyKey(token, keyEl, reveal);
                    } catch (err) {
                        status.textContent = `Couldn't copy: ${err.message}`;
                    }
                } }, icon('copy'), ' Copy'),
                status);
        } else {
            keyPart = el('div', { class: 'muted apikey-keyrow' },
                'This server doesn\'t show keys (httpd_allow_auth_view=false).');
        }

        const own = ownName !== null && name === ownName;

        return el('div', { class: ['apikey-item', expired && 'expired'] },
            el('div', { class: 'apikey-info' },
                el('strong', {}, name),
                own ? el('span', { class: 'badge' }, 'this app') : null,
                expired ? el('span', { class: 'badge error' }, 'expired') : null,
                el('div', { class: 'muted' },
                    el('span', { title: roleHelp(role) }, roleTitle(role)),
                    ' · ',
                    expires ? `${expired ? 'Expired' : 'Expires'} ${format.time(expires)}` : 'Never expires')),
            el('div', { class: 'apikey-actions' },
                el('button', { type: 'button', class: 'danger', onclick: async () => {
                    const ok = await confirm({
                        title: 'Revoke API key?',
                        text: `Revoke "${name}"?  Anything using this key loses access to the server.` +
                            (own ? '\n\nThis app uses this key for this server, and will ask you to log in again.' : ''),
                        ok: 'Revoke', danger: true,
                    });
                    if (!ok)
                        return;
                    try {
                        await api.command('auth/apikey/revoke.cmd', { name });
                        made.delete(name);
                        shown.delete(name);
                        fill();
                    } catch (err) {
                        listError.textContent = `Couldn't revoke "${name}": ${err.message}`;
                    }
                } }, 'Revoke')),
            keyPart);
    }

    async function fill() {
        listError.textContent = '';
        try {
            const keys = await api.get('auth/apikey/list.json');
            const recs = (Array.isArray(keys) ? keys : [])
                .filter((k) => k && typeof k === 'object')
                .sort((a, b) => String(a['kismet.httpd.auth.name']).localeCompare(String(b['kismet.httpd.auth.name'])));
            listEl.replaceChildren(...(recs.length ? recs.map(row) : [el('p', { class: 'muted' }, 'No API keys yet.')]));
            return recs;
        } catch (err) {
            listEl.replaceChildren();
            listError.textContent = err.status === 401 || err.status === 403 ?
                'Only an admin login can manage API keys.' : `Couldn't load the API keys: ${err.message}`;
            return [];
        }
    }

    // The key just made, shown once in front of the list
    function showCreated(keyName, token, listed) {
        const keyEl = el('div', { class: 'mono apikey-new-key' }, token);
        const status = el('span', { class: 'muted', 'aria-live': 'polite' });
        const d = dialog({
            title: 'API key created',
            className: 'apikey-new-dialog',
            body: el('div', { class: 'form' },
                el('p', {}, `The key for "${keyName}":`),
                keyEl,
                el('p', { class: 'form-note' }, listed ?
                    'It can be shown and copied again from the list of keys.' :
                    'This server doesn\'t show keys again: copy it now.'),
                el('div', { class: 'form-buttons' },
                    status,
                    el('button', { type: 'button', class: 'primary', onclick: async () => {
                        try {
                            status.textContent = await copyKey(token, keyEl, () => {});
                        } catch (err) {
                            status.textContent = `Couldn't copy: ${err.message}`;
                        }
                    } }, icon('copy'), ' Copy'),
                    el('button', { type: 'button', onclick: () => d.close() }, 'Done'))),
        });
        d.node.querySelector('.form-buttons .primary')?.focus();
    }

    const name = el('input', { name: 'apikey-name', required: true, maxlength: maxName, autocomplete: 'off', spellcheck: false });
    const role = el('select', { name: 'apikey-role' },
        roles.map((r) => el('option', { value: r.id, title: r.help }, `${r.title} (${r.id})`)),
        el('option', { value: '' }, 'Other role…'));
    const custom = el('input', { name: 'apikey-custom-role', placeholder: 'Role name', maxlength: 32, autocomplete: 'off',
        spellcheck: false, hidden: true });
    const roleNote = el('p', { class: 'form-note' }, roles[0].help);
    const duration = el('select', { name: 'apikey-duration' }, durations.map(([t, s]) => el('option', { value: String(s) }, t)));
    const error = el('p', { class: 'form-error' });

    role.addEventListener('change', () => {
        custom.hidden = role.value !== '';
        custom.required = role.value === '';
        roleNote.textContent = role.value ? roleHelp(role.value) : 'A role a plugin defines; it can use only what the plugin allows.';
    });

    const form = el('form', { class: 'form apikey-add' },
        el('h3', {}, 'Create a key'),
        el('label', {}, 'Name', name),
        el('label', {}, 'Role', role, custom),
        roleNote,
        el('label', {}, 'Expires after', duration),
        error,
        el('div', { class: 'form-buttons' }, el('button', { type: 'submit', class: 'primary' }, 'Create')));

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        error.textContent = '';
        const n = name.value.trim();
        const r = role.value || custom.value.trim();
        if (!n || n.length > maxName || /[\u0000-\u001f\u007f]/.test(n)) {
            error.textContent = `Give the key a name of up to ${maxName} characters.`;
            return;
        }
        if (!role.value && !customRole.test(r)) {
            error.textContent = 'A role name is letters, digits, "_", "." or "-", up to 32 characters.';
            return;
        }
        try {
            const token = (await api.command('auth/apikey/generate.cmd',
                { name: n, role: r, duration: Number(duration.value) })).trim();
            const valid = /^[0-9a-fA-F]{32}$/.test(token);
            if (valid)
                made.set(n, token);
            name.value = '';
            const recs = await fill();
            if (valid)
                showCreated(n, token, recs.some((k) => k['kismet.httpd.auth.name'] === n &&
                    typeof k['kismet.httpd.auth.token'] === 'string'));
            else
                error.textContent = 'The key was made, but the server sent back something unexpected; see the list.';
        } catch (err) {
            error.textContent = /duplicate/i.test(err.message) ? `There's already a key named "${n}".` : err.message;
        }
    });

    const help = el('p', { class: 'muted apikeys-help' },
        'Programs and remote capture use a key in place of a login: send it as ',
        el('code', {}, 'Authorization: Bearer <key>'), ' or the ', el('code', {}, 'KISMET'), ' cookie.');

    fill();
    open = dialog({
        title: api.remote ? `API keys: ${api.remote.name}` : 'API keys',
        body: el('div', { class: 'apikeys' },
            el('div', { class: 'apikeys-main' }, listError, listEl, help),
            el('div', { class: 'apikeys-side' }, form)),
        className: 'apikeys-dialog',
        onClose: () => {
            made.clear();
            shown.clear();
            open = null;
        },
    });
    name.focus();
}
