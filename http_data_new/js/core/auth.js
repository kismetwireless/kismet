// Logging in to Kismet.
//
// Logging in once with the username and password makes the server set a
// session cookie (KISMET), which every later request and the websocket use.
// On another server (js/core/servers.js) the login instead makes an API key
// for this app there, which is kept in place of a cookie.
// The password itself is never stored by the UI.

import * as api from './api.js';
import * as servers from './servers.js';
import { el } from './dom.js';
import { dialog } from '../widgets/dialog.js';
import { openServers } from '../widgets/serversdialog.js';

// Another way out of a login, in the app or when on another server
function switchButton() {
    return servers.installed() || api.remote ?
        el('button', { type: 'button', onclick: () => openServers() }, 'Switch server') : null;
}

function basicAuth(user, password) {
    const bytes = new TextEncoder().encode(`${user}:${password}`);
    return 'Basic ' + btoa(String.fromCharCode(...bytes));
}

async function tryLogin(user, password) {
    const auth = basicAuth(user, password);
    const r = await api.probe('session/check_login', { headers: { Authorization: auth } });
    if (!r.ok || !api.remote)
        return r.ok;

    // A key for this app on that server; the name says where it's from, so it
    // can be found and revoked there
    const name = `Kismet app, ${new Date().toISOString().slice(0, 10)}, ${crypto.randomUUID().slice(0, 8)}`;
    const body = new URLSearchParams({ json: JSON.stringify({ name, role: 'admin', duration: 0 }) });
    const k = await api.probe('auth/apikey/generate.cmd', {
        method: 'POST', ...api.formBody(body),
        headers: { ...api.formBody(body).headers, Authorization: auth },
    });
    if (!k.ok)
        throw new Error(`Logged in, but the server would not make a key for this app: ${(await k.text()).trim()}`);
    const token = (await k.text()).trim();
    if (!/^[0-9a-fA-F]{32}$/.test(token))
        throw new Error('Logged in, but the server sent back an unexpected key');
    servers.setToken(api.remote.id, token, name);
    // Reload so every request and websocket starts with the key
    location.reload();
    return new Promise(() => {});
}

// Resolves once we have a working session, asking the user to log in (or to
// set a password on a new install) if needed.
export async function ensureSession() {
    const setup = await api.probe('session/check_setup_ok');

    // 500: no login has been configured yet on this server
    if (setup.status === 500)
        return askNewPassword();

    if ((await api.probe('session/check_session')).ok)
        return;

    return askLogin();
}

let pending = null;
const loginListeners = new Set();

// Called after the user logs in again, so anything that failed while the
// session was gone can reload
export function onLogin(fn) {
    loginListeners.add(fn);
    return () => loginListeners.delete(fn);
}

// Show the login dialog (once, however many requests got a 401)
export function askLogin(message = '') {
    if (pending)
        return pending;

    pending = new Promise((resolve) => {
        const user = el('input', { name: 'username', autocomplete: 'username', required: true });
        const password = el('input', { name: 'password', type: 'password', autocomplete: 'current-password', required: true });
        const error = el('p', { class: 'form-error' }, message);

        const form = el('form', { class: 'form' },
            el('p', {}, api.remote ?
                `Log in to ${api.remote.name} (${api.root.host}).  This app keeps a key for that server, not the password.` :
                'Log in to this Kismet server.  The login is in ~/.kismet/kismet_httpd.conf on the server.'),
            el('label', {}, 'Username', user),
            el('label', {}, 'Password', password),
            error,
            el('div', { class: 'form-buttons' }, switchButton(), el('button', { type: 'submit', class: 'primary' }, 'Log in')));

        const d = dialog({ title: 'Login', body: form, closable: false });

        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            error.textContent = '';
            try {
                if (await tryLogin(user.value, password.value)) {
                    d.close();
                    pending = null;
                    resolve();
                    for (const fn of loginListeners)
                        fn();
                } else {
                    error.textContent = 'Wrong username or password';
                    password.select();
                }
            } catch (err) {
                error.textContent = err.message;
            }
        });

        user.focus();
    });

    return pending;
}

// First run: the server has no login yet, so ask for one
function askNewPassword() {
    return new Promise((resolve) => {
        const user = el('input', { name: 'username', autocomplete: 'username', required: true });
        const password = el('input', { name: 'password', type: 'password', autocomplete: 'new-password', required: true });
        const again = el('input', { name: 'confirm', type: 'password', autocomplete: 'new-password', required: true });
        const error = el('p', { class: 'form-error' });

        const form = el('form', { class: 'form' },
            el('p', {}, 'This Kismet server has no login yet.  Choose the username and password for the web UI and API.'),
            el('label', {}, 'Username', user),
            el('label', {}, 'Password', password),
            el('label', {}, 'Confirm password', again),
            error,
            el('div', { class: 'form-buttons' }, el('button', { type: 'submit', class: 'primary' }, 'Set login')));

        const d = dialog({ title: 'Set a login', body: form, closable: false });

        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            if (password.value !== again.value) {
                error.textContent = 'The passwords don\'t match';
                return;
            }
            try {
                const body = new URLSearchParams({ username: user.value, password: password.value });
                const r = await api.probe('session/set_password', { method: 'POST', ...api.formBody(body) });
                if (!r.ok)
                    throw new Error(await r.text());
                await tryLogin(user.value, password.value);
                d.close();
                resolve();
            } catch (err) {
                error.textContent = `Could not set the login: ${err.message}`;
            }
        });

        user.focus();
    });
}

api.onAuthRequired(() => askLogin('Your session has ended; please log in again.'));
