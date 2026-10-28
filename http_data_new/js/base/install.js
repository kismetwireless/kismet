// Settings section for installing the UI as an app on a phone, which browsers
// only allow over HTTPS they trust.  Kismet can serve HTTPS with a certificate
// from a small CA of its own (httpd_ssl=true); the phone needs that CA first.

export function register(kismet) {
    const { ui, api, dom, servers } = kismet;
    const { el } = dom;

    const local = ['localhost', '127.0.0.1', '[::1]'];

    function steps(title, items) {
        return el('details', { class: 'install-steps' },
            el('summary', {}, title),
            el('ol', {}, items.map((i) => el('li', {}, i))));
    }

    function off() {
        return [
            el('p', {}, 'Phones only install the Kismet UI as an app when it comes from an HTTPS address they trust, ' +
                'and this server doesn\'t have HTTPS turned on.'),
            el('p', {}, 'To turn it on, add ', el('code', {}, 'httpd_ssl=true'), ' to kismet_site.conf and restart Kismet.  ' +
                'Kismet then also answers HTTPS on port 2502 (', el('code', {}, 'httpd_ssl_port'), '), with a certificate ' +
                'it makes itself, or your own with ', el('code', {}, 'httpd_ssl_cert'), ' and ', el('code', {}, 'httpd_ssl_key'), '.'),
        ];
    }

    function on(status) {
        const https = new URL(api.root);
        https.protocol = 'https:';
        https.port = String(status.port);

        const out = [];

        if (location.protocol === 'https:' && servers.installed())
            out.push(el('p', { class: 'server-ok' }, 'This app is installed and using HTTPS.'));

        out.push(el('h4', {}, 'HTTPS address'),
            el('p', {}, el('a', { href: https.href, target: '_blank', rel: 'noopener', class: 'mono' }, https.href)));

        if (local.includes(https.hostname))
            out.push(el('p', { class: 'muted' }, 'From a phone, use this computer\'s name or network address in place of ' +
                `${https.hostname}.  Kismet's certificate covers its host name, the name with .local, and its private ` +
                'IPv4 addresses; ' +
                'add others with httpd_ssl_names.'));

        if (!status.generated) {
            out.push(el('p', { class: 'muted' }, 'This server uses its own certificate (httpd_ssl_cert).  If a phone doesn\'t ' +
                'trust it, install the authority that signed it on the phone.'));
            return out;
        }

        out.push(el('h4', {}, 'Trust this server on a phone'),
            el('p', {}, 'Kismet signed its certificate with its own certificate authority.  Install that on the phone, ' +
                'then open the HTTPS address and add it to the home screen.'),
            el('p', {}, el('a', { href: api.url('ssl/kismet_ca.crt').href, download: 'kismet_ca.crt', class: 'button' },
                'Download the Kismet CA')),
            el('p', { class: 'muted' }, 'SHA-256 fingerprint, also in the Kismet log at startup; check they match, ' +
                'since the download may have come over plain HTTP:'),
            el('p', { class: 'mono install-fingerprint' }, status.ca_sha256),
            el('p', { class: 'muted' }, 'The CA can only vouch for local names and private addresses, so it can\'t be ' +
                'used to impersonate other sites to the phone.'),
            steps('iPhone and iPad', [
                'Open the download link in Safari and allow the profile download.',
                'In Settings, General, VPN & Device Management, open the Kismet CA profile and install it.',
                'In Settings, General, About, Certificate Trust Settings, turn on full trust for the Kismet CA.',
                'Open the HTTPS address in Safari, then Share, Add to Home Screen.',
            ]),
            steps('Android', [
                'Download the CA.',
                'In Settings, Security, Encryption & credentials, Install a certificate, CA certificate, pick kismet_ca.crt.  ' +
                    'The menu names differ a little between phones; searching settings for "certificate" finds it.',
                'Open the HTTPS address in Chrome, then the menu, Install app (or Add to Home screen).',
            ]),
            steps('Desktop browsers', [
                'Chrome and Edge: Settings, Privacy and security, Security, Manage certificates, and import the CA as a trusted authority.',
                'Firefox: Settings, Privacy & Security, View Certificates, Authorities, Import, and trust it for websites.',
            ]));

        return out;
    }

    ui.settingsPanes.add({
        id: 'install', title: 'Install as an app', priority: 40,
        create(body) {
            body.append(el('p', { class: 'muted' }, 'Checking this server…'));
            api.get('ssl/status.json', { noAuthEvent: true })
                .then((status) => body.replaceChildren(...(status.enabled ? on(status) : off())))
                .catch((err) => body.replaceChildren(el('p', { class: 'form-error' },
                    `Couldn't ask the server about HTTPS: ${err.message}.  It may be an older Kismet.`)));
        },
    });
}
