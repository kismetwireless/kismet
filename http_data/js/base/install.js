// Settings section for installing the UI as an app on a phone, which browsers
// only allow over HTTPS they trust.  Kismet can serve HTTPS with a certificate
// from a small CA of its own (httpd_ssl=true); the phone needs that CA first.
// Behind an HTTPS proxy (httpd_https_proxy=true) the proxy's certificate is
// used instead, at the address in httpd_public_url.

export function register(kismet) {
    const { ui, api, dom, servers, pwa, icons } = kismet;
    const { el } = dom;

    const local = ['localhost', '127.0.0.1', '[::1]'];

    function steps(title, items) {
        return el('details', { class: 'install-steps' },
            el('summary', {}, title),
            el('ol', {}, items.map((i) => el('li', {}, i))));
    }

    // httpd_public_url, if it's a usable address
    function publicUrl(status) {
        try {
            const u = new URL(status.public_url ?? '');
            return ['http:', 'https:'].includes(u.protocol) ? u : null;
        } catch {
            return null;
        }
    }

    const ipad = /iPad/.test(navigator.userAgent) || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);
    const ios = ipad || /iPhone|iPod/.test(navigator.userAgent);
    const iosOtherBrowser = /CriOS|FxiOS|EdgiOS/.test(navigator.userAgent);

    // iOS has no install prompt for pages to offer; it's in the Share menu
    function iosSteps() {
        const where = iosOtherBrowser ? 'the Share button (in the address bar or the menu)' :
            ipad ? 'the Share button at the top of the screen' : 'the Share button in the bar at the bottom of the screen';
        return el('ol', { class: 'install-ios' },
            el('li', {}, 'Tap ', el('span', { class: 'install-glyph' }, icons.icon('share')), ` ${where}.`),
            el('li', {}, 'Scroll down the list and tap ', el('span', { class: 'install-glyph' }, icons.icon('plus')),
                ' ', el('strong', {}, 'Add to Home Screen'), '.'),
            el('li', {}, 'Turn on ', el('strong', {}, 'Open as Web App'), ' if it\'s shown, then tap ', el('strong', {}, 'Add'), '.'),
            el('li', {}, 'Start Kismet from the new icon on the home screen.'));
    }

    // The install button, or how to install from here.  `address` is where the
    // UI can be installed from, when that's somewhere else.
    function installBox(address) {
        const box = el('div', { class: 'install-box' });

        function fill() {
            let content;
            if (servers.installed()) {
                content = el('p', { class: 'server-ok' }, 'Kismet is installed as an app.');
            } else if (pwa.canInstall()) {
                content = el('button', { type: 'button', class: 'primary install-button', onclick: async () => {
                    await pwa.install();
                    fill();
                } }, 'Install Kismet');
            } else if (!window.isSecureContext || (address && address.origin !== location.origin)) {
                content = address?.protocol === 'https:' ?
                    [el('p', {}, 'Installing needs the HTTPS address; open it there, then install from that page.'),
                        el('a', { href: address.href, class: 'button install-button' }, 'Open the HTTPS address')] :
                    el('p', {}, 'Installing needs an HTTPS address; see below.');
            } else if (ios) {
                content = [el('p', {}, el('strong', {}, 'To install on this ' + (ipad ? 'iPad' : 'iPhone') + ':')), iosSteps()];
            } else {
                content = el('p', {}, 'Use the browser\'s menu: Install app, or Add to Home screen.  If neither is there, ' +
                    'reload the page once and try again.');
            }
            box.replaceChildren(...[content].flat());
        }

        fill();
        return { box, fill };
    }

    // Where the UI can be installed from: the proxy's or public address, or
    // Kismet's own HTTPS port
    function installAddress(status) {
        const pub = publicUrl(status);
        if (pub?.protocol === 'https:' && (status.https_proxy || status.enabled))
            return pub;
        if (status.https_proxy)
            return api.root.protocol === 'https:' ? new URL(api.root) : null;
        if (!status.enabled)
            return null;
        const u = new URL(api.root);
        u.protocol = 'https:';
        u.port = String(status.port);
        return u;
    }

    function addressLink(u) {
        return el('p', {}, el('a', { href: u.href, target: '_blank', rel: 'noopener', class: 'mono' }, u.href));
    }

    function proxied(status) {
        const u = installAddress(status);

        if (!u)
            return [
                el('p', {}, 'This server is set up behind an HTTPS proxy (httpd_https_proxy), but doesn\'t know the ' +
                    'proxy\'s address.'),
                el('p', {}, 'Set ', el('code', {}, 'httpd_public_url'), ' in kismet_site.conf to the https:// address ' +
                    'the proxy serves Kismet at, and restart Kismet.'),
            ];

        return [
            el('h4', {}, 'Address'),
            addressLink(u),
            el('p', { class: 'muted' }, 'Kismet is reached through an HTTPS proxy.  Phones trust it when the proxy\'s ' +
                'certificate comes from an authority they already trust, such as Let\'s Encrypt, so there is nothing to ' +
                'install first.'),
            steps('iPhone and iPad', ['Open the address in Safari, then Share, Add to Home Screen.']),
            steps('Android', ['Open the address in Chrome, then the menu, Install app (or Add to Home screen).']),
        ];
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
        const https = installAddress(status);
        const out = [el('h4', {}, 'HTTPS address'), addressLink(https)];

        if (publicUrl(status)?.href !== https.href && local.includes(https.hostname))
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
            let current = null;
            const stop = pwa.onInstallChange(() => current?.fill());

            body.append(el('p', { class: 'muted' }, 'Checking this server…'));
            api.get('ssl/status.json', { noAuthEvent: true })
                .then((status) => {
                    const parts = status.https_proxy ? proxied(status) : status.enabled ? on(status) : off();
                    current = installBox(installAddress(status));
                    body.replaceChildren(current.box, ...parts);
                })
                .catch((err) => body.replaceChildren(el('p', { class: 'form-error' },
                    `Couldn't ask the server about HTTPS: ${err.message}.  It may be an older Kismet.`)));

            return stop;
        },
    });
}
