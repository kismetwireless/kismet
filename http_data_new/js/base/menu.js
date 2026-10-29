// The standard main menu entries and page panes.

export function register(kismet) {
    const { ui, dom, api } = kismet;
    const { el } = dom;

    ui.panes.add({
        id: 'messages', title: 'Messages', area: 'bottom', priority: 0,
        create: (body) => kismet.widgets.messages.createMessages(body),
    });

    ui.menuItems.add({
        id: 'channels', title: 'Channel coverage', icon: 'radio',
        onClick: () => kismet.widgets.coverage.openCoverage(),
    });

    ui.menuItems.add({
        id: 'gps', title: 'GPS', icon: 'gps',
        onClick: () => kismet.widgets.gps.openGps(),
    });

    // Switching servers is for the installed app, or to get back from another server
    if (kismet.servers.installed() || kismet.servers.current() || kismet.servers.list().length)
        ui.menuItems.add({
            id: 'servers', title: 'Servers', icon: 'server', priority: 10, section: 'settings',
            onClick: () => kismet.widgets.serversdialog.openServers(),
        });

    ui.menuItems.add({
        id: 'settings', title: 'Settings', icon: 'gear', priority: 0, section: 'settings',
        onClick: () => kismet.widgets.settingsdialog.openSettings(),
    });

    ui.menuItems.add({
        id: 'about', title: 'About', icon: 'info', priority: 0, section: 'about',
        async onClick() {
            const body = el('div', { class: 'about' }, el('p', {}, 'Loading...'));
            kismet.widgets.dialog.dialog({ title: 'About Kismet', body });
            try {
                const [s, dyn] = await Promise.all([api.get('system/status.json'), api.get('dynamic.json').catch(() => null)]);
                ui.detailFields(body, s, [
                    { title: 'Server', field: 'kismet.system.server_name' },
                    { title: 'Description', field: 'kismet.system.server_description' },
                    { title: 'Location', field: 'kismet.system.server_location' },
                    { title: 'Version', field: 'kismet.system.version' },
                    { title: 'Git', field: 'kismet.system.git' },
                    { title: 'Built', field: 'kismet.system.build_time' },
                    { title: 'Running as', field: 'kismet.system.user' },
                    { title: 'Up since', field: 'kismet.system.timestamp.start_sec',
                        format: kismet.format.time },
                    { title: 'UI build', value: () => kismet.modules.build ?? 'unknown' },
                    { title: 'Server UI build', value: () => dyn?.build ?? 'unknown', show: (v) => v !== kismet.modules.build },
                    { title: 'UI modules', value: () => kismet.modules.loaded.join(', ') || 'none' },
                    { title: 'Not available in this UI yet', value: () => kismet.modules.skipped.map((m) => m.name).join(', '),
                        show: (v) => v !== '' },
                ]);
            } catch (err) {
                body.replaceChildren(el('p', { class: 'form-error' }, err.message));
            }
        },
    });
}
