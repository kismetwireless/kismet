// The standard main menu entries and page panes.

export function register(kismet) {
    const { ui, dom, api } = kismet;
    const { el } = dom;

    ui.panes.add({
        id: 'messages', title: 'Messages', area: 'bottom', priority: 0,
        create: (body) => kismet.widgets.messages.createMessages(body),
    });

    ui.menuItems.add({
        id: 'channels', title: 'Channel coverage', icon: 'radio', priority: 10,
        onClick: () => kismet.widgets.coverage.openCoverage(),
    });

    ui.menuItems.add({
        id: 'settings', title: 'Settings', icon: 'gear', priority: 0,
        onClick: () => kismet.widgets.settingsdialog.openSettings(),
    });

    ui.menuItems.add({
        id: 'about', title: 'About', icon: 'info', priority: 1000,
        async onClick() {
            const body = el('div', { class: 'about' }, el('p', {}, 'Loading...'));
            kismet.widgets.dialog.dialog({ title: 'About Kismet', body });
            try {
                const s = await api.get('system/status.json');
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
