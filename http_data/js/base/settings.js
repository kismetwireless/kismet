// The standard settings sections: appearance, units and the ribbon.  Device list
// columns and row highlights are edited on the list itself.

export function register(kismet) {
    const { ui, settings, theme, dom } = kismet;
    const { el } = dom;
    const { isVisible } = kismet.widgets.ribbon;

    function choice(name, options, current, onPick) {
        return el('div', { class: 'choice', role: 'radiogroup' },
            options.map((o) => el('label', { class: 'choice-item' },
                el('input', { type: 'radio', name, value: o.id, checked: o.id === current,
                    onchange: () => onPick(o.id) }),
                o.swatch ?? null,
                o.title)));
    }

    ui.settingsPanes.add({
        id: 'appearance', title: 'Appearance', priority: 0,
        create(body) {
            // A small picture of a scheme: its background, a panel, the accent, and text
            const preview = ([bg, panel, accent, text]) => el('span', { class: 'scheme-preview', style: { background: bg } },
                el('span', { class: 'scheme-preview-panel', style: { background: panel } },
                    el('span', { class: 'scheme-preview-line', style: { background: text } }),
                    el('span', { class: 'scheme-preview-line short', style: { background: text } })),
                el('span', { class: 'scheme-preview-accent', style: { background: accent } }));

            const schemes = el('div', { class: 'scheme-grid', role: 'radiogroup' },
                theme.schemes().map((sc) => el('label', { class: 'scheme-item' },
                    el('input', { type: 'radio', name: 'scheme', value: sc.id, checked: sc.id === theme.scheme().id,
                        onchange: () => { theme.setScheme(sc.id); update(); } }),
                    preview(sc.preview),
                    el('span', { class: 'scheme-name' }, sc.title,
                        sc.variants.length === 1 ? el('span', { class: 'muted' }, ` (${sc.variants[0]} only)`) : null))));

            const modeNote = el('p', { class: 'muted' });
            const modes = choice('mode', [
                { id: 'auto', title: 'Match the system' },
                { id: 'light', title: 'Light' },
                { id: 'dark', title: 'Dark' },
            ], theme.mode(), theme.setMode);

            const accentTitle = el('h4', {}, 'Accent color');
            const accents = choice('palette', theme.palettes.map((p) => ({
                ...p,
                swatch: el('span', { class: 'swatch', dataset: { palette: p.id } }),
            })), theme.palette(), theme.setPalette);

            // Light/dark only means something for schemes with both; accent
            // colors are the Kismet scheme's own
            function update() {
                const sc = theme.scheme();
                const single = sc.variants.length === 1;
                modes.classList.toggle('disabled', single);
                modes.querySelectorAll('input').forEach((i) => { i.disabled = single; });
                modeNote.textContent = single ? `${sc.title} only comes in ${sc.variants[0]}.` : '';
                modeNote.hidden = !single;
                accentTitle.hidden = accents.hidden = sc.id !== 'kismet';
            }

            body.append(
                el('h4', {}, 'Color scheme'),
                schemes,
                el('h4', {}, 'Light or dark'),
                modes,
                modeNote,
                accentTitle,
                accents);
            update();
        },
    });

    ui.settingsPanes.add({
        id: 'units', title: 'Units', priority: 20,
        create(body) {
            body.append(
                el('h4', {}, 'Speed'),
                choice('units-speed', kismet.format.speedUnits, kismet.format.speedUnits.find((u) =>
                    u.id === settings.get('units.speed'))?.id ?? 'kmh', (id) => settings.set('units.speed', id)),
                el('h4', {}, 'Distance and height'),
                choice('units-length', kismet.format.lengthUnits, kismet.format.lengthUnits.find((u) =>
                    u.id === settings.get('units.length'))?.id ?? 'metric', (id) => settings.set('units.length', id)),
                el('p', { class: 'muted' }, 'Distances change to kilometers or miles as they get longer; ' +
                    'altitudes stay in meters or feet.'));
        },
    });

    ui.settingsPanes.add({
        id: 'ribbon', title: 'Ribbon', priority: 30,
        create(body) {
            body.append(el('p', { class: 'muted' }, 'Choose the stats shown along the top.'));
            for (const stat of ui.ribbonStats.list()) {
                body.append(el('label', { class: 'check-item' },
                    el('input', { type: 'checkbox', checked: isVisible(stat), onchange: (e) => {
                        settings.set('ribbon.visible', { ...settings.get('ribbon.visible', {}), [stat.id]: e.target.checked });
                    } }),
                    stat.title,
                    stat.description ? el('span', { class: 'muted' }, ` - ${stat.description}`) : null));
            }
        },
    });
}
