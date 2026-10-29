// The Data sources window: every source Kismet has, and the interfaces it
// could open.
//
// Each source is a card: a header that says at a glance what it's doing
// (state, channel, packet rate), and sections below it.  The sections come
// from kismet.ui.sourceSections, so a phy module adds the controls its
// drivers need beside the standard ones (js/base/sources.js), and
// kismet.ui.sourceTypes says how each kind of source and interface is
// titled and enabled.
//
// The sources are read every second and the interfaces every few seconds,
// only while the window is open and the page visible.  Cards update in place,
// so an open menu, a half-typed value, or a control being used survives the
// updates.

import { el } from '../core/dom.js';
import * as settings from '../core/settings.js';
import * as rrd from '../core/rrd.js';
import * as clock from '../core/clock.js';
import * as format from '../core/format.js';
import * as sources from '../core/sources.js';
import { icon } from '../core/icons.js';
import { sourceSections, sourceFields, sourceTypes, channelPickers, applies, typeOf, driverOf } from '../registry/sources.js';
import { detailFields } from './detailfields.js';
import { sparkline } from './sparkline.js';
import { dialog } from './dialog.js';

const sourceSeconds = 1;
const interfaceSeconds = 3;
const noUuid = '00000000-0000-0000-0000-000000000000';

const ds = 'kismet.datasource';

let openWindow = null;

export function sourceState(s) {
    if (s[`${ds}.error`])
        return 'error';
    if (!s[`${ds}.running`])
        return 'closed';
    if (s[`${ds}.paused`])
        return 'paused';
    return 'running';
}

const stateText = { running: 'Running', paused: 'Paused', closed: 'Closed', error: 'Error' };

// What the source is tuned to, in a few words
export function channelSummary(s) {
    if (!s[`${ds}.running`])
        return '';
    if (s[`${ds}.hopping`]) {
        const n = (s[`${ds}.hop_channels`] ?? []).length;
        return `Hopping ${n} channel${n === 1 ? '' : 's'}, ${sources.rateText(s[`${ds}.hop_rate`])}`;
    }
    return s[`${ds}.channel`] ? `Channel ${s[`${ds}.channel`]}` : '';
}

// A section's rows: its own, with rows other modules added slotted in by priority
function sectionFields(section) {
    const own = (section.fields ?? []).map((f, i) => ({ priority: i * 10, entry: f, order: 0 }));
    const added = sourceFields.list()
        .filter((f) => f.section === section.id)
        .map((f) => ({ priority: f.priority, entry: f, order: 1 }));
    return [...own, ...added]
        .sort((a, b) => a.priority - b.priority || a.order - b.order)
        .map((x) => x.entry);
}

// Hand controls the window's context: detailFields gives draw() the record
// last, and here that's the context instead
function withContext(entries, ctx) {
    return entries.map((e) => {
        const out = { ...e };
        if (e.draw)
            out.draw = (cell, value, rec, state) => e.draw(cell, value, rec, state, ctx);
        if (e.fields)
            out.fields = withContext(e.fields, ctx);
        return out;
    });
}

function remembered(key) {
    return settings.get(key, {});
}

function remember(key, id, on) {
    const all = { ...settings.get(key, {}) };
    if (on)
        all[id] = true;
    else
        delete all[id];
    settings.set(key, all);
}

// The cover shown over a card while a command runs
function makeCover() {
    const text = el('span');
    const node = el('div', { class: 'ds-cover', hidden: true }, el('span', { class: 'ds-spinner' }), text);
    return { node, show: (t) => { text.textContent = t; node.hidden = false; }, hide: () => { node.hidden = true; } };
}

class Card {
    constructor(win, kind, id) {
        this.win = win;
        this.kind = kind;
        this.id = id;
        this.sections = new Map();
        this.cover = makeCover();
        this.note = el('div', { class: 'ds-note', hidden: true });
        this.icon = el('span', { class: 'ds-icon' });
        this.dot = el('span', { class: 'ds-dot' });
        this.name = el('span', { class: 'ds-name' });
        this.subtitle = el('span', { class: 'ds-subtitle muted' });
        this.badges = el('span', { class: 'ds-badges' });
        this.channel = el('span', { class: 'ds-channel muted' });
        this.spark = sparkline({ className: 'ds-spark' });
        this.rate = el('span', { class: 'ds-pps muted' });
        this.body = el('div', { class: 'ds-body' });
        const summary = el('summary', { class: 'ds-summary' },
            this.dot, this.icon,
            el('span', { class: 'ds-titles' }, el('span', { class: 'ds-title-line' }, this.name, this.badges), this.subtitle),
            this.channel,
            kind === 'source' ? el('span', { class: 'ds-activity' }, this.spark.canvas, this.rate) : null);
        const openKey = kind === 'source' ? 'sources.open' : 'sources.openIntf';
        this.node = el('details', { class: ['ds-card', `ds-${kind}`], open: !!remembered(openKey)[id] },
            summary, this.note, el('div', { class: 'ds-content' }, this.body, this.cover.node));
        this.node.addEventListener('toggle', () => {
            remember(openKey, id, this.node.open);
            if (this.node.open)
                this.win.redraw(this);
        });

        this.ctx = {
            busy: (promise, text) => this.busy(promise, text),
            refresh: () => this.win.refreshSoon(),
            message: (text, kind) => this.message(text, kind),
            get sources() { return win.sources; },
            card: this,
        };
    }

    message(text, kind = '') {
        this.note.hidden = !text;
        this.note.className = ['ds-note', kind].filter(Boolean).join(' ');
        this.note.textContent = text ?? '';
    }

    async busy(promise, text) {
        this.cover.show(text);
        this.message('');
        try {
            const r = await promise;
            return r;
        } catch (err) {
            this.message(err.message, 'error');
            return null;
        } finally {
            this.cover.hide();
            this.win.refreshSoon();
        }
    }

    setBadges(list) {
        const key = list.map((b) => `${b.kind}:${b.text}`).join('|');
        if (key === this.badgeKey)
            return;
        this.badgeKey = key;
        this.badges.replaceChildren(...list.map((b) => el('span', { class: ['badge', b.kind] }, b.text)));
    }

    setIcon(name) {
        if (name === this.iconName)
            return;
        this.iconName = name;
        this.icon.replaceChildren(icon(name));
    }

    // The sections that apply, in priority order, each updated in place
    renderSections(rec, list) {
        const wanted = new Set(list.map((s) => s.id));
        for (const [id, node] of this.sections) {
            if (!wanted.has(id)) {
                node.remove();
                this.sections.delete(id);
            }
        }
        let at = this.body.firstElementChild;
        for (const s of list) {
            let section = this.sections.get(s.id);
            if (!section) {
                const fieldsEl = el('div', { class: 'detail-body' });
                const customEl = el('div', { class: 'detail-body detail-custom' });
                section = el('details', { class: 'detail-section ds-section', open: !remembered('sources.closed')[s.id] && s.open !== false,
                    dataset: { id: s.id } }, el('summary', {}, s.title), fieldsEl, customEl);
                section.addEventListener('toggle', () => remember('sources.closed', s.id, !section.open));
                section.fieldsEl = fieldsEl;
                section.customEl = customEl;
                this.sections.set(s.id, section);
            }
            if (section !== at)
                this.body.insertBefore(section, at);
            else
                at = at.nextElementSibling;

            if (!section.open)
                continue;
            try {
                const fields = sectionFields(s);
                section.fieldsEl.hidden = fields.length === 0;
                if (fields.length)
                    detailFields(section.fieldsEl, rec, withContext(fields, this.ctx));
                section.customEl.hidden = !s.render;
                if (s.render)
                    s.render(rec, section.customEl, this.ctx);
            } catch (err) {
                console.error(`data source section ${s.id} failed:`, err);
                section.customEl.hidden = false;
                section.customEl.replaceChildren(el('p', { class: 'form-error' }, `This section failed: ${err.message}`));
            }
        }
    }
}

function updateSourceCard(card, s, win) {
    const type = typeOf(s);
    const state = sourceState(s);
    card.rec = s;
    card.dot.className = `ds-dot ${state}`;
    card.dot.title = stateText[state];
    card.setIcon(type?.icon ?? 'source');
    card.name.textContent = s[`${ds}.name`] || s[`${ds}.interface`] || s[`${ds}.uuid`];

    let sub = '';
    try {
        sub = type?.subtitle?.(s, card.ctx) ?? '';
    } catch (err) {
        console.error(`source type ${type.id} failed:`, err);
    }
    if (!sub) {
        const hw = s[`${ds}.hardware`];
        sub = [s[`${ds}.interface`], hw].filter(Boolean).join(' · ');
    }
    card.subtitle.textContent = sub;

    const badges = [{ kind: 'driver', text: driverOf(s) || 'unknown' }];
    if (state === 'error')
        badges.push({ kind: 'error', text: 'Error' });
    else if (state !== 'running')
        badges.push({ kind: 'state', text: stateText[state] });
    if (s[`${ds}.remote`])
        badges.push({ kind: 'state', text: 'Remote' });
    card.setBadges(badges);
    card.channel.textContent = state === 'error' ? (s[`${ds}.error_reason`] || 'failed') : channelSummary(s);
    card.channel.classList.toggle('error-text', state === 'error');

    const now = clock.isKnown() ? clock.now() : undefined;
    const pr = s[`${ds}.packets_rrd`];
    const hist = rrd.history(pr, now);
    card.spark.draw(hist.slice(0, -1));
    card.rate.textContent = state === 'running' ? `${format.count(Math.round(rrd.recent(pr, now, 5, 'mean')))}/s` : '';

    if (!card.node.open)
        return;
    const sections = sourceSections.list().filter((sec) => applies(sec, s) &&
        (!sec.running || s[`${ds}.running`]) && (!sec.when || sec.when(s, type)));
    card.renderSections(s, sections);
}

function interfaceKey(intf) {
    return `${intf['kismet.datasource.probed.interface']}|${driverOf(intf)}`;
}

function updateInterfaceCard(card, intf) {
    const type = typeOf(intf);
    const iface = intf['kismet.datasource.probed.interface'];
    const driver = driverOf(intf);
    card.rec = intf;
    card.dot.className = 'ds-dot available';
    card.dot.title = 'Available';
    card.setIcon(type?.icon ?? 'source');
    let title = '';
    let sub = '';
    try {
        title = type?.interfaceTitle?.(intf) ?? '';
        sub = type?.interfaceSubtitle?.(intf) ?? '';
    } catch (err) {
        console.error(`source type ${type.id} failed:`, err);
    }
    card.name.textContent = title || iface;
    card.subtitle.textContent = sub || intf['kismet.datasource.probed.hardware'] || '';
    card.setBadges([{ kind: 'driver', text: driver }]);
    card.channel.textContent = '';

    if (!card.node.open)
        return;
    detailFields(card.fieldsEl ??= el('div', { class: 'detail-body' }), intf, [
        { title: 'Interface', field: 'kismet.datasource.probed.interface' },
        { title: 'Capture driver', value: () => driver },
        { title: 'Type', field: 'kismet.datasource.type_driver/kismet.datasource.driver.description', hideEmpty: true },
        { title: 'Hardware', field: 'kismet.datasource.probed.hardware', hideEmpty: true },
        { title: 'Version', field: 'kismet.datasource.probed.datasource_version', hideEmpty: true },
    ]);
    if (!card.enableEl) {
        let form = null;
        try {
            form = type?.enableForm?.(intf, card.ctx) ?? null;
        } catch (err) {
            console.error(`source type ${type.id} enable form failed:`, err);
        }
        card.enableEl = el('div', { class: 'ds-enable' }, form ?? el('button', { type: 'button', class: 'primary',
            onclick: () => card.busy(sources.add(`${iface}:type=${driver}`), 'Opening the source...') }, 'Enable source'));
        card.body.replaceChildren(card.fieldsEl, card.enableEl);
    }
}

export function openSources() {
    if (openWindow) {
        openWindow.dialog.node.dispatchEvent(new PointerEvent('pointerdown'));
        return openWindow.dialog;
    }

    const sourceList = el('div', { class: 'ds-list' });
    const intfList = el('div', { class: 'ds-list' });
    const intfStatus = el('p', { class: 'muted ds-looking' }, 'Looking for interfaces Kismet could capture from...');
    const summary = el('span', { class: 'muted' });
    const definition = el('input', { type: 'text', class: 'ds-definition', placeholder: 'interface:option=value,...', spellcheck: false });
    const addNote = el('span', { class: 'ds-add-note' });
    const addForm = el('form', { class: 'ds-add', hidden: true,
        onsubmit: async (e) => {
            e.preventDefault();
            const def = definition.value.trim();
            if (!def)
                return;
            addNote.className = 'ds-add-note muted';
            addNote.textContent = 'Opening...';
            try {
                await sources.add(def);
                addNote.textContent = '';
                definition.value = '';
                addForm.hidden = true;
                win.refreshSoon();
            } catch (err) {
                addNote.className = 'ds-add-note form-error';
                addNote.textContent = err.message;
            }
        } },
        el('label', {}, 'Source definition', definition),
        el('button', { type: 'submit', class: 'primary' }, 'Add'),
        el('button', { type: 'button', onclick: () => { addForm.hidden = true; } }, 'Cancel'),
        addNote,
        el('p', { class: 'muted ds-add-help' }, 'The same text as a source= line in kismet.conf, such as wlan0 or ' +
            'wlan0:name=outside,channel_hop=false.  A source added here lasts until Kismet restarts.'));

    const body = el('div', { class: 'datasources' },
        el('div', { class: 'ds-toolbar' }, summary,
            el('button', { type: 'button', onclick: () => { addForm.hidden = !addForm.hidden; if (!addForm.hidden) definition.focus(); } },
                icon('source'), ' Add a source...')),
        addForm,
        el('h3', { class: 'ds-heading' }, 'Data sources'), sourceList,
        el('h3', { class: 'ds-heading' }, 'Available interfaces'), intfStatus, intfList);

    const saved = settings.get('sources.position', null);
    const w = Math.min(980, Math.round(window.innerWidth * 0.9));
    const h = Math.round(window.innerHeight * 0.85);
    const d = dialog({
        title: 'Data sources',
        body,
        modal: false,
        className: 'datasources-panel',
        position: saved ?? { left: Math.round((window.innerWidth - w) / 2), top: Math.round(window.innerHeight * 0.06), width: w, height: h },
        onMove: (pos) => settings.set('sources.position', pos),
        onClose: () => {
            closed = true;
            clearTimeout(sourceTimer);
            clearTimeout(intfTimer);
            stops.forEach((s) => s());
            for (const c of [...sourceCards.values(), ...intfCards.values()])
                c.spark.destroy();
            openWindow = null;
        },
    });

    let closed = false;
    let sourceTimer = null;
    let intfTimer = null;
    let loadingSources = false;
    const sourceCards = new Map();
    const intfCards = new Map();
    let interfacesSeen = null;

    const win = {
        sources: [],
        refreshSoon() {
            clearTimeout(sourceTimer);
            sourceTimer = setTimeout(loadSources, 100);
            clearTimeout(intfTimer);
            intfTimer = setTimeout(loadInterfaces, 300);
        },
        redraw(card) {
            if (card.kind === 'source' && card.rec)
                updateSourceCard(card, card.rec, win);
            else if (card.rec)
                updateInterfaceCard(card, card.rec);
        },
    };

    function place(list, cards, order) {
        let at = list.firstElementChild;
        for (const id of order) {
            const node = cards.get(id).node;
            if (node !== at)
                list.insertBefore(node, at);
            else
                at = at.nextElementSibling;
        }
    }

    function drawSources(list) {
        win.sources = list;
        const seen = new Set();
        for (const s of list) {
            const id = s[`${ds}.uuid`];
            seen.add(id);
            let card = sourceCards.get(id);
            if (!card) {
                card = new Card(win, 'source', id);
                sourceCards.set(id, card);
            }
            updateSourceCard(card, s, win);
        }
        for (const [id, card] of sourceCards) {
            if (!seen.has(id)) {
                card.node.remove();
                card.spark.destroy();
                sourceCards.delete(id);
            }
        }
        const order = [...list].sort((a, b) => String(a[`${ds}.name`]).localeCompare(String(b[`${ds}.name`]), undefined, { numeric: true }))
            .map((s) => s[`${ds}.uuid`]);
        place(sourceList, sourceCards, order);
        if (!list.length)
            sourceList.replaceChildren(el('p', { class: 'muted' }, 'Kismet has no data sources.  Enable one of the interfaces below, or add one by its definition.'));
        else
            sourceList.querySelector(':scope > p')?.remove();

        const errors = list.filter((s) => sourceState(s) === 'error').length;
        const running = list.filter((s) => sourceState(s) === 'running').length;
        summary.textContent = `${list.length} source${list.length === 1 ? '' : 's'}, ${running} running` +
            (errors ? `, ${errors} with an error` : '');
    }

    function drawInterfaces(raw) {
        let list = raw.filter((i) => !i['kismet.datasource.probed.in_use_uuid'] || i['kismet.datasource.probed.in_use_uuid'] === noUuid);
        for (const t of sourceTypes.list()) {
            if (!t.interfaces)
                continue;
            try {
                list = t.interfaces(list, { sources: win.sources }) ?? list;
            } catch (err) {
                console.error(`source type ${t.id} interfaces failed:`, err);
            }
        }
        // An interface that's now a source belongs to that source's card
        const defined = new Set(win.sources.map((s) => `${s[`${ds}.interface`]}|${driverOf(s)}`));
        list = list.filter((i) => !defined.has(interfaceKey(i)));

        const seen = new Set();
        for (const intf of list) {
            const id = interfaceKey(intf);
            seen.add(id);
            let card = intfCards.get(id);
            if (!card) {
                card = new Card(win, 'interface', id);
                intfCards.set(id, card);
            }
            updateInterfaceCard(card, intf);
        }
        for (const [id, card] of intfCards) {
            if (!seen.has(id)) {
                card.node.remove();
                card.spark.destroy();
                intfCards.delete(id);
            }
        }
        const key = (i) => {
            const t = typeOf(i);
            try {
                return t?.sortKey?.(i) ?? i['kismet.datasource.probed.interface'];
            } catch {
                return i['kismet.datasource.probed.interface'];
            }
        };
        const order = [...list].sort((a, b) => String(key(a)).localeCompare(String(key(b)), undefined, { numeric: true }))
            .map(interfaceKey);
        place(intfList, intfCards, order);
        intfStatus.hidden = list.length > 0;
        intfStatus.textContent = 'No other interfaces found.  Kismet looks again every few seconds; ' +
            'some kinds of source (remote captures, files) are never listed and are added by their definition.';
    }

    async function loadSources() {
        if (closed || loadingSources)
            return;
        clearTimeout(sourceTimer);
        if (document.visibilityState === 'hidden') {
            sourceTimer = setTimeout(loadSources, sourceSeconds * 1000);
            return;
        }
        loadingSources = true;
        try {
            drawSources(await sources.list());
            if (interfacesSeen)
                drawInterfaces(interfacesSeen);
        } catch (err) {
            summary.textContent = `Could not read the sources: ${err.message}`;
        } finally {
            loadingSources = false;
            if (!closed)
                sourceTimer = setTimeout(loadSources, sourceSeconds * 1000);
        }
    }

    let loadingIntf = false;
    async function loadInterfaces() {
        if (closed || loadingIntf)
            return;
        clearTimeout(intfTimer);
        if (document.visibilityState === 'hidden') {
            intfTimer = setTimeout(loadInterfaces, interfaceSeconds * 1000);
            return;
        }
        loadingIntf = true;
        try {
            interfacesSeen = await sources.interfaces();
            drawInterfaces(interfacesSeen);
        } catch (err) {
            intfStatus.hidden = false;
            intfStatus.textContent = `Could not list interfaces: ${err.message}`;
        } finally {
            loadingIntf = false;
            if (!closed)
                intfTimer = setTimeout(loadInterfaces, interfaceSeconds * 1000);
        }
    }

    // Sections and types a slow module adds show up on the next draw
    const redrawAll = () => {
        for (const c of sourceCards.values())
            win.redraw(c);
        for (const c of intfCards.values()) {
            c.enableEl = null;
            win.redraw(c);
        }
    };
    const stops = [sourceSections.watch(redrawAll), sourceFields.watch(redrawAll), sourceTypes.watch(redrawAll),
        channelPickers.watch(redrawAll)];

    loadSources();
    loadInterfaces();

    openWindow = { dialog: d };
    return d;
}
