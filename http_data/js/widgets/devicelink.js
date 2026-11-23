// Links from the device panel to other devices: the address with a link
// icon, opening that device's own panel.
//
//   kismet.ui.deviceLink(key, text, { title })   a link to the device with this key
//   kismet.ui.macLink(mac, { phy })              a link to the device with this MAC
//                                                address, found when clicked; a record
//                                                of phy first, if there is one
//   kismet.ui.recordLink({ title })              a detailFields draw() for a row whose
//                                                value is a device key: a link showing
//                                                the record's MAC address
//   kismet.ui.macDevices(mac)                    the devices with this MAC address,
//                                                [{ phy, key }], or undefined until asked
//   kismet.ui.findMac(mac, { again })            ask the server for them; a promise of the
//                                                same list.  Kept for the page; again asks
//                                                once more when none were found.
//
// Only well-formed MAC addresses are looked up; the server doesn't decode the
// path, so nothing else may end up in it.

import { el } from '../core/dom.js';
import * as api from '../core/api.js';
import { icon } from '../core/icons.js';
import { openDevice } from './detailpanel.js';

const base = 'kismet.device.base';
const macPattern = /^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$/;
const keep = 1024;

const found = new Map();        // MAC -> [{ phy, key }]
const asking = new Map();       // MAC -> promise of the same

export const macDevices = (mac) => found.get(mac);

export function findMac(mac, { again = false } = {}) {
    if (typeof mac !== 'string' || !macPattern.test(mac))
        return Promise.resolve([]);
    const have = found.get(mac);
    if (have && !(again && have.length === 0))
        return Promise.resolve(have);
    if (asking.has(mac))
        return asking.get(mac);
    const p = api.post(`devices/by-mac/${mac}/devices.json`, { fields: [`${base}.key`, `${base}.phyname`] })
        .then((devs) => (Array.isArray(devs) ? devs : [])
            .filter((d) => typeof d?.[`${base}.key`] === 'string' && d[`${base}.key`] !== '')
            .map((d) => ({ phy: d[`${base}.phyname`], key: d[`${base}.key`] })))
        .catch(() => [])
        .then((list) => {
            asking.delete(mac);
            found.delete(mac);
            found.set(mac, list);
            while (found.size > keep)
                found.delete(found.keys().next().value);
            return list;
        });
    asking.set(mac, p);
    return p;
}

export const deviceLink = (key, text, { title = 'Open this device' } = {}) =>
    el('a', { href: '#', class: 'mono', title, onclick: (e) => {
        e.preventDefault();
        openDevice(key);
    } }, text, ' ', icon('chain'));

export function macLink(mac, { phy = null } = {}) {
    if (typeof mac !== 'string' || !macPattern.test(mac))
        return el('span', { class: 'mono' }, mac ?? '');
    const a = el('a', { href: '#', class: 'mono', title: 'Open this device', onclick: async (ev) => {
        ev.preventDefault();
        const list = await findMac(mac, { again: true });
        const key = (list.find((d) => d.phy === phy) ?? list[0])?.key;
        if (key) {
            openDevice(key);
        } else {
            a.title = 'Kismet doesn\'t track a device with this MAC address';
            a.classList.add('muted');
        }
    } }, mac, ' ', icon('chain'));
    return a;
}

export const recordLink = ({ title = 'Open this device' } = {}) => (cell, key, rec, state) => {
    const mac = rec?.[`${base}.macaddr`];
    const k = JSON.stringify([key ?? null, mac ?? null]);
    if (state.link === k && cell.childNodes.length)
        return undefined;
    state.link = k;
    cell.replaceChildren(typeof key === 'string' && key !== '' ? deviceLink(key, mac ?? key, { title }) : '');
    return undefined;
};
