// Peaks in a gamma spectrum and the common gamma lines near them, as hints to
// what a source might be.  Never an identification: a scintillator's peaks are
// wide, isotopes have lines close together, and Compton edges and backscatter
// make bumps of their own.
//
// findPeaks(counts, calibration, { resolution }) -> peaks, strongest first:
//   { channel, energy, fwhm, net, significance, lines: [line, ...] }
//   lines are the isotopeLines within half a peak width, nearest first
// isotopeHints(peaks) -> [{ isotope, series, natural, note, lines: [keV, ...],
//   significance }], the isotopes with a main line nearest a peak, strongest first

// Gamma lines in keV.  main: a line the isotope is usually seen by; series:
// the decay series a natural line belongs to.
export const isotopeLines = [
    { at: 59.5, isotope: 'Am-241', main: true, note: 'smoke detectors' },
    { at: 81.0, isotope: 'Ba-133' },
    { at: 140.5, isotope: 'Tc-99m', main: true, note: 'medical imaging' },
    { at: 185.7, isotope: 'U-235', main: true },
    { at: 186.2, isotope: 'Ra-226', series: 'U-238', natural: true },
    { at: 238.6, isotope: 'Pb-212', series: 'Th-232', natural: true, main: true },
    { at: 295.2, isotope: 'Pb-214', series: 'U-238', natural: true },
    { at: 351.9, isotope: 'Pb-214', series: 'U-238', natural: true, main: true },
    { at: 356.0, isotope: 'Ba-133', main: true },
    { at: 364.5, isotope: 'I-131', main: true, note: 'medical treatment' },
    { at: 511.0, isotope: 'Annihilation', main: true, note: 'positron emitters such as F-18 and Na-22, or cosmic rays' },
    { at: 583.2, isotope: 'Tl-208', series: 'Th-232', natural: true },
    { at: 609.3, isotope: 'Bi-214', series: 'U-238', natural: true, main: true },
    { at: 661.7, isotope: 'Cs-137', main: true },
    { at: 911.2, isotope: 'Ac-228', series: 'Th-232', natural: true, main: true },
    { at: 1120.3, isotope: 'Bi-214', series: 'U-238', natural: true },
    { at: 1173.2, isotope: 'Co-60', main: true },
    { at: 1274.5, isotope: 'Na-22', main: true },
    { at: 1332.5, isotope: 'Co-60', main: true },
    { at: 1460.8, isotope: 'K-40', natural: true, main: true },
    { at: 1764.5, isotope: 'Bi-214', series: 'U-238', natural: true },
    { at: 2614.5, isotope: 'Tl-208', series: 'Th-232', natural: true, main: true },
];

// Peak width (FWHM) as a fraction of the energy at 662 keV; about right for the
// CsI and GAGG crystals in pocket detectors
const defaultResolution = 0.09;
const minEnergy = 40;
const minSignificance = 5;
// The shape test only weeds out bumps that aren't peak shaped; the net counts
// test above decides whether a peak is real
const minCurvature = 3;
const minNet = 30;
const maxPeaks = 12;

// Peak width in keV at an energy, growing with its square root
const fwhmAt = (e, res) => res * Math.sqrt(661.7 * Math.max(e, 1));

// Background under the peaks by SNIP (Morhac): each channel is clipped to the
// mean of its neighbours a window away, on a log-log-sqrt scale, with the
// window shrinking from about a peak width to 1
function snip(counts, widths) {
    const n = counts.length;
    const lls = (v) => Math.log(Math.log(Math.sqrt(v + 1) + 1) + 1);
    const unlls = (v) => (Math.exp(Math.exp(v) - 1) - 1) ** 2 - 1;
    let v = counts.map((c) => lls(Math.max(c, 0)));
    const maxW = Math.max(1, ...widths);
    for (let p = maxW; p >= 1; p--) {
        const next = v.slice();
        for (let i = 0; i < n; i++) {
            const w = Math.min(p, widths[i]);
            if (w < 1 || i - w < 0 || i + w >= n)
                continue;
            const m = (v[i - w] + v[i + w]) / 2;
            if (m < next[i])
                next[i] = m;
        }
        v = next;
    }
    return v.map((x) => Math.max(0, unlls(x)));
}

export function findPeaks(counts, calibration, { resolution = defaultResolution } = {}) {
    if (!Array.isArray(counts) || counts.length < 16 || !Array.isArray(calibration) ||
            calibration.length !== 3 || !calibration.every(Number.isFinite))
        return [];
    const [a0, a1, a2] = calibration;
    if (!(a1 > 0) || a2 < 0 || !(resolution > 0))
        return [];

    const n = counts.length;
    const c = counts.map((x) => (Number.isFinite(x) && x > 0 ? x : 0));
    const energy = (ch) => a0 + a1 * ch + a2 * ch * ch;
    const keVper = (ch) => a1 + 2 * a2 * ch;
    // Peak width in channels at each channel
    const widthCh = c.map((_, i) => fwhmAt(Math.max(energy(i), minEnergy), resolution) / keVper(i));

    // Smoothed over about a third of a peak width, so noise in single channels
    // neither makes maxima nor drags the clipped background down
    const smoothN = new Array(n);
    const smooth = c.map((_, i) => {
        const h = Math.max(1, Math.round(widthCh[i] / 6));
        let s = 0;
        let k = 0;
        for (let j = Math.max(0, i - h); j <= Math.min(n - 1, i + h); j++, k++)
            s += c[j];
        smoothN[i] = k;
        return s / k;
    });
    const bg = snip(smooth, widthCh.map((w) => Math.max(1, Math.round(w))));
    const net = smooth.map((v, i) => v - bg[i]);

    const peaks = [];
    for (let i = 1; i < n - 1; i++) {
        const e = energy(i);
        if (e < minEnergy || net[i] <= 0 || net[i] < net[i - 1] || net[i] < net[i + 1])
            continue;
        const hw = Math.max(1, Math.round(widthCh[i] / 2));
        if (i - hw < 0 || i + hw >= n)
            continue;
        // A peak bends down half a width either side (a Gaussian is at half
        // height there); a sloping or curving background mostly doesn't
        const d2 = smooth[i - hw] - 2 * smooth[i] + smooth[i + hw];
        const d2Err = Math.sqrt((smooth[i - hw] / smoothN[i - hw]) + 4 * (smooth[i] / smoothN[i]) +
            (smooth[i + hw] / smoothN[i + hw]));
        if (!(d2Err > 0) || -d2 / d2Err < minCurvature)
            continue;
        let netSum = 0;
        let bgSum = 0;
        let eSum = 0;
        let chSum = 0;
        for (let j = Math.max(0, i - hw); j <= Math.min(n - 1, i + hw); j++) {
            const nv = c[j] - bg[j];
            netSum += nv;
            bgSum += bg[j];
            if (nv > 0) {
                eSum += nv * energy(j);
                chSum += nv;
            }
        }
        if (netSum < minNet || chSum <= 0)
            continue;
        // Net counts against the uncertainty of the counts and the background under them
        const significance = netSum / Math.sqrt(netSum + 2 * bgSum);
        if (significance < minSignificance)
            continue;
        const centroid = eSum / chSum;
        peaks.push({ channel: i, energy: centroid, fwhm: fwhmAt(centroid, resolution), net: netSum, significance });
    }

    // One peak per peak width, keeping the strongest
    peaks.sort((x, y) => y.significance - x.significance);
    const kept = [];
    for (const p of peaks) {
        if (!kept.some((k) => Math.abs(k.energy - p.energy) < Math.max(k.fwhm, p.fwhm) / 2))
            kept.push(p);
        if (kept.length >= maxPeaks)
            break;
    }

    for (const p of kept) {
        p.lines = isotopeLines.filter((l) => Math.abs(l.at - p.energy) <= fwhmAt(l.at, resolution) / 2)
            .sort((x, y) => Math.abs(x.at - p.energy) - Math.abs(y.at - p.energy));
    }
    return kept;
}

export function isotopeHints(peaks) {
    const byIsotope = new Map();
    for (const p of peaks ?? []) {
        // Only the nearest line; the others stay in the peak's own list
        for (const l of (p.lines ?? []).slice(0, 1)) {
            let h = byIsotope.get(l.isotope);
            if (!h) {
                h = { isotope: l.isotope, series: l.series ?? null, natural: !!l.natural, note: l.note ?? null,
                    lines: [], main: false, significance: 0 };
                byIsotope.set(l.isotope, h);
            }
            if (!h.lines.includes(l.at))
                h.lines.push(l.at);
            h.main ||= !!l.main;
            h.significance = Math.max(h.significance, p.significance);
        }
    }
    return [...byIsotope.values()].filter((h) => h.main)
        .map(({ main, ...h }) => ({ ...h, lines: h.lines.sort((x, y) => x - y) }))
        .sort((x, y) => y.significance - x.significance);
}
