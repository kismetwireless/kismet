// A gamma spectrum window from the radiation spectrum endpoint as a file:
// CSV (channel, energy, counts), or ANSI N42.42-2012 XML, which spectrum tools
// such as InterSpec and BecqMoni open.
//
// spectrumCsv(win) -> text
// spectrumN42(win, { name, type, window }) -> text, or null unless n42Ready(win)
//   name: the sensor's data source name, type: its detector type
// n42Ready(win): N42 needs an energy calibration, counts, and a counting time

const sp = 'radiation.spectrum';

function calibrationOf(win) {
    const c = win?.[`${sp}.calibration`];
    return Array.isArray(c) && c.length === 3 && c.every(Number.isFinite) ? c : null;
}

const countsOf = (win) => (win?.[`${sp}.counts`] ?? []).map((v) => (Number.isFinite(v) && v > 0 ? Math.round(v) : 0));

export const n42Ready = (win) => !!calibrationOf(win) && countsOf(win).length > 0 &&
    Number.isFinite(win?.[`${sp}.duration`]) && win[`${sp}.duration`] > 0;

export function spectrumCsv(win) {
    const cal = calibrationOf(win);
    const rows = ['channel,energy_kev,counts'];
    countsOf(win).forEach((v, ch) => {
        const e = cal ? (cal[0] + cal[1] * ch + cal[2] * ch * ch).toFixed(3) : '';
        rows.push(`${ch},${e},${v}`);
    });
    return rows.join('\r\n') + '\r\n';
}

// Text for XML, cut to 256 characters: characters XML 1.0 can't hold
// (controls, lone surrogates) are dropped and markup escaped
function xmlText(s) {
    return Array.from(String(s ?? '')).slice(0, 256).join('')
        .replace(/[^\x09\x0A\x0D\x20-퟿-�\u{10000}-\u{10FFFF}]/gu, '')
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;').replace(/'/g, '&apos;');
}

const isoTime = (t) => new Date((Number.isFinite(t) && t > 0 ? t : 0) * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');
const isoDuration = (s) => `PT${(Number.isFinite(s) && s > 0 ? s : 0).toFixed(3)}S`;

export function spectrumN42(win, { name = '', type = '', window = '' } = {}) {
    const cal = calibrationOf(win);
    const dur = win?.[`${sp}.duration`];
    if (!n42Ready(win))
        return null;
    // The schema allows no markup or inner spaces here
    const model = String(type ?? '').replace(/[^A-Za-z0-9._-]/g, '').slice(0, 64) || 'Unknown';
    const desc = [name, window ? `${window} spectrum` : ''].filter(Boolean).join(', ');
    const lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<RadInstrumentData xmlns="http://physics.nist.gov/N42/2011/N42">',
        '  <RadInstrumentDataCreatorName>Kismet</RadInstrumentDataCreatorName>',
        '  <RadInstrumentInformation id="RadInstrumentInformation-1">',
        `    <RadInstrumentManufacturerName>${model}</RadInstrumentManufacturerName>`,
        `    <RadInstrumentModelName>${model}</RadInstrumentModelName>`,
        desc ? `    <RadInstrumentDescription>${xmlText(desc)}</RadInstrumentDescription>` : null,
        '    <RadInstrumentClassCode>Spectroscopic Personal Radiation Detector</RadInstrumentClassCode>',
        '    <RadInstrumentVersion>',
        '      <RadInstrumentComponentName>Software</RadInstrumentComponentName>',
        '      <RadInstrumentComponentVersion>Kismet</RadInstrumentComponentVersion>',
        '    </RadInstrumentVersion>',
        '  </RadInstrumentInformation>',
        '  <RadDetectorInformation id="RadDetectorInformation-1">',
        '    <RadDetectorCategoryCode>Gamma</RadDetectorCategoryCode>',
        '    <RadDetectorKindCode>Other</RadDetectorKindCode>',
        '  </RadDetectorInformation>',
        '  <EnergyCalibration id="EnergyCalibration-1">',
        `    <CoefficientValues>${cal.map((v) => String(v)).join(' ')}</CoefficientValues>`,
        '  </EnergyCalibration>',
        '  <RadMeasurement id="RadMeasurement-1">',
        '    <MeasurementClassCode>Foreground</MeasurementClassCode>',
        `    <StartDateTime>${isoTime(win?.[`${sp}.start_time`])}</StartDateTime>`,
        `    <RealTimeDuration>${isoDuration(dur)}</RealTimeDuration>`,
        '    <Spectrum id="Spectrum-1" radDetectorInformationReference="RadDetectorInformation-1" ' +
            'energyCalibrationReference="EnergyCalibration-1">',
        `      <LiveTimeDuration>${isoDuration(dur)}</LiveTimeDuration>`,
        `      <ChannelData compressionCode="None">${countsOf(win).join(' ')}</ChannelData>`,
        '    </Spectrum>',
        '  </RadMeasurement>',
        '</RadInstrumentData>',
    ];
    return lines.filter((l) => l !== null).join('\n') + '\n';
}
