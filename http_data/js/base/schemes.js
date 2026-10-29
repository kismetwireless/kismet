// The built-in color schemes, after popular VS Code themes (from
// vscodethemes.com).  The default, Kismet, is in css/themes.css with its
// accent palettes; these are registered the same way a plugin's would be.
//
// Each scheme gives the colors for a dark version, a light version, or both;
// see kismet.ui.colorSchemes in js/registry/ui.js for the names.

export function register(kismet) {
    const { ui } = kismet;

    ui.colorSchemes.add({
        id: 'github', title: 'GitHub', priority: 10,
        dark: {
            bg: '#0d1117', surface: '#161b22', 'surface-2': '#21262d', border: '#30363d',
            text: '#e6edf3', muted: '#8b949e', accent: '#2f81f7', 'accent-text': '#ffffff',
            ok: '#3fb950', warn: '#d29922', error: '#f85149',
            shadow: '0 4px 16px rgb(1 4 9 / 0.6)', 'highlight-mix': '30%',
        },
        light: {
            bg: '#f6f8fa', surface: '#ffffff', 'surface-2': '#eaeef2', border: '#d0d7de',
            text: '#1f2328', muted: '#656d76', accent: '#0969da', 'accent-text': '#ffffff',
            ok: '#1a7f37', warn: '#9a6700', error: '#cf222e',
            shadow: '0 4px 16px rgb(140 149 159 / 0.3)', 'highlight-mix': '35%',
        },
    });

    ui.colorSchemes.add({
        id: 'onedarkpro', title: 'One Dark Pro', priority: 20,
        dark: {
            bg: '#21252b', surface: '#282c34', 'surface-2': '#2c313a', border: '#3e4451',
            text: '#abb2bf', muted: '#7f848e', accent: '#61afef', 'accent-text': '#1e2227',
            ok: '#98c379', warn: '#e5c07b', error: '#e06c75',
            shadow: '0 4px 16px rgb(0 0 0 / 0.5)', 'highlight-mix': '30%',
        },
    });

    ui.colorSchemes.add({
        id: 'dracula', title: 'Dracula', priority: 30,
        dark: {
            bg: '#21222c', surface: '#282a36', 'surface-2': '#343746', border: '#44475a',
            text: '#f8f8f2', muted: '#8b93c0', accent: '#bd93f9', 'accent-text': '#21222c',
            ok: '#50fa7b', warn: '#f1fa8c', error: '#ff5555',
            shadow: '0 4px 16px rgb(0 0 0 / 0.55)', 'highlight-mix': '30%',
        },
    });

    ui.colorSchemes.add({
        id: 'atomonedark', title: 'Atom One Dark', priority: 40,
        dark: {
            bg: '#1e2127', surface: '#24282f', 'surface-2': '#2c313c', border: '#3b4048',
            text: '#c8ccd4', muted: '#828997', accent: '#528bff', 'accent-text': '#ffffff',
            ok: '#98c379', warn: '#d19a66', error: '#e06c75',
            shadow: '0 4px 16px rgb(0 0 0 / 0.5)', 'highlight-mix': '30%',
        },
    });

    ui.colorSchemes.add({
        id: 'material', title: 'Material', priority: 50,
        dark: {
            bg: '#1e272c', surface: '#263238', 'surface-2': '#2e3c43', border: '#37474f',
            text: '#eeffff', muted: '#90a4ae', accent: '#80cbc4', 'accent-text': '#1e272c',
            ok: '#c3e88d', warn: '#ffcb6b', error: '#f07178',
            shadow: '0 4px 16px rgb(0 0 0 / 0.5)', 'highlight-mix': '30%',
        },
        light: {
            bg: '#f5f5f5', surface: '#ffffff', 'surface-2': '#eceff1', border: '#d3e1e8',
            text: '#546e7a', muted: '#90a4ae', accent: '#39adb5', 'accent-text': '#ffffff',
            ok: '#91b859', warn: '#e2931d', error: '#e53935',
            shadow: '0 4px 16px rgb(0 0 0 / 0.12)', 'highlight-mix': '35%',
        },
    });

    ui.colorSchemes.add({
        id: 'ayu', title: 'Ayu', priority: 60,
        dark: {
            bg: '#0b0e14', surface: '#0d1017', 'surface-2': '#131721', border: '#1e232b',
            text: '#bfbdb6', muted: '#6c7380', accent: '#e6b450', 'accent-text': '#0b0e14',
            ok: '#7fd962', warn: '#ffb454', error: '#d95757',
            shadow: '0 4px 16px rgb(0 0 0 / 0.6)', 'highlight-mix': '30%',
        },
        light: {
            bg: '#f3f4f5', surface: '#fcfcfc', 'surface-2': '#eef0f2', border: '#e1e4e8',
            text: '#5c6166', muted: '#8a9199', accent: '#fa8d3e', 'accent-text': '#ffffff',
            ok: '#6cbf43', warn: '#e59645', error: '#e65050',
            shadow: '0 4px 16px rgb(0 0 0 / 0.1)', 'highlight-mix': '35%',
        },
    });

    ui.colorSchemes.add({
        id: 'monokaipro', title: 'Monokai Pro', priority: 70,
        dark: {
            bg: '#19181a', surface: '#2d2a2e', 'surface-2': '#403e41', border: '#5b595c',
            text: '#fcfcfa', muted: '#939293', accent: '#ffd866', 'accent-text': '#19181a',
            ok: '#a9dc76', warn: '#fc9867', error: '#ff6188',
            shadow: '0 4px 16px rgb(0 0 0 / 0.55)', 'highlight-mix': '30%',
        },
    });

    ui.colorSchemes.add({
        id: 'winteriscoming', title: 'Winter is Coming', priority: 80,
        dark: {
            bg: '#011221', surface: '#011627', 'surface-2': '#0b253a', border: '#1e3a52',
            text: '#d6deeb', muted: '#8aa8c2', accent: '#219fd5', 'accent-text': '#011221',
            ok: '#8dec95', warn: '#ffca28', error: '#ef5350',
            shadow: '0 4px 16px rgb(0 0 0 / 0.55)', 'highlight-mix': '30%',
        },
        light: {
            bg: '#eef2f6', surface: '#ffffff', 'surface-2': '#e8eef4', border: '#cfdae5',
            text: '#1c3249', muted: '#6b8299', accent: '#2d6ebf', 'accent-text': '#ffffff',
            ok: '#2e8b57', warn: '#b8860b', error: '#d32f2f',
            shadow: '0 4px 16px rgb(28 50 73 / 0.14)', 'highlight-mix': '35%',
        },
    });

    ui.colorSchemes.add({
        id: 'nightowl', title: 'Night Owl', priority: 90,
        dark: {
            bg: '#010e1a', surface: '#011627', 'surface-2': '#0b2942', border: '#1d3b53',
            text: '#d6deeb', muted: '#7e97ac', accent: '#82aaff', 'accent-text': '#011627',
            ok: '#addb67', warn: '#ecc48d', error: '#ef5350',
            shadow: '0 4px 16px rgb(0 0 0 / 0.55)', 'highlight-mix': '30%',
        },
        light: {
            bg: '#f0f0f0', surface: '#fbfbfb', 'surface-2': '#f0f4f6', border: '#e0e7ea',
            text: '#403f53', muted: '#7d8a95', accent: '#4876d6', 'accent-text': '#ffffff',
            ok: '#08916a', warn: '#c96765', error: '#de3d3b',
            shadow: '0 4px 16px rgb(0 0 0 / 0.1)', 'highlight-mix': '35%',
        },
    });

    ui.colorSchemes.add({
        id: 'tokyonight', title: 'Tokyo Night', priority: 100,
        dark: {
            bg: '#16161e', surface: '#1a1b26', 'surface-2': '#24283b', border: '#292e42',
            text: '#c0caf5', muted: '#737aa2', accent: '#7aa2f7', 'accent-text': '#16161e',
            ok: '#9ece6a', warn: '#e0af68', error: '#f7768e',
            shadow: '0 4px 16px rgb(0 0 0 / 0.55)', 'highlight-mix': '30%',
        },
        light: {
            bg: '#d5d6db', surface: '#e6e7ed', 'surface-2': '#dcdee3', border: '#c1c2c7',
            text: '#343b58', muted: '#6c6e75', accent: '#34548a', 'accent-text': '#ffffff',
            ok: '#485e30', warn: '#8f5e15', error: '#8c4351',
            shadow: '0 4px 16px rgb(0 0 0 / 0.14)', 'highlight-mix': '35%',
        },
    });

    ui.colorSchemes.add({
        id: 'onemonokai', title: 'One Monokai', priority: 110,
        dark: {
            bg: '#1d2026', surface: '#282c34', 'surface-2': '#30343c', border: '#3e4451',
            text: '#d4d7dd', muted: '#8a919c', accent: '#98c379', 'accent-text': '#1d2026',
            ok: '#98c379', warn: '#e5c07b', error: '#f92672',
            shadow: '0 4px 16px rgb(0 0 0 / 0.5)', 'highlight-mix': '30%',
        },
    });

    ui.colorSchemes.add({
        id: 'palenight', title: 'Palenight', priority: 120,
        dark: {
            bg: '#232635', surface: '#292d3e', 'surface-2': '#32374d', border: '#3a3f58',
            text: '#a6accd', muted: '#8087a8', accent: '#c792ea', 'accent-text': '#232635',
            ok: '#c3e88d', warn: '#ffcb6b', error: '#ff5370',
            shadow: '0 4px 16px rgb(0 0 0 / 0.5)', 'highlight-mix': '30%',
        },
    });

    ui.colorSchemes.add({
        id: 'synthwave84', title: "SynthWave '84", priority: 130,
        dark: {
            bg: '#1e1a2b', surface: '#262335', 'surface-2': '#34294f', border: '#495495',
            text: '#f0eff1', muted: '#9a9fd0', accent: '#ff7edb', 'accent-text': '#1e1a2b',
            ok: '#72f1b8', warn: '#fede5d', error: '#fe4450',
            shadow: '0 4px 18px rgb(255 126 219 / 0.12)', 'highlight-mix': '30%',
        },
    });

    ui.colorSchemes.add({
        id: 'shadesofpurple', title: 'Shades of Purple', priority: 140,
        dark: {
            bg: '#1e1e3f', surface: '#2d2b55', 'surface-2': '#3b3870', border: '#4d4b8a',
            text: '#ffffff', muted: '#a599e9', accent: '#fad000', 'accent-text': '#1e1e3f',
            ok: '#3ad900', warn: '#ff9d00', error: '#ec3a37',
            shadow: '0 4px 16px rgb(0 0 0 / 0.5)', 'highlight-mix': '30%',
        },
    });

    ui.colorSchemes.add({
        id: 'cobalt2', title: 'Cobalt2', priority: 150,
        dark: {
            bg: '#15232d', surface: '#193549', 'surface-2': '#1f4662', border: '#234e6d',
            text: '#ffffff', muted: '#9aaec0', accent: '#ffc600', 'accent-text': '#15232d',
            ok: '#3ad900', warn: '#ff9d00', error: '#ff628c',
            shadow: '0 4px 16px rgb(0 0 0 / 0.5)', 'highlight-mix': '30%',
        },
    });
}
