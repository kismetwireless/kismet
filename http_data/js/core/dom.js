// Small helpers for building the page out of plain DOM elements.
//
//   el('div', { class: 'card', onclick: () => ... }, 'Hello ', el('b', {}, name))
//
// Strings become text, never HTML, so data from the server can't inject markup.
// Use html`...` (below) only for trusted, fixed markup such as icons.

export function el(tag, props = {}, ...children) {
    const node = document.createElement(tag);

    for (const [key, value] of Object.entries(props ?? {})) {
        if (value === undefined || value === null || value === false)
            continue;

        if (key === 'class')
            node.className = Array.isArray(value) ? value.filter(Boolean).join(' ') : value;
        else if (key === 'style' && typeof value === 'object')
            Object.assign(node.style, value);
        else if (key === 'dataset')
            Object.assign(node.dataset, value);
        else if (key.startsWith('on') && typeof value === 'function')
            node.addEventListener(key.slice(2), value);
        else if (key in node && typeof value !== 'string')
            node[key] = value;
        else
            node.setAttribute(key, value === true ? '' : value);
    }

    append(node, ...children);
    return node;
}

// Append children: nodes, strings/numbers (as text), arrays of either; nulls skipped.
export function append(node, ...children) {
    for (const child of children.flat(Infinity)) {
        if (child === undefined || child === null || child === false)
            continue;
        node.append(child instanceof Node ? child : document.createTextNode(String(child)));
    }
    return node;
}

// Replace everything inside node with children.
export function replace(node, ...children) {
    node.replaceChildren();
    return append(node, ...children);
}

// Build nodes from trusted, fixed markup.  Values interpolated into the
// template are escaped.
export function html(strings, ...values) {
    const template = document.createElement('template');
    template.innerHTML = strings.reduce((out, s, i) =>
        out + s + (i < values.length ? escapeHtml(values[i]) : ''), '');
    return template.content.childElementCount === 1 ?
        template.content.firstElementChild : template.content;
}

export function escapeHtml(value) {
    return String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

// Call fn once calls have stopped for `ms` milliseconds.
export function debounce(ms, fn) {
    let timer = null;
    return (...args) => {
        clearTimeout(timer);
        timer = setTimeout(() => fn(...args), ms);
    };
}
