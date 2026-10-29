// A small line graph with no axes, for showing a trend at a glance.
//
//   const spark = sparkline();           // a <canvas> sized by CSS
//   spark.draw([1, 4, 2, 8, ...]);

import { el } from '../core/dom.js';
import { themeColor, onChange } from '../core/theme.js';

export function sparkline({ color = '--accent', className = 'sparkline' } = {}) {
    const canvas = el('canvas', { class: className });
    let values = [];

    function draw(newValues = values) {
        values = newValues;

        const ratio = window.devicePixelRatio || 1;
        const w = Math.max(1, Math.round(canvas.clientWidth * ratio));
        const h = Math.max(1, Math.round(canvas.clientHeight * ratio));
        if (canvas.width !== w || canvas.height !== h) {
            canvas.width = w;
            canvas.height = h;
        }

        const ctx = canvas.getContext('2d');
        ctx.clearRect(0, 0, w, h);
        if (values.length < 2)
            return;

        const max = Math.max(1, ...values);
        const step = w / (values.length - 1);
        const y = (v) => h - 1 - (v / max) * (h - 2);
        const stroke = themeColor(color) || '#888';

        ctx.beginPath();
        values.forEach((v, i) => (i === 0 ? ctx.moveTo(0, y(v)) : ctx.lineTo(i * step, y(v))));
        ctx.lineWidth = ratio;
        ctx.strokeStyle = stroke;
        ctx.stroke();

        ctx.lineTo(w, h);
        ctx.lineTo(0, h);
        ctx.closePath();
        ctx.globalAlpha = 0.2;
        ctx.fillStyle = stroke;
        ctx.fill();
        ctx.globalAlpha = 1;
    }

    const stop = onChange(() => draw());
    return { canvas, draw, destroy: stop };
}
