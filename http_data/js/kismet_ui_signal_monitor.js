(
    typeof define === "function" ? function (m) { define("kismet-ui-signal-monitor-js", m); } :
    typeof exports === "object" ? function (m) { module.exports = m(); } :
    function (m) { this.kismet_ui_signal_monitor = m(); }
)(function () {

"use strict";

var exports = {};

var local_uri_prefix = "";
if (typeof KISMET_URI_PREFIX !== "undefined") {
    local_uri_prefix = KISMET_URI_PREFIX;
}

function hashDeviceKey(key) {
    var h = 0;
    var s = String(key || "");
    for (var i = 0; i < s.length; i++) {
        h = ((h << 5) - h) + s.charCodeAt(i);
        h |= 0;
    }
    return String(h);
}

function extractDbmFromDevice(dev) {
    if (!dev) return null;
    var v = dev["kismet.common.signal.last_signal_dbm"];
    if (v != null) return parseFloat(v);
    var sig = dev["kismet.device.base.signal"];
    if (sig && typeof sig === "object" && sig["kismet.common.signal.last_signal_dbm"] != null) {
        return parseFloat(sig["kismet.common.signal.last_signal_dbm"]);
    }
    return null;
}

function signalLabel(dbm, tfn) {
    if (dbm == null || isNaN(dbm)) return tfn("signal_monitor.no_signal");
    if (dbm >= -50) return tfn("signal_monitor.very_strong");
    if (dbm >= -70) return tfn("signal_monitor.strong");
    if (dbm >= -80) return tfn("signal_monitor.medium");
    if (dbm >= -90) return tfn("signal_monitor.weak");
    return tfn("signal_monitor.very_weak");
}

function barColor(dbm) {
    if (dbm == null || isNaN(dbm)) return "#95a5a6";
    if (dbm >= -50) return "#27ae60";
    if (dbm >= -70) return "#f1c40f";
    return "#e74c3c";
}

exports.OpenSignalMonitor = function (deviceKey, macAddr, deviceName, manufName) {
    var tfn = function (k) {
        return (typeof kismet_i18n !== "undefined" && kismet_i18n.t) ? kismet_i18n.t(k) : k;
    };

    var mockMode = false;
    var ws = null;
    var pollTimer = null;
    var mockTimer = null;
    var chartInst = null;
    var signalHistory = [];
    var rateSec = 1;
    var panelId = "signal-monitor-" + hashDeviceKey(deviceKey);

    var user = kismet.getStorage("kismet.base.login.username", "kismet");
    var pw = kismet.getStorage("kismet.base.login.password", "");

    var proto = document.location.protocol === "https:" ? "wss" : "ws";
    var host = new URL(document.URL);
    var wsUrl = proto + "://" + host.host + "/" + (typeof KISMET_PROXY_PREFIX !== "undefined" ? KISMET_PROXY_PREFIX : "") +
        "devices/monitor.ws?user=" + encodeURIComponent(user) + "&password=" + encodeURIComponent(pw);

    var headerTitle = tfn("signal_monitor.title") + ": " + macAddr;

    var content = $("<div>", { class: "signal-monitor-content" });
    content.append($("<div>", { class: "signal-device-info" }).text(
        (deviceName || "") + " / " + (manufName || "")
    ));

    var barOuter = $("<div>", { class: "signal-bar-container" });
    var barInner = $("<div>", { class: "signal-bar" }).css({ width: "0%" });
    barOuter.append(barInner);
    content.append(barOuter);

    var valRow = $("<div>").css({ marginTop: "8px" });
    var valNum = $("<span>", { class: "signal-value" }).text("--");
    var valLbl = $("<span>", { class: "signal-level-text" }).text("");
    valRow.append(valNum).append(valLbl);
    content.append(valRow);

    content.append($("<div>", { class: "signal-scale" }).html(
        "<span>-20</span><span>-50</span><span>-70</span><span>-90</span>"
    ));

    var canvas = $("<canvas>", { width: 520, height: 180 });
    var chartHolder = $("<div>", { class: "signal-chart-container" }).append(canvas);
    content.append(chartHolder);

    var intervalSel = $("<select>").append(
        $("<option>", { value: "1" }).text("1 " + tfn("signal_monitor.sec")),
        $("<option>", { value: "2" }).text("2 " + tfn("signal_monitor.sec")),
        $("<option>", { value: "5" }).text("5 " + tfn("signal_monitor.sec"))
    );

    var controls = $("<div>", { class: "signal-controls" });
    controls.append($("<span>").text(tfn("signal_monitor.interval") + ": "));
    controls.append(intervalSel);
    controls.append($("<button>", { type: "button", class: "btn" }).text(tfn("signal_monitor.csv_save")).on("click", saveCsv));
    controls.append($("<button>", { type: "button", class: "btn" }).text(tfn("signal_monitor.close")).on("click", function () {
        panel.close();
    }));
    content.append(controls);

    function updateUi(dbm) {
        if (dbm == null || isNaN(dbm)) {
            valNum.text("--");
            valLbl.text(signalLabel(null, tfn));
            barInner.css({ width: "0%", background: barColor(NaN) });
            return;
        }
        valNum.text(dbm + " dBm");
        valLbl.text(signalLabel(dbm, tfn));
        var pct = Math.max(0, Math.min(100, (dbm + 100) / 80 * 100));
        barInner.css({ width: pct + "%", background: barColor(dbm) });
        var now = new Date();
        var label = now.toTimeString().slice(0, 8);
        signalHistory.push({ t: label, dbm: dbm });
        if (signalHistory.length > 120) signalHistory.shift();
        if (chartInst) {
            chartInst.data.labels = signalHistory.map(function (p) { return p.t; });
            chartInst.data.datasets[0].data = signalHistory.map(function (p) { return p.dbm; });
            chartInst.update("none");
        }
    }

    function saveCsv() {
        var BOM = "\uFEFF";
        var lines = [BOM + tfn("signal_monitor.time") + "," + tfn("signal_monitor.signal_dbm")];
        for (var i = 0; i < signalHistory.length; i++) {
            lines.push(signalHistory[i].t + "," + signalHistory[i].dbm);
        }
        var blob = new Blob([lines.join("\n")], { type: "text/csv;charset=utf-8" });
        var a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = "signal_" + String(macAddr).replace(/:/g, "") + "_" + Date.now() + ".csv";
        a.click();
        URL.revokeObjectURL(a.href);
    }

    function startMock() {
        mockMode = true;
        headerTitle = "[MOCK] " + headerTitle;
        mockTimer = window.setInterval(function () {
            var dbm = Math.round(-30 - Math.random() * 50);
            updateUi(dbm);
        }, 1000);
    }

    function startPoll() {
        pollTimer = window.setInterval(function () {
            $.get(local_uri_prefix + "devices/by-mac/" + encodeURIComponent(macAddr) + "/devices.json")
                .done(function (data) {
                    if (data && data[0]) {
                        var dbm = extractDbmFromDevice(data[0]);
                        updateUi(dbm);
                    }
                });
        }, 3000);
    }

    function connectWs() {
        try {
            ws = new WebSocket(wsUrl);
        } catch (e) {
            startPoll();
            return;
        }
        ws.onopen = function () {
            ws.send(JSON.stringify({
                monitor: macAddr,
                request: Date.now(),
                rate: rateSec,
                fields: ["kismet.device.base.signal/kismet.common.signal.last_signal_dbm"]
            }));
        };
        ws.onmessage = function (ev) {
            try {
                var j = JSON.parse(ev.data);
                var dbm = null;
                if (typeof j === "object") {
                    dbm = extractDbmFromDevice(j);
                }
                if (dbm != null) updateUi(dbm);
            } catch (e2) { /* ignore */ }
        };
        ws.onerror = function () {
            if (ws) ws.close();
            if (!pollTimer) startPoll();
        };
        ws.onclose = function () {
            if (!pollTimer && !mockMode) startPoll();
        };
    }

    intervalSel.on("change", function () {
        rateSec = parseInt(intervalSel.val(), 10) || 1;
        if (ws && ws.readyState === 1) {
            ws.send(JSON.stringify({ cancel: macAddr }));
            ws.send(JSON.stringify({
                monitor: macAddr,
                request: Date.now(),
                rate: rateSec,
                fields: ["kismet.device.base.signal/kismet.common.signal.last_signal_dbm"]
            }));
        }
        if (pollTimer) {
            window.clearInterval(pollTimer);
            pollTimer = null;
            startPoll();
        }
    });

    var panel = $.jsPanel({
        id: panelId,
        headerTitle: headerTitle,
        content: content,
        theme: "dark",
        headerControls: { iconfont: "jsglyph", controls: "closeonly" },
        onclosed: function () {
            if (ws && ws.readyState === 1) {
                try {
                    ws.send(JSON.stringify({ cancel: macAddr }));
                } catch (e) { /* ignore */ }
                ws.close();
            }
            if (pollTimer) window.clearInterval(pollTimer);
            if (mockTimer) window.clearInterval(mockTimer);
            if (chartInst) chartInst.destroy();
        },
        callback: function () {
            if (typeof Chart === "undefined") {
                startMock();
                return;
            }
            var ctx = canvas[0].getContext("2d");
            chartInst = new Chart(ctx, {
                type: "line",
                data: {
                    labels: [],
                    datasets: [{
                        data: [],
                        borderColor: "#3498db",
                        tension: 0.3,
                        pointRadius: 0,
                        fill: false
                    }]
                },
                options: {
                    animation: false,
                    scales: {
                        y: { min: -100, max: -10 },
                        x: { display: true }
                    },
                    plugins: { legend: { display: false } }
                }
            });
            connectWs();
            window.setTimeout(function () {
                if (!signalHistory.length && !pollTimer && (!ws || ws.readyState !== 1)) {
                    if (ws) ws.close();
                    startMock();
                }
            }, 2000);
        }
    });

    panel.resize({ width: 560, height: 450 });
};

return exports;

});
