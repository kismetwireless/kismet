(
    typeof define === "function" ? function (m) { define("kismet-ui-export-js", m); } :
    typeof exports === "object" ? function (m) { module.exports = m(); } :
    function (m) { this.kismet_ui_export = m(); }
)(function () {

"use strict";

var exports = {};

function t(k) {
    return (typeof kismet_i18n !== "undefined" && kismet_i18n.t) ? kismet_i18n.t(k) : k;
}

function fmtTs(sec) {
    if (sec == null || sec === "") return "";
    var d = new Date(Number(sec) * 1000);
    return d.toLocaleString("ja-JP", { year: "numeric", month: "2-digit", day: "2-digit",
        hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

exports.exportDeviceListCSV = function (data, options) {
    var opts = options || {};
    var title = opts.title || t("export.report_title");
    var BOM = "\uFEFF";
    var headers = [
        t("device_list.mac_address"),
        t("device_list.name"),
        t("device_list.manufacturer"),
        t("device_list.type"),
        t("device_list.signal"),
        t("device_list.channel"),
        t("device_list.encryption"),
        t("device_list.last_seen"),
        t("device_list.first_seen"),
        t("unassociated.probed_ssids"),
        t("device_list.packets"),
        t("whitelist.status")
    ];
    if (!opts.includeWhitelistStatus) {
        headers.pop();
    }
    var lines = [BOM + headers.join(",")];
    for (var i = 0; i < data.length; i++) {
        var row = data[i];
        var od = row.original_data || row;
        var mac = od["kismet.device.base.macaddr"] || row.mac || "";
        var name = od["kismet.device.base.name"] || od["kismet.device.base.commonname"] || "";
        var manuf = od["kismet.device.base.manuf"] || "";
        var typ = od["kismet.device.base.type"] || "";
        var sig = od["kismet.common.signal.last_signal_dbm"];
        if (sig == null && od["kismet.device.base.signal"]) {
            sig = od["kismet.device.base.signal"]["kismet.common.signal.last_signal_dbm"];
        }
        var ch = od["kismet.device.base.channel"] || "";
        var crypt = od["kismet.device.base.crypt"] || "";
        var lt = fmtTs(od["kismet.device.base.last_time"]);
        var ft = fmtTs(od["kismet.device.base.first_time"]);
        var probed = "";
        if (od["dot11.device.probed_ssid_map"]) {
            probed = Object.keys(od["dot11.device.probed_ssid_map"]).join(";");
        }
        var pkts = od["kismet.device.base.packets"] && od["kismet.device.base.packets"].total != null
            ? od["kismet.device.base.packets"].total : "";
        var wl = "";
        if (opts.includeWhitelistStatus && typeof kismet_whitelist_api !== "undefined") {
            wl = kismet_whitelist_api.isWhitelisted(mac) ? t("whitelist.approved") : t("whitelist.unknown");
        }
        var cells = [mac, name, manuf, typ, sig, ch, crypt, lt, ft, probed, pkts];
        if (opts.includeWhitelistStatus) cells.push(wl);
        lines.push(cells.map(function (c) {
            var s = String(c == null ? "" : c).replace(/"/g, "\"\"");
            if (s.indexOf(",") >= 0 || s.indexOf("\n") >= 0) return "\"" + s + "\"";
            return s;
        }).join(","));
    }
    var blob = new Blob([lines.join("\n")], { type: "text/csv;charset=utf-8" });
    var a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = (opts.filename || "export") + ".csv";
    a.click();
    URL.revokeObjectURL(a.href);
    return title;
};

exports.exportDeviceListPDF = function (data, options) {
    var opts = options || {};
    var doc = new window.jsPDF({ orientation: "landscape", unit: "pt", format: "a4" });
    var now = new Date().toISOString();
    doc.setFontSize(14);
    doc.text(40, 40, String(opts.title || t("export.report_title")));
    doc.setFontSize(10);
    doc.text(40, 58, String(t("export.generated_at", { datetime: now })));
    doc.text(40, 72, String(t("export.total_devices", { count: data.length })));
    var sf = opts.signalFilter;
    if (typeof sf === "function") sf = sf();
    if (sf != null) {
        doc.text(40, 86, String(t("export.filter_note", { threshold: sf })));
    }
    var body = [];
    for (var i = 0; i < data.length; i++) {
        var od = data[i].original_data || data[i];
        body.push([
            String(od["kismet.device.base.macaddr"] || ""),
            String(od["kismet.device.base.commonname"] || od["kismet.device.base.name"] || ""),
            String(od["kismet.common.signal.last_signal_dbm"] != null
                ? od["kismet.common.signal.last_signal_dbm"] : "")
        ]);
    }
    doc.autoTable({
        head: [["MAC", "Name", "Sig"]],
        body: body,
        startY: 100
    });
    doc.save((opts.filename || "export") + ".pdf");
};

exports.createExportButtons = function (containerSelector, getDataCallback, options) {
    var opts = options || {};
    var wrap = $("<div>", { class: "export-buttons" });
    var bcsv = $("<button>", { type: "button", class: "export-btn export-btn-csv" }).text(t("export.csv"))
        .on("click", function () {
            var data = getDataCallback();
            exports.exportDeviceListCSV(data, opts);
        });
    var bpdf = $("<button>", { type: "button", class: "export-btn export-btn-pdf" }).text(t("export.pdf"))
        .on("click", function () {
            var data = getDataCallback();
            exports.exportDeviceListPDF(data, opts);
        });
    wrap.append(bcsv).append(bpdf);
    $(containerSelector).append(wrap);
    return wrap;
};

return exports;

});
