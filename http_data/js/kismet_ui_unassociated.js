(
    typeof define === "function" ? function (m) { define("kismet-ui-unassociated-js", m); } :
    typeof exports === "object" ? function (m) { module.exports = m(); } :
    function (m) { this.kismet_ui_unassociated_module = m(); }
)(function () {

"use strict";

var exports = {};

var local_uri_prefix = "";
if (typeof KISMET_URI_PREFIX !== "undefined") {
    local_uri_prefix = KISMET_URI_PREFIX;
}

function t(k, o) {
    return (typeof kismet_i18n !== "undefined" && kismet_i18n.t) ? kismet_i18n.t(k, o) : k;
}

var unassocTable = null;
var allRows = [];
var filterApi = null;

function getTypeSet(dev) {
    var ts = dev["dot11.device.type_set"];
    if (ts == null && dev["dot11.device"] && dev["dot11.device"]["dot11.device.type_set"] != null) {
        ts = dev["dot11.device"]["dot11.device.type_set"];
    }
    return ts;
}

function typeSetHas(ts, name) {
    if (!ts) return false;
    if (Array.isArray(ts)) return ts.indexOf(name) >= 0;
    if (typeof ts === "string") return ts.indexOf(name) >= 0;
    if (typeof ts === "object") return name in ts;
    return false;
}

function isUnassociatedProbing(dev) {
    var ts = getTypeSet(dev);
    var hasProbing = typeSetHas(ts, "probing");
    var hasToDs = typeSetHas(ts, "to-ds");
    var assoc = dev["dot11.device.associated_client_map"];
    if (assoc == null && dev["dot11.device"]) {
        assoc = dev["dot11.device"]["dot11.device.associated_client_map"];
    }
    var emptyAssoc = !assoc || (typeof assoc === "object" && Object.keys(assoc).length === 0);
    return hasProbing && emptyAssoc && !hasToDs;
}

function probedSsids(dev) {
    var m = dev["dot11.device.probed_ssid_map"];
    if (!m && dev["dot11.device"]) {
        m = dev["dot11.device"]["dot11.device.probed_ssid_map"];
    }
    if (!m || typeof m !== "object") return "(broadcast)";
    var keys = Object.keys(m);
    if (keys.length === 0) return "(broadcast)";
    return keys.join(", ");
}

function lastSignalDbm(dev) {
    var v = dev["kismet.common.signal.last_signal_dbm"];
    if (v != null) return parseFloat(v);
    var s = dev["kismet.device.base.signal"];
    if (s && s["kismet.common.signal.last_signal_dbm"] != null) {
        return parseFloat(s["kismet.common.signal.last_signal_dbm"]);
    }
    return null;
}

function mapRow(dev) {
    var mac = dev["kismet.device.base.macaddr"] || "";
    var key = dev["kismet.device.base.key"] || "";
    var wl = (typeof kismet_whitelist_api !== "undefined" && kismet_whitelist_api.isWhitelisted(mac));
    return {
        original_data: dev,
        device_key: key,
        mac: mac,
        manuf: dev["kismet.device.base.manuf"] || "",
        probed: probedSsids(dev),
        signal_dbm: lastSignalDbm(dev),
        channel: dev["kismet.device.base.channel"] || "",
        last_seen: dev["kismet.device.base.last_time"] || 0,
        packets: (dev["kismet.device.base.packets"] && dev["kismet.device.base.packets"].total) || 0,
        approved: wl
    };
}

var MOCK_DATA = [
    {
        "kismet.device.base.key": "mock1",
        "kismet.device.base.macaddr": "AA:BB:CC:DD:EE:01",
        "kismet.device.base.manuf": "MockVendor",
        "kismet.device.base.last_time": Math.floor(Date.now() / 1000),
        "kismet.device.base.channel": 6,
        "kismet.common.signal.last_signal_dbm": -45,
        "kismet.device.base.packets": { total: 100 },
        "dot11.device.type_set": ["probing"],
        "dot11.device.associated_client_map": {},
        "dot11.device.probed_ssid_map": { "サンプルSSID": {} }
    }
];

function fetchDevices() {
    var fields = [
        "kismet.device.base.key",
        "kismet.device.base.macaddr",
        "kismet.device.base.name",
        "kismet.device.base.manuf",
        "kismet.device.base.last_time",
        "kismet.device.base.first_time",
        "kismet.device.base.signal/kismet.common.signal.last_signal_dbm",
        "kismet.device.base.packets.total",
        "dot11.device/dot11.device.probed_ssid_map",
        "dot11.device/dot11.device.type_set",
        "dot11.device/dot11.device.associated_client_map",
        "kismet.device.base.channel",
        "kismet.device.base.frequency"
    ];
    var postdata = {
        json: JSON.stringify({ fields: fields }),
        page: 0,
        length: 500
    };
    return $.post(local_uri_prefix + "devices/views/all/devices.json", postdata)
        .then(function (data) {
            if (!data || !data.data) return [];
            var raw = kismet.sanitizeObject(data.data);
            var out = [];
            for (var i = 0; i < raw.length; i++) {
                if (isUnassociatedProbing(raw[i])) {
                    out.push(raw[i]);
                }
            }
            return out;
        }, function () {
            return MOCK_DATA.filter(function (d) { return isUnassociatedProbing(d); });
        });
}

function OpenUnassociatedPanel() {
    var root = $("<div>");
    var titleBar = $("<div>", { class: "unassoc-toolbar" });
    titleBar.append($("<h3>").text(t("unassociated.title")));
    root.append(titleBar);

    var filterHost = $("<div>");
    root.append(filterHost);

    var exportHost = $("<div>", { class: "unassoc-toolbar export-buttons-host" });
    root.append(exportHost);

    var tableDiv = $("<div>", { id: "unassoc-table" });
    root.append(tableDiv);

    var bulk = $("<div>", { class: "unassoc-bulk-bar" });
    bulk.append($("<label>").append($("<input>", { type: "checkbox", id: "unassoc-sel-all" })).append($("<span>").text(t("whitelist.select_all"))));
    bulk.append($("<span>", { id: "unassoc-sel-count" }).text(t("whitelist.selected_count", { count: 0 })));
    bulk.append($("<button>", { type: "button", class: "btn-register" }).text(t("whitelist.add_bulk")).on("click", function () {
        var sel = unassocTable.getSelectedData();
        if (!sel.length) return;
        if (!confirm(t("whitelist.confirm_bulk_register", { count: sel.length }))) return;
        var box = $("<div>", { class: "whitelist-dialog" });
        var cs = $("<select>");
        ["pc", "mobile", "iot", "printer", "network", "other"].forEach(function (k) {
            cs.append($("<option>", { value: k }).text(t("whitelist.categories." + k)));
        });
        var notesTa = $("<textarea>", { id: "bulk-notes" });
        box.append($("<label>").text(t("whitelist.category"))).append(cs);
        box.append($("<label>").text(t("whitelist.notes"))).append(notesTa);
        showBulkModal(t("whitelist.add_bulk"), box, function () {
            var notes = notesTa.val();
            var cat = cs.val();
            var entries = sel.map(function (row) {
                return {
                    mac: row.mac,
                    name: row.original_data["kismet.device.base.name"] || "",
                    category: cat,
                    notes: notes
                };
            });
            kismet_whitelist_api.addBulkToWhitelist(entries);
            unassocTable.redraw(true);
        });
    }));
    root.append(bulk);

    $.jsPanel({
        headerTitle: t("unassociated.title"),
        content: root,
        theme: "dark",
        width: $(window).width() * 0.9,
        height: $(window).height() * 0.85,
        callback: function () {
            unassocTable = new Tabulator("#unassoc-table", {
                layout: "fitColumns",
                selectable: true,
                columns: [
                    {
                        field: "approved",
                        title: t("whitelist.status"),
                        formatter: function (cell) {
                            return cell.getValue()
                                ? "<span class='whitelist-approved'><i class='fa fa-check'></i></span>"
                                : "<span class='whitelist-unknown'><i class='fa fa-exclamation-triangle'></i></span>";
                        }
                    },
                    { field: "mac", title: t("device_list.mac_address") },
                    { field: "manuf", title: t("device_list.manufacturer") },
                    { field: "probed", title: t("unassociated.probed_ssids") },
                    { field: "signal_dbm", title: t("unassociated.signal_strength") },
                    { field: "channel", title: t("device_list.channel") },
                    {
                        field: "last_seen",
                        title: t("device_list.last_seen"),
                        formatter: function (c) {
                            var v = c.getValue();
                            return v ? (new Date(v * 1000).toString()).substring(4, 25) : "";
                        }
                    },
                    { field: "packets", title: t("device_list.packets") }
                ]
            });
            if (typeof kismet_ui_signal_filter !== "undefined") {
                filterApi = kismet_ui_signal_filter.createSignalFilterBar("#unassoc-table", {
                    onFilterChange: function () {
                        updateCount();
                    }
                });
                filterHost.append(filterApi);
            }
            if (typeof kismet_ui_export !== "undefined") {
                kismet_ui_export.createExportButtons(".export-buttons-host", function () {
                    if (!unassocTable) return [];
                    return unassocTable.getData("active");
                }, {
                    includeWhitelistStatus: true,
                    filename: "unassociated_export",
                    signalFilter: function () {
                        return kismet_ui_signal_filter ? kismet_ui_signal_filter.getSignalThreshold() : null;
                    }
                });
            }
            unassocTable.on("rowClick", function (e, row) {
                if ($(e.target).closest("input[type=checkbox]").length) return;
                var d = row.getData();
                if (typeof kismet_ui_signal_monitor !== "undefined") {
                    kismet_ui_signal_monitor.OpenSignalMonitor(
                        d.device_key,
                        d.mac,
                        d.original_data["kismet.device.base.name"] || "",
                        d.manuf
                    );
                }
            });
            $("#unassoc-sel-all").on("change", function () {
                if (this.checked) {
                    unassocTable.selectRow();
                } else {
                    unassocTable.deselectRow();
                }
            });
            unassocTable.on("rowSelected", function () {
                $("#unassoc-sel-count").text(t("whitelist.selected_count", {
                    count: unassocTable.getSelectedData().length
                }));
            });
            unassocTable.on("rowDeselected", function () {
                $("#unassoc-sel-count").text(t("whitelist.selected_count", {
                    count: unassocTable.getSelectedData().length
                }));
            });
            fetchDevices().then(function (list) {
                allRows = list.map(mapRow);
                unassocTable.setData(allRows);
                updateCount();
            });
        }
    });
}

function showBulkModal(title, body, onDone) {
    var overlay = $("<div>", { class: "kismet-modal-overlay" });
    var modal = $("<div>", { class: "kismet-modal" });
    modal.append($("<div>", { class: "kismet-modal-header" }).text(title));
    modal.append(body);
    var foot = $("<div>", { class: "kismet-modal-footer" });
    foot.append($("<button>", { type: "button" }).text(t("common.cancel")).on("click", function () {
        overlay.remove();
    }));
    foot.append($("<button>", { type: "button" }).text(t("common.ok")).on("click", function () {
        onDone();
        overlay.remove();
    }));
    modal.append(foot);
    overlay.append(modal);
    $("body").append(overlay);
}

function updateCount() {
    if (!unassocTable) return;
    var total = allRows.length;
    var vis = unassocTable.getData("active").length;
    $("#unassoc-sel-count").text(t("signal_filter.device_count", { visible: vis, total: total }));
}

exports.registerSidebar = function () {
    if (typeof kismet_ui_sidebar === "undefined") return;
    kismet_ui_sidebar.AddSidebarItem({
        id: "unassociated_clients",
        listTitle: "<i class=\"fa fa-wifi\"></i> " + t("sidebar.unassociated_clients"),
        priority: -10,
        clickCallback: OpenUnassociatedPanel
    });
};

return exports;

});
