(
    typeof define === "function" ? function (m) { define("kismet-whitelist-api-js", m); } :
    typeof exports === "object" ? function (m) { module.exports = m(); } :
    function (m) { this.kismet_whitelist_api = m(); }
)(function () {

"use strict";

var exports = {};

var STORAGE_KEY = "kismet.whitelist.devices";
var whitelistMacSet = new Set();

var local_uri_prefix = "";
if (typeof KISMET_URI_PREFIX !== "undefined") {
    local_uri_prefix = KISMET_URI_PREFIX;
}

/** CSV_COLUMN mapping for Kismet export headers and simple aliases */
var CSV_COLUMN_MAP = {
    "kismet.device.base.macaddr": "mac",
    "kismet.device.base.name": "name",
    "kismet.device.base.manuf": "category",
    mac: "mac",
    name: "name",
    category: "category",
    notes: "notes"
};

function dispatchChanged() {
    document.dispatchEvent(new CustomEvent("kismet-whitelist-changed"));
}

function normalizeMac(mac) {
    if (!mac || typeof mac !== "string") return "";
    return mac.trim().toUpperCase().replace(/-/g, ":");
}

function validateMacFormat(mac) {
    var m = normalizeMac(mac);
    return /^([0-9A-F]{2}:){5}[0-9A-F]{2}$/.test(m);
}

function loadStorage() {
    var raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    try {
        var arr = JSON.parse(raw);
        return Array.isArray(arr) ? arr : [];
    } catch (e) {
        return [];
    }
}

function saveStorage(arr) {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(arr));
    rebuildCache(arr);
    dispatchChanged();
}

function rebuildCache(arr) {
    whitelistMacSet = new Set();
    for (var i = 0; i < arr.length; i++) {
        if (arr[i] && arr[i].mac) {
            whitelistMacSet.add(normalizeMac(arr[i].mac));
        }
    }
}

function trySyncTags(entry) {
    if (typeof $ === "undefined") return;
    var mac = normalizeMac(entry.mac);
    $.get(local_uri_prefix + "devices/by-mac/" + encodeURIComponent(mac) + "/devices.json")
        .done(function (data) {
            if (!data || !data.length) return;
            var key = data[0]["kismet.device.base.key"];
            if (!key) return;
            var base = local_uri_prefix + "devices/by-key/" + encodeURIComponent(key) + "/set_tag.cmd";
            $.post(base, JSON.stringify({ tagname: "whitelist", tagvalue: "approved" }));
            if (entry.category) {
                $.post(base, JSON.stringify({ tagname: "whitelist_category", tagvalue: entry.category }));
            }
            if (entry.notes) {
                $.post(base, JSON.stringify({ tagname: "whitelist_notes", tagvalue: entry.notes }));
            }
        });
}

(function init() {
    rebuildCache(loadStorage());
})();

exports.getWhitelist = function () {
    return loadStorage().slice();
};

exports.getWhitelistCache = function () {
    return whitelistMacSet;
};

exports.isWhitelisted = function (mac) {
    return whitelistMacSet.has(normalizeMac(mac));
};

exports.addToWhitelist = function (entry) {
    if (!entry || !entry.mac) throw new Error("mac required");
    var mac = normalizeMac(entry.mac);
    if (!validateMacFormat(mac)) throw new Error("MAC format invalid");
    var list = loadStorage();
    if (list.some(function (e) { return normalizeMac(e.mac) === mac; })) {
        throw new Error("duplicate mac");
    }
    var row = {
        mac: mac,
        name: entry.name || "",
        category: entry.category || "",
        notes: entry.notes || "",
        added_date: entry.added_date || new Date().toISOString().slice(0, 10)
    };
    list.push(row);
    saveStorage(list);
    trySyncTags(row);
    return row;
};

exports.addBulkToWhitelist = function (entries) {
    var n = 0;
    for (var i = 0; i < entries.length; i++) {
        try {
            exports.addToWhitelist(entries[i]);
            n++;
        } catch (e) { /* skip */ }
    }
    return n;
};

exports.updateWhitelistEntry = function (mac, updates) {
    var m = normalizeMac(mac);
    var list = loadStorage();
    for (var i = 0; i < list.length; i++) {
        if (normalizeMac(list[i].mac) === m) {
            if (updates.name != null) list[i].name = updates.name;
            if (updates.category != null) list[i].category = updates.category;
            if (updates.notes != null) list[i].notes = updates.notes;
            saveStorage(list);
            trySyncTags(list[i]);
            return list[i];
        }
    }
    return null;
};

exports.removeFromWhitelist = function (mac) {
    var m = normalizeMac(mac);
    var list = loadStorage().filter(function (e) { return normalizeMac(e.mac) !== m; });
    if (list.length === loadStorage().length) return false;
    saveStorage(list);
    return true;
};

exports.removeBulkFromWhitelist = function (macs) {
    var set = new Set();
    for (var i = 0; i < macs.length; i++) {
        set.add(normalizeMac(macs[i]));
    }
    var list = loadStorage().filter(function (e) { return !set.has(normalizeMac(e.mac)); });
    saveStorage(list);
};

exports.importFromCSV = function (csvString) {
    var success = 0;
    var errors = [];
    if (typeof Papa === "undefined" || !Papa.parse) {
        errors.push("PapaParse not available");
        return { success: success, errors: errors };
    }
    var parsed = Papa.parse(csvString, { header: true });
    var rows = parsed.data || [];
    for (var r = 0; r < rows.length; r++) {
        var row = rows[r];
        if (!row) continue;
        var mac = "";
        var name = "";
        var category = "";
        var notes = "";
        for (var k in row) {
            if (!Object.prototype.hasOwnProperty.call(row, k)) continue;
            var nk = CSV_COLUMN_MAP[k] || CSV_COLUMN_MAP[k.toLowerCase()] || k;
            if (nk === "mac") mac = row[k];
            else if (nk === "name") name = row[k];
            else if (nk === "category") category = row[k];
            else if (nk === "notes") notes = row[k];
        }
        try {
            exports.addToWhitelist({ mac: mac, name: name, category: category, notes: notes });
            success++;
        } catch (e) {
            errors.push(String(r + 1) + ": " + String(e.message || e));
        }
    }
    return { success: success, errors: errors };
};

exports.exportToCSV = function () {
    var list = loadStorage();
    var BOM = "\uFEFF";
    var header = "mac,name,category,notes,added_date";
    var lines = [header];
    for (var i = 0; i < list.length; i++) {
        var e = list[i];
        var row = [
            e.mac,
            e.name || "",
            e.category || "",
            (e.notes || "").replace(/"/g, "\"\""),
            e.added_date || ""
        ].map(function (cell) {
            if (cell.indexOf(",") >= 0 || cell.indexOf("\n") >= 0) {
                return "\"" + cell + "\"";
            }
            return cell;
        });
        lines.push(row.join(","));
    }
    return BOM + lines.join("\n");
};

return exports;

});
