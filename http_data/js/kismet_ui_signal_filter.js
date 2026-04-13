(
    typeof define === "function" ? function (m) { define("kismet-ui-signal-filter-js", m); } :
    typeof exports === "object" ? function (m) { module.exports = m(); } :
    function (m) { this.kismet_ui_signal_filter = m(); }
)(function () {

"use strict";

var exports = {};

var currentThreshold = null;
var dtSearchIndex = null;
var tabulatorInstance = null;
var tableSelectorRef = "";

function getSignalThresholdInternal() {
    return currentThreshold;
}

exports.getSignalThreshold = function () {
    return currentThreshold;
};

exports.setSignalThreshold = function (value) {
    currentThreshold = value;
    applyFilter();
};

function applyFilter() {
    if (tabulatorInstance && typeof tabulatorInstance.setFilter === "function") {
        tabulatorInstance.clearFilter(true);
        if (currentThreshold !== null) {
            tabulatorInstance.setFilter(function (data) {
                var s = data.signal_dbm;
                if (s === undefined || s === null || s === "") return false;
                var n = parseFloat(s);
                return !isNaN(n) && n >= currentThreshold;
            });
        }
        return;
    }
    if ($.fn.dataTable && tableSelectorRef) {
        var dt = $(tableSelectorRef).DataTable();
        if (dt) dt.draw();
    }
}

function findSignalColumnIndex(dtSettings) {
    var idx = -1;
    $(dtSettings.aoColumns).each(function (i, col) {
        if (col.sName === "signal_dbm" || (col.mData === "signal_dbm")) {
            idx = i;
        }
    });
    return idx;
}

exports.createSignalFilterBar = function (tableSelector, options) {
    tableSelectorRef = tableSelector;
    var thresholds = (options && options.thresholds) || [
        { label: "60", value: -60 },
        { label: "70", value: -70 },
        { label: "80", value: -80 },
        { label: "all", value: null }
    ];

    var onFilterChange = options && options.onFilterChange;

    var el = $("<div>", { class: "signal-filter-wrap" });
    var bar = $("<div>", { class: "signal-filter-bar" });
    var note = $("<div>", { class: "signal-filter-note" }).hide();

    function setNote() {
        if (currentThreshold === null) {
            note.hide().empty();
        } else {
            var thr = String(currentThreshold).replace("-", "-");
            note.text(typeof kismet_i18n !== "undefined" ? kismet_i18n.t("signal_filter.filtering_active", { threshold: thr }) : "Filter");
            note.show();
        }
    }

    function mkBtn(labelKey, val, tlabel) {
        var lbl = tlabel || (typeof kismet_i18n !== "undefined" ? kismet_i18n.t(labelKey) : labelKey);
        return $("<button>", { type: "button", class: "signal-filter-btn", text: lbl })
            .on("click", function () {
                currentThreshold = val;
                bar.find(".signal-filter-btn").removeClass("active");
                $(this).addClass("active");
                setNote();
                applyFilter();
                if (typeof onFilterChange === "function") onFilterChange(currentThreshold);
            });
    }

    bar.append(mkBtn("signal_filter.above_60", -60, null));
    bar.append(mkBtn("signal_filter.above_70", -70, null));
    bar.append(mkBtn("signal_filter.above_80", -80, null));
    bar.append(mkBtn("signal_filter.show_all", null, null));

    el.append(bar);
    el.append(note);

    var domEl = $(tableSelector)[0];
    if (typeof Tabulator !== "undefined" && domEl) {
        tabulatorInstance = Tabulator.findTable(domEl);
    }

    if ($.fn.dataTable && $(tableSelector).length && $.fn.dataTable.isDataTable(tableSelector)) {
        if (dtSearchIndex !== null && $.fn.dataTable.ext.search[dtSearchIndex]) {
            $.fn.dataTable.ext.search.splice(dtSearchIndex, 1);
        }
        dtSearchIndex = $.fn.dataTable.ext.search.push(function (settings, data, dataIndex) {
            if (currentThreshold === null) return true;
            var colIdx = findSignalColumnIndex(settings);
            if (colIdx < 0) return true;
            var raw = data[colIdx];
            if (raw === undefined || raw === null) return false;
            var n = parseFloat(String(raw).replace(/[^0-9.-]/g, ""));
            if (isNaN(n)) return false;
            return n >= currentThreshold;
        });
    }

    return el;
};

return exports;

});
