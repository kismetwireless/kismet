(
    typeof define === "function" ? function (m) { define("kismet-ui-whitelist-js", m); } :
    typeof exports === "object" ? function (m) { module.exports = m(); } :
    function (m) { this.kismet_ui_whitelist_module = m(); }
)(function () {

"use strict";

var exports = {};

function t(k, o) {
    return (typeof kismet_i18n !== "undefined" && kismet_i18n.t) ? kismet_i18n.t(k, o) : k;
}

var tabulator = null;

function categoryOptions() {
    return [
        { v: "pc", l: t("whitelist.categories.pc") },
        { v: "mobile", l: t("whitelist.categories.mobile") },
        { v: "iot", l: t("whitelist.categories.iot") },
        { v: "printer", l: t("whitelist.categories.printer") },
        { v: "network", l: t("whitelist.categories.network") },
        { v: "other", l: t("whitelist.categories.other") }
    ];
}

function buildCategorySelect(val) {
    var sel = $("<select>");
    var opts = categoryOptions();
    for (var i = 0; i < opts.length; i++) {
        sel.append($("<option>", { value: opts[i].v }).text(opts[i].l));
    }
    if (val) sel.val(val);
    return sel;
}

function showModal(title, body, onOk) {
    var overlay = $("<div>", { class: "kismet-modal-overlay" });
    var modal = $("<div>", { class: "kismet-modal" });
    modal.append($("<div>", { class: "kismet-modal-header" }).text(title));
    modal.append($("<div>", { class: "whitelist-dialog" }).append(body));
    var foot = $("<div>", { class: "kismet-modal-footer" });
    foot.append($("<button>", { type: "button" }).text(t("common.cancel")).on("click", function () {
        overlay.remove();
    }));
    foot.append($("<button>", { type: "button", class: "btn-primary" }).text(t("common.ok")).on("click", function () {
        onOk(function () { overlay.remove(); });
    }));
    modal.append(foot);
    overlay.append(modal);
    $("body").append(overlay);
}

function validateMac(m) {
    var x = String(m || "").trim().toUpperCase().replace(/-/g, ":");
    return /^([0-9A-F]{2}:){5}[0-9A-F]{2}$/.test(x);
}

function refreshTable() {
    if (!tabulator) return;
    tabulator.replaceData(kismet_whitelist_api.getWhitelist());
}

function OpenWhitelistPanel() {
    var wrap = $("<div>");
    var toolbar = $("<div>", { class: "whitelist-toolbar" });
    toolbar.append($("<button>", { type: "button", class: "btn btn-primary" }).text(t("whitelist.add_single")).on("click", function () {
        openEditDialog(null);
    }));
    var fileInput = $("<input>", { type: "file", accept: ".csv", css: { display: "none" } });
    fileInput.attr("data-import", "import_csv");
    toolbar.append($("<button>", { type: "button", class: "btn btn-success" }).text(t("whitelist.import_csv")).on("click", function () {
        fileInput.click();
    }));
    toolbar.append(fileInput);
    toolbar.append($("<button>", { type: "button", class: "btn btn-warning" }).text(t("whitelist.export_csv")).on("click", function () {
        var csv = kismet_whitelist_api.exportToCSV();
        var blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
        var a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = "whitelist.csv";
        a.click();
        URL.revokeObjectURL(a.href);
    }));
    var search = $("<input>", { type: "search", placeholder: t("common.search") }).on("keyup", function () {
        var term = $(this).val().toLowerCase();
        tabulator.setFilter(function (data) {
            if (!term) return true;
            return String(data.mac + data.name + data.category + data.notes).toLowerCase().indexOf(term) >= 0;
        });
    });
    toolbar.append(search);
    wrap.append(toolbar);

    var tableHost = $("<div>", { id: "whitelist-table-host" });
    wrap.append(tableHost);

    var bulk = $("<div>", { class: "whitelist-toolbar" });
    bulk.append($("<span>", { id: "wl-selected-label" }).text(t("whitelist.selected_count", { count: 0 })));
    bulk.append($("<button>", { type: "button", class: "btn" }).text(t("whitelist.delete_selected")).prop("disabled", true).on("click", function () {
        if (!confirm(t("whitelist.confirm_delete"))) return;
        var rows = tabulator.getSelectedData();
        var macs = rows.map(function (r) { return r.mac; });
        kismet_whitelist_api.removeBulkFromWhitelist(macs);
        refreshTable();
    }));
    wrap.append(bulk);

    fileInput.on("change", function (e) {
        var f = e.target.files && e.target.files[0];
        if (!f) return;
        var reader = new FileReader();
        reader.onload = function () {
            var text = reader.result;
            var preview = String(text).split("\n").slice(0, 6).join("\n");
            var prevBox = $("<pre>").text(preview);
            showModal(t("whitelist.import_csv"), prevBox, function (done) {
                var res = kismet_whitelist_api.importFromCSV(String(text));
                alert(t("whitelist.import_success", { count: res.success }));
                if (res.errors.length) {
                    alert(res.errors.join("\n"));
                }
                refreshTable();
                done();
            });
        };
        reader.readAsText(f);
    });

    $.jsPanel({
        headerTitle: t("whitelist.title"),
        content: wrap,
        theme: "dark",
        width: $(window).width() * 0.85,
        height: $(window).height() * 0.75,
        callback: function () {
            tabulator = new Tabulator("#whitelist-table-host", {
                data: kismet_whitelist_api.getWhitelist(),
                layout: "fitColumns",
                selectable: true,
                columns: [
                    { field: "mac", title: t("whitelist.mac_address"), headerSort: true },
                    { field: "name", title: t("whitelist.device_name") },
                    { field: "category", title: t("whitelist.category") },
                    { field: "notes", title: t("whitelist.notes") },
                    { field: "added_date", title: t("whitelist.added_date") },
                    {
                        title: t("whitelist.edit"),
                        formatter: function () {
                            return "<button class='btn btn-primary'>" + t("whitelist.edit") + "</button>";
                        },
                        cellClick: function (e, cell) {
                            e.stopPropagation();
                            openEditDialog(cell.getRow().getData());
                        }
                    },
                    {
                        title: t("whitelist.delete"),
                        formatter: function () {
                            return "<button class='btn'>" + t("whitelist.delete") + "</button>";
                        },
                        cellClick: function (e, cell) {
                            e.stopPropagation();
                            if (confirm(t("whitelist.confirm_delete"))) {
                                kismet_whitelist_api.removeFromWhitelist(cell.getRow().getData().mac);
                                refreshTable();
                            }
                        }
                    }
                ]
            });
            function syncSel() {
                var n = tabulator.getSelectedData().length;
                $("#wl-selected-label").text(t("whitelist.selected_count", { count: n }));
                bulk.find("button").prop("disabled", n === 0);
            }
            tabulator.on("rowSelected", syncSel);
            tabulator.on("rowDeselected", syncSel);
        }
    });
}

function openEditDialog(existing) {
    var macInput = $("<input>", { type: "text" }).val(existing ? existing.mac : "");
    if (existing) macInput.prop("disabled", true);
    var nameInput = $("<input>", { type: "text" }).val(existing ? existing.name : "");
    var catSel = buildCategorySelect(existing ? existing.category : "pc");
    var notes = $("<textarea>").val(existing ? existing.notes : "");
    var box = $("<div>");
    box.append($("<label>").text(t("whitelist.mac_address"))).append(macInput);
    box.append($("<label>").text(t("whitelist.device_name"))).append(nameInput);
    box.append($("<label>").text(t("whitelist.category"))).append(catSel);
    box.append($("<label>").text(t("whitelist.notes"))).append(notes);
    showModal(existing ? t("whitelist.edit_title") : t("whitelist.add_title"), box, function (done) {
        var mac = macInput.val();
        if (!validateMac(mac)) {
            alert(t("common.error"));
            return;
        }
        try {
            if (existing) {
                kismet_whitelist_api.updateWhitelistEntry(mac, {
                    name: nameInput.val(),
                    category: catSel.val(),
                    notes: notes.val()
                });
            } else {
                kismet_whitelist_api.addToWhitelist({
                    mac: mac,
                    name: nameInput.val(),
                    category: catSel.val(),
                    notes: notes.val()
                });
            }
        } catch (e) {
            alert(t("common.error"));
            return;
        }
        refreshTable();
        done();
    });
}

exports.registerSidebar = function () {
    if (typeof kismet_ui_sidebar === "undefined") return;
    kismet_ui_sidebar.AddSidebarItem({
        id: "whitelist_manage",
        listTitle: "<i class=\"fa fa-shield\"></i> " + t("sidebar.whitelist_manage"),
        priority: -8,
        clickCallback: OpenWhitelistPanel
    });
};

return exports;

});
