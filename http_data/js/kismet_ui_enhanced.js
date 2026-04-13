(
    typeof define === "function" ? function (m) { define("kismet-ui-enhanced-js", m); } :
    typeof exports === "object" ? function (m) { module.exports = m(); } :
    function (m) { this.kismet_ui_enhanced_module = m(); }
)(function () {

"use strict";

var exports = {};

function t(k, o) {
    return (typeof kismet_i18n !== "undefined" && kismet_i18n.t) ? kismet_i18n.t(k, o) : k;
}

exports.registerEnhanced = function () {
    if (typeof kismet_ui === "undefined") return;

    kismet_ui.AddDeviceColumn("column_whitelist_status", {
        title: t("whitelist.status"),
        description: "Whitelist status",
        field: "kismet.device.base.macaddr",
        sortable: true,
        searchable: false,
        render: function (data, row, cell, onrender, aux) {
            var mac = data;
            if (typeof kismet_whitelist_api !== "undefined" && kismet_whitelist_api.isWhitelisted(mac)) {
                return "<span class=\"whitelist-status-icon whitelist-approved\"><i class=\"fa fa-check\"></i></span>";
            }
            return "<span class=\"whitelist-status-icon whitelist-unknown\"><i class=\"fa fa-exclamation-triangle\"></i></span>";
        }
    });

    kismet_ui.AddDeviceRowHighlight({
        name: "Unassociated Probing Client",
        description: t("unassociated.description"),
        priority: 20,
        defaultcolor: "#FFA500",
        defaultenable: true,
        fields: ["dot11.device/dot11.device.type_set", "dot11.device/dot11.device.associated_client_map"],
        selector: function (data) {
            var ts = data["dot11.device.type_set"];
            if (ts == null && data["dot11.device"] && data["dot11.device"]["dot11.device.type_set"]) {
                ts = data["dot11.device"]["dot11.device.type_set"];
            }
            var hasProbing = false;
            if (Array.isArray(ts)) hasProbing = ts.indexOf("probing") >= 0;
            else if (typeof ts === "string") hasProbing = ts.indexOf("probing") >= 0;
            var assoc = data["dot11.device.associated_client_map"];
            if (!assoc && data["dot11.device"]) {
                assoc = data["dot11.device"]["dot11.device.associated_client_map"];
            }
            var emptyAssoc = !assoc || (typeof assoc === "object" && Object.keys(assoc).length === 0);
            return hasProbing && emptyAssoc;
        }
    });

    kismet_ui.AddDeviceRowHighlight({
        name: "Unknown Device (Not Whitelisted)",
        description: t("whitelist.unknown"),
        priority: 15,
        defaultcolor: "#FFCCCC",
        defaultenable: false,
        fields: ["kismet.device.base.macaddr"],
        selector: function (data) {
            var mac = data["kismet.device.base.macaddr"];
            if (!mac || typeof kismet_whitelist_api === "undefined") return false;
            return !kismet_whitelist_api.isWhitelisted(mac);
        }
    });

    if (typeof kismet_ui_settings !== "undefined") {
        kismet_ui_settings.AddSettingsPane({
            id: "language_settings",
            listTitle: t("settings.language"),
            create: function (content) {
                content.empty();
                var p = $("<p>").text(t("settings.language_desc"));
                var sel = $("<select>", { id: "kismet-lang-select" });
                sel.append($("<option>", { value: "en" }).text("English"));
                sel.append($("<option>", { value: "ja" }).text("Japanese"));
                sel.val(kismet_i18n.getCurrentLanguage());
                content.append(p).append(sel);
            },
            save: function () {
                var v = $("#kismet-lang-select").val();
                return kismet_i18n.changeLanguage(v);
            },
            priority: -10
        });
    }
};

return exports;

});
