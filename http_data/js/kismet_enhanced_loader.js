(
    typeof define === "function" ? function (m) { define("kismet-enhanced-loader-js", m); } :
    typeof exports === "object" ? function (m) { module.exports = m(); } :
    function (m) { this.kismet_enhanced_loader = m(); }
)(function () {

"use strict";

/* Loads after: kismet_i18n, kismet_whitelist_api, kismet_ui_signal_filter,
 * kismet_ui_signal_monitor, kismet_ui_export, kismet_ui_whitelist,
 * kismet_ui_unassociated, kismet_ui_enhanced (see index.html script order). */

var exports = {};

var local_uri_prefix = "";
if (typeof KISMET_URI_PREFIX !== "undefined") {
    local_uri_prefix = KISMET_URI_PREFIX;
}

$("<link>")
    .appendTo("head")
    .attr({
        type: "text/css",
        rel: "stylesheet",
        href: local_uri_prefix + "css/kismet_enhanced.css"
    });

window.kismet_enhanced_run_async = function () {
    if (typeof kismet_i18n === "undefined" || !kismet_i18n.initI18n) {
        console.error("kismet_enhanced_loader: kismet_i18n missing");
        return Promise.resolve();
    }
    return kismet_i18n.initI18n()
        .then(function () {
            try {
                if (typeof kismet_ui_whitelist_module !== "undefined" && kismet_ui_whitelist_module.registerSidebar) {
                    kismet_ui_whitelist_module.registerSidebar();
                }
            } catch (e) {
                console.error("whitelist sidebar", e);
            }
            try {
                if (typeof kismet_ui_unassociated_module !== "undefined" && kismet_ui_unassociated_module.registerSidebar) {
                    kismet_ui_unassociated_module.registerSidebar();
                }
            } catch (e) {
                console.error("unassociated sidebar", e);
            }
            try {
                if (typeof kismet_ui_enhanced_module !== "undefined" && kismet_ui_enhanced_module.registerEnhanced) {
                    kismet_ui_enhanced_module.registerEnhanced();
                }
            } catch (e) {
                console.error("enhanced ui", e);
            }
            document.dispatchEvent(new CustomEvent("kismet-enhanced-ready"));
        })
        .catch(function (err) {
            console.error("kismet_enhanced_loader init failed", err);
        });
};

return exports;

});
