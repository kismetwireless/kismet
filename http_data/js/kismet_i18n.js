(
    typeof define === "function" ? function (m) { define("kismet-i18n-js", m); } :
    typeof exports === "object" ? function (m) { module.exports = m(); } :
    function (m) { this.kismet_i18n = m(); }
)(function () {

"use strict";

var exports = {};

var local_uri_prefix = "";
if (typeof KISMET_URI_PREFIX !== "undefined") {
    local_uri_prefix = KISMET_URI_PREFIX;
}

function uriForLocale(lng) {
    return local_uri_prefix + "locales/" + lng + "/translation.json";
}

exports.initI18n = function () {
    return new Promise(function (resolve, reject) {
        var detected = "en";
        try {
            if (localStorage.getItem("i18nextLng")) {
                detected = localStorage.getItem("i18nextLng");
            } else if (navigator.language) {
                detected = navigator.language.split("-")[0];
            }
        } catch (e) {
            detected = "en";
        }

        function loadJson(url) {
            return fetch(url, { credentials: "same-origin" }).then(function (r) {
                if (!r.ok) throw new Error(String(r.status));
                return r.json();
            });
        }

        Promise.all([
            loadJson(uriForLocale("en")).catch(function () { return {}; }),
            loadJson(uriForLocale("ja")).catch(function () { return {}; })
        ]).then(function (bundles) {
            var enTr = bundles[0];
            var jaTr = bundles[1];
            var lng = detected;
            if (lng !== "en" && lng !== "ja") {
                lng = "en";
            }
            var resources = {
                en: { translation: enTr },
                ja: { translation: jaTr }
            };
            if (!window.i18next || !window.i18next.init) {
                reject(new Error("i18next not loaded"));
                return;
            }
            return window.i18next.init({
                lng: lng,
                fallbackLng: "en",
                resources: resources
            }, function () {
                try {
                    localStorage.setItem("i18nextLng", lng);
                } catch (e2) { /* ignore */ }
                document.dispatchEvent(new CustomEvent("kismet-i18n-ready", { detail: { lng: lng } }));
                resolve();
            });
        }).catch(function (err) {
            reject(err);
        });
    });
};

exports.t = function (key, opts) {
    if (window.i18next && typeof window.i18next.t === "function") {
        return window.i18next.t(key, opts);
    }
    return key;
};

exports.changeLanguage = function (lng) {
    if (window.i18next && typeof window.i18next.changeLanguage === "function") {
        return window.i18next.changeLanguage(lng).then(function () {
            try {
                localStorage.setItem("i18nextLng", lng);
            } catch (e) { /* ignore */ }
            window.location.reload();
        });
    }
    return Promise.resolve();
};

exports.getCurrentLanguage = function () {
    if (window.i18next && window.i18next.language) {
        return window.i18next.language;
    }
    try {
        return localStorage.getItem("i18nextLng") || "en";
    } catch (e) {
        return "en";
    }
};

return exports;

});
