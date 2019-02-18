(
  typeof define === "function" ? function (m) { define("kismet-ui-gadgets-js", m); } :
  typeof exports === "object" ? function (m) { module.exports = m(); } :
  function(m){ this.kismet_ui_gadgets = m(); }
)(function () {

"use strict";

var exports = {};

// Flag we're still loading
exports.load_complete = 0;

var local_uri_prefix = ""; 
if (typeof(KISMET_URI_PREFIX) !== 'undefined')
    local_uri_prefix = KISMET_URI_PREFIX;

// Load our css
$('<link>')
    .appendTo('head')
    .attr({
        type: 'text/css', 
        rel: 'stylesheet',
        href: local_uri_prefix + 'css/kismet.ui.gadgets.css'
    });

// Defined gadgets
var gadgets = new Array();

// User picked gadgets
var active_gadgets = new Array();

/* Options for gadgets:
 * id           unique id of gadget
 * priority     priority of gadget order
 * fields       *array* of fields required by this gadget, merged into the request
 * defaultenable optional bool, if the gadget is not disabled in the user preferences,
 *              enable it by default
 * drawfunc     function called for drawing, with arguments:
 *              container - div for the widget
 *              data - data for this row
 */

exports.AddGadget = function(options) {
    if (!('id' in options)) {
        console.log("Missing ID in gadget");
        return -1;
    }

    if (!('drawfunc' in options)) {
        console.log("Missing drawfunc in gadget");
        return -1;
    }

    if (!('priority' in options)) {
        options.priority = 0;
    }

    if (!('defaultenable' in options)) {
        options.defaultenable = false;
    }

    if (!('fields' in options)) {
        options.fields = [];
    }

    gadgets.push(options);

    exports.UpdateGadgets();
};

exports.UpdateGadgets = function() {
    var newgadgets = new Array();

    gadgets.sort(function(a, b) {
        if (a.priority < b.priority)
            return -1;
        if (a.priority > b.priority)
            return 1;

        return 0;
    });

    // Load the saved gadgets
    var saved_gadgets = kismet.getStorage('kismet.base.gadgets', []);

    // Search through the saved gadgets and populate gadgets we know about
    saved_gadgets.every(function(e) {
        // Corrupt pref
        if (!('id' in e))
            return true;

        // Find the gadget by saved id
        var g = gadgets.find(function(gi) {
            return (e.id === gi.id);
        });

        // Skip gadgets we don't know about anymore
        if (g === undefined)
            return true;

        // Add to the list, cloning the object
        newgadgets.push(g);
    });

    // Add any unknown gadgets to the list and mark their default visibility
    unknowng = [];

    gadgets.every(function(e) {
        // Look for this ID in our active gadgets
        var g = newgadgets.find(function(ng) {
            return (e.id === ng.id);
        });

        if (g === undefined) {
            unknowng.push(e);
        }
    });

    // Concatenate
    active_gadgets = newgadgets.concat(unknowng);

    active_gadgets.sort(function(a, b) {
        if (a.priority < b.priority)
            return -1;
        if (a.priority > b.priority)
            return 1;

        return 0;
    });
}

var renderGadgets = function(d, t, r, m) {

}

kismet_ui.AddDeviceColumn('column_gadget', {
    sTitle: ' ',
    field: 'kismet.device.base.name',
    description: 'UI gadgets',
    renderfunc: function(d, t, r, m) {
        renderGadgets(d, t, r, m);
    },
    orderable: false,
    searchable: false,
    priority: -1000,
});
        

// We're done loading
exports.load_complete = 1;

return exports;

});
