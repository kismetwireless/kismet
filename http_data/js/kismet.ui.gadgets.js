(
  typeof define === "function" ? function (m) { define("kismet-ui-gadgets-js", m); } :
  typeof exports === "object" ? function (m) { module.exports = m(); } :
  function(m){ this.kismet_ui_gadgets = m(); }
)(function () {

"use strict";

var exports = {};

// Flag we're still loading
exports.load_complete = 0;

// Load our css
$('<link>')
    .appendTo('head')
    .attr({
        type: 'text/css', 
        rel: 'stylesheet',
        href: '/css/kismet.ui.gadgets.css'
    });

var gadgets = new Array();

var active_gadgets = new Array();

/* Options for gadgets:
 * id           unique id of gadget
 * priority     priority of gadget order
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

    saved_gadgets.every(function(e) {
        // Malformed setting
        if (!('id' in e))
            return true;

        if (!('visible' in e))
            return true;

        // Find the gadget by saved id
        var g = gadgets.find(function(gi) {
            return (e.id === gi.id);
        });

        // Skip gadgets we don't know about anymore
        if (g === undefined)
            return true;

        // Add to the list
        newgadgets.push({
            id: g.id,
            gadget: g,
            visible: e.visisble
        });
    });

    // Add any unknown gadgets to the list
    gadgets.every(function(e) {
        var g = newgadgets.find(function(ng) {
            return (e.id === ng.id);
        });

        if (g === undefined) {
            newgadgets.push({
                id: g.id,
                gadget: g,
                visisble: true
            });
        }
    });

    active_gadgets = newgadgets;
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
