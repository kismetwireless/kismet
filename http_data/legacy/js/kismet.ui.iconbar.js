(
  typeof define === "function" ? function (m) { define("kismet-ui-iconbar-js", m); } :
  typeof exports === "object" ? function (m) { module.exports = m(); } :
  function(m){ this.kismet_ui_iconbar = m(); }
)(function () {

"use strict";

var exports = {};

var local_uri_prefix = ""; 
if (typeof(KISMET_URI_PREFIX) !== 'undefined')
    local_uri_prefix = KISMET_URI_PREFIX;

// Flag we're still loading
exports.load_complete = 0;

// Load our css
$('<link>')
    .appendTo('head')
    .attr({
        type: 'text/css', 
        rel: 'stylesheet',
        href: local_uri_prefix + 'css/kismet.ui.iconbar.css'
    });

/* Iconbar items are stored as a list of objects with callbacks for when they
 * are created */

var IconbarItems = new Array();

/* Add an iconbar item
 *
 * 'options' is a dictionary which must include:
 *
 * id: id for created object/div
 * createCallback(div): function for populating the div
 *
 * and may include:
 *
 * priority: order priority in list
 *
 */

exports.AddIconbarItem = function(options) {
    if (!('id' in options) ||
        !('createCallback' in options)) {
        return;
    }

    if (!('priority' in options)) {
        options['priority'] = 0;
    }

    options['visible'] = true;

    IconbarItems.push(options);
}

exports.makeIconbar = function(container) {
    var saved_state = kismet.getStorage('kismet.base.iconbar', {});

    // Update any item status based on saved config
    for (var ii in IconbarItems) {
        var ibi = IconbarItems[ii];

        if (ibi.id in saved_state) {
            ibi.priority = saved_state[ibi.id].priority;
            ibi.visibile = saved_state[ibi.id].visible;
        } else {
            ibi.visible = true;
        }
    }

    // Sort by priority
    IconbarItems.sort(function(a, b) {
        if (a.priority < b.priority)
            return -1;
        if (a.priority > b.priority)
            return 1;
        return 0;
    });

    // Wipe out the existing div
    container.empty();

    for (var ii in IconbarItems) {
        var ibi = IconbarItems[ii];

        if (!ibi.visible)
            continue;

        var div = 
            $('<div>', {
                id: ibi.id,
                class: 'k-ib-item',
            });

        container.append(div);
        ibi.createCallback(div);
    }
}


// We're done loading
exports.load_complete = 1;

return exports;

});
