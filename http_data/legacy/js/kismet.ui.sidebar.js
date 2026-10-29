(
  typeof define === "function" ? function (m) { define("kismet-ui-sidebar-js", m); } :
  typeof exports === "object" ? function (m) { module.exports = m(); } :
  function(m){ this.kismet_ui_sidebar = m(); }
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
        href: local_uri_prefix + 'css/kismet.ui.sidebar.css'
    });

/* Sidebar items are stored as a list of objects defining callbacks which
 * allow us to create the entries and map clicks */

var SidebarItems = new Array();

/* Add a sidebar item
 *
 * Options is a dictionary which must include:
 *
 * id: id for created div
 * listTitle: Title shown in list, which can include HTML for improved icons
 * clickCallback: function in for handling a click event
 *
 * priority: order priority in list (optional)
 */
exports.AddSidebarItem = function(options) {
    if (!('id' in options) ||
        !('listTitle' in options) ||
        !('clickCallback' in options)) {
        return;
    }

    if (!('priority' in options)) {
        options['priority'] = 0;
    }

    SidebarItems.push(options);
};

function createListCallback(c) {
    return function() {
        // Hack closing the sidemenu
        $('.pm_overlay').click();
        c.clickCallback();
    };
}

function populateList(list) {
    SidebarItems.sort(function(a, b) {
        if (a.priority < b.priority)
            return -1;
        if (a.priority > b.priority)
            return 1;

        return 0;
    });

    for (var i in SidebarItems) {
        var c = SidebarItems[i];
        list.append(
            $('<div>', {
                id: c.id,
                class: 'k-sb-list-item'
            })
            .html(c.listTitle)
            .on('click', createListCallback(c))
        );
    }
}

// Populate the sidebar content in the supplied div
exports.MakeSidebar = function(div) {
    populateList(div);
};

// We're done loading
exports.load_complete = 1;

return exports;

});
