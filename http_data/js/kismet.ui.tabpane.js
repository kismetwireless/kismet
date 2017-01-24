(
  typeof define === "function" ? function (m) { define("kismet-ui-tabpane-js", m); } :
  typeof exports === "object" ? function (m) { module.exports = m(); } :
  function(m){ this.kismet_ui_tabpane = m(); }
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
        href: '/css/kismet.ui.tabpane.css'
    });

/* List of objects used to turn into tabs */
var TabItems = new Array();

/* Add a tab
 *
 * Options is a dictionary which must include:
 *
 * id: id for created div
 * tabTitle: Title show in tab bar
 * createCallback: function called after the div is created, passed the new div
 *
 * priority: order priority in list (optional)
 */
exports.AddTab = function(options) {
    if (! 'id' in options ||
        ! 'tabTitle' in options ||
        ! 'createCallback' in options) {
        return;
    }

    if (! 'priority' in options) {
        options.priority = 0;
    }

    TabItems.push(options);
};

function createListCallback(c) {
    return function() {
        c.createCallback();
    };
}

function populateList(div) {
    TabItems.sort(function(a, b) {
        if (a.priority < b.priority)
            return -1;
        if (a.priority > b.priority)
            return 1;

        return 0;
    });

    div.empty();

    var ul = $('<ul>', {
            id: 'tabpane_ul'
        });

    div.append(ul);

    for (var i in TabItems) {
        var c = TabItems[i];

        ul.append(
            $('<li>', { })
            .append(
                $('<a>', {
                    href: '#' + c.id
                })
                .html(c.tabTitle)
            )
        );

        var td = 
            $('<div>', {
                id: c.id
            });

        div.append(td);

        c.createCallback(td);
    }

    div.tabs({
        heightStyle: 'fill',
        activate: function(e, ui) {
            var id = $('a', ui.newTab).attr('href');
            kismet.putStorage('kismet.base.last_tab', id);
        }
    });

    var lasttab = kismet.getStorage('kismet.base.last_tab', '');
    $('a[href="' + lasttab + '"]', div).click();
}

// Populate the sidebar content in the supplied div
exports.MakeTabPane = function(div) {
    populateList(div);
};

// We're done loading
exports.load_complete = 1;

return exports;

});
