(
  typeof define === "function" ? function (m) { define("kismet-ui-tabpane-js", m); } :
  typeof exports === "object" ? function (m) { module.exports = m(); } :
  function(m){ this.kismet_ui_tabpane = m(); }
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
        href: local_uri_prefix + 'css/kismet.ui.tabpane.css'
    });

var tabholders = {};

/* Add a tab
 *
 * By default adds to the 'south' container, which previously was the only tab holder available.
 *
 * Options is a dictionary which must include:
 *
 * id: id for created div
 * tabTitle: Title show in tab bar
 * createCallback: function called after the div is created, passed the new div
 *
 * priority: order priority in list (optional)
 */
exports.AddTab = function(options, group="south") {
    if (!('id' in options) ||
        !('tabTitle' in options) ||
        !('createCallback' in options)) {
        return;
    }

    if (!('priority' in options)) {
        options.priority = 0;
    }

    if (!('expandable' in options)) {
        options.expandable = false;
    }

    if (!('expandCallback' in options)) {
        options.expandCallback = null;
    }

    options.expanded = false;

    if (group in tabholders) {
        for (var x = 0; x < tabholders[group].TabItems.length; x++) {
            if (tabholders[group].TabItems[x].id == options["id"]) {
                tabholders[group].TabItems.splice(x, 1);
                break;
            }
        }

        tabholders[group].TabItems.push(options);
    } else {
        tabholders[group] = {
            TabItems: [options],
        };
    }
};

exports.RemoveTab = function(id, group="south") {
    try {
        for (var x = 0; x < tabholders[group].TabItems.length; x++) {
            if (tabholders[group].TabItems[x].id == id) {
                tabholders[group].TabItems.splice(x, 1);
                break;
            }
        }
    } catch (error) {
        alert(`UI attempted to remove tab ${id} from invalid group ${group}`);
    }
}

function createListCallback(c) {
    return function() {
        c.createCallback();
    };
}

function createExpanderCallback(c, group) {
    return function() {
        MoveToExpanded(c, group);
    }
}

function populateList(div, group) {
    if (group in tabholders) {
        tabholders[group].TabDiv = div;
    } else {
        tabholders[group] = {
            TabDiv: div,
            TabItems: []
        };
    }

    tabholders[group].TabItems.sort(function(a, b) {
        if (a.priority < b.priority)
            return -1;
        if (a.priority > b.priority)
            return 1;

        return 0;
    });

    div.empty();

    var ul = $('<ul>', {
            id: `tabpane_ul_${group}`
        });

    div.append(ul);

    for (var i in tabholders[group].TabItems) {
        var c = tabholders[group].TabItems[i];

        var title = c.tabTitle;;

        if (c.expandable) {
            title += ' <i class="fa fa-expand pseudolink"></i>';
        }

        ul.append(
            $('<li>', { })
            .append(
                $('<a>', {
                    href: '#' + c.id
                })
                .html(title)
            )
        );

        $('i', ul).tooltipster({content: 'Expand tab to own window'});

        if (c.expandable) {
            $('i', ul).on('click', createExpanderCallback(c, group));
        }

        var td =
            $('<div>', {
                id: c.id
            });

        div.append(td);

        c['content'] = td;

        c.createCallback(td);
    }

    div.tabs({
        heightStyle: 'fill',
        activate: function(e, ui) {
            var id = $('a', ui.newTab).attr('href');
            kismet.putStorage(`kismet.base.${group}.last_tab`, id);
        }
    });

    var lasttab = kismet.getStorage(`kismet.base.${group}.last_tab`, '');
    $('a[href="' + lasttab + '"]', div).click();
}

function MoveToExpanded(tab, group) {
    var div = $('div#' + tab.id, tabholders[group].TabDiv);

    var placeholder = $('<div>', {
        id: 'original_' + tab.id,
    })
    .html("Content moved to window");

    var original = div;

    var panelcontainer =
        $('<div>', {
            id: 'panel',
            height: '100%',
            width: '100%',
        })
        .append($('<div>', {
            id: 'target',
        }));

    tab.jspanel = $.jsPanel({
        id: 'tab_' + tab.id,
        headerTitle: tab.tabTitle,
        headerControls: {
            iconfont: 'jsglyph',
        },
        content: panelcontainer,
        onclosed: function() {
            placeholder.replaceWith(original);
            tabholders[group].TabDiv.tabs("refresh");
        },
    });

    div.replaceWith(placeholder);

    // Take out the fixed height and width imposed by tab width
    original.removeProp('height');
    original.removeProp('width');
    original.css('height', '');
    original.css('width', '');

    $('#target', panelcontainer).replaceWith(original);

    original.resize();

    var w = $(window).width() * 0.75;
    var h = $(window).height() * 0.5;
    var offty = 20;

    if ($(window).width() < 450 || $(window).height() < 450) {
        w = $(window).width() - 5;
        h = $(window).height() - 5;
        offty = 0;
    }

    tab.jspanel.resize({
        width: w,
        height: h,
    })
    .reposition({
        my: 'center-top',
        at: 'center-top',
        of: 'window',
        offsetY: offty
    });

    // Call the tab expansion callback
    if (('expandCallback' in tab) && tab['expandCallback'] != null) {
        tab['expandCallback'](jspanel);
    }

}

// Populate the sidebar content in the supplied div
exports.MakeTabPane = function(div, group) {
    populateList(div, group);
};

// We're done loading
exports.load_complete = 1;

return exports;

});
