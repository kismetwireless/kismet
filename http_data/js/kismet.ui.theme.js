/* jshint browser: true */
/* global define, module */
( // Module boilerplate to support browser globals and browserify and AMD.
  typeof define === "function" ? function (m) { define("kismet_theme", m); } :
  typeof exports === "object" ? function (m) { module.exports = m(); } :
  function(m){ this.kismet_theme = m(); }
)(function () {
    "use strict";

    var exports = {};

    var storage = Storages.localStorage;

    if (!storage.isSet('kismet.ui.theme') || (storage.isSet('kismet.ui.theme') && 
        storage.get('kismet.ui.theme') == 'dark')) { 

        $('head').append('<link rel="stylesheet" type="text/css" href="css/kismet-dark.css">');
        $('head').append('<link rel="stylesheet" type="text/css" href="css/dark.css">');
        $('head').append('<link rel="stylesheet" type="text/css" href="css/datatables-dark.css">');

        exports.theme = 'dark';

        exports.page_background = '#222';

        exports.sparkline_main = '#FFF';
        exports.sparkline_multi_a = '#F7FF00';
        exports.sparkline_multi_b = '#00FF00';

        Chart.defaults.backgroundColor = '#333';
        Chart.defaults.borderColor = '#555';
        Chart.defaults.color = '#FFF';

        exports.graphBasicColor = 'rgba(255, 255, 255, 1)';
        exports.graphBasicBackgroundColor = 'rgba(200, 200, 200, 0.33)',

        document.documentElement.setAttribute('data-theme', 'dark');
    } else { 
        $('head').append('<link rel="stylesheet" type="text/css" href="css/light.css">');
        $('head').append('<link rel="stylesheet" type="text/css" href="css/jquery-ui.min.css">');
        $('head').append('<link rel="stylesheet" type="text/css" href="css/datatables.min.css">');
        $('head').append('<link rel="stylesheet" type="text/css" href="css/kismet.css">');

        exports.theme = 'light';

        exports.page_background = '#FFF';
        exports.sparkline_multi_a = '#C70039';
        exports.sparkline_multi_b = '#002EFF';

        exports.sparkline_main = '#000';

        exports.graphBasicColor = 'rgba(160, 160, 160, 1)';
        exports.graphBasicBackgroundColor = 'rgba(100, 100, 100, 0.33)';

        // document.documentElement.setAttribute('data-theme', 'light');
    }

    (function ($) {
        var element = null;
        var ticon;

        $.fn.thememode = function(_data, inopt) {
            element = $(this);

            ticon = $('i.icon', this);
            if (ticon.length == 0) {
                ticon = $('<i>', {
                    class: "icon fa clickable kg-icon-base"
                })
                .on('click', () => { 
                    if (exports.theme === 'dark') { 
                        storage.set('kismet.ui.theme', 'light');
                        location.reload();
                    } else {
                        storage.set('kismet.ui.theme', 'dark');
                        location.reload();
                    }
                });

                if (exports.theme === 'dark') { 
                    ticon.addClass('fa-moon-o');
                } else { 
                    ticon.addClass('fa-lightbulb-o');
                }
            }

            element.append(ticon);
        };

    }(jQuery));

    return exports;
});
