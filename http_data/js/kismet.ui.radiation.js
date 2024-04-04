
"use strict";

var local_uri_prefix = ""; 
if (typeof(KISMET_URI_PREFIX) !== 'undefined')
    local_uri_prefix = KISMET_URI_PREFIX;

$('<link>')
    .attr({
        type: 'text/css', 
        rel: 'stylesheet',
        href: local_uri_prefix + 'css/kismet.ui.radiation.css'
    })
    .appendTo('head');

kismet_ui_sidebar.AddSidebarItem({
    id: 'radiation_sidebar',
    listTitle: '<i class="fa fa-circle-radiation"></i> Radiation',
    clickCallback: function() {
        radiationWindow();
    },
});

var rad_update_tid;
var rad_panel = null;
var rad_hps_chart = null;
var rad_usv_chart = null;
var rad_spectrum_chart = null;
var rad_content = 
    $('<div class="k-rad-contentdiv">')
    .append($('<canvas>', {
        id: 'k-rad-spectrum-canvas',
        class: 'k-rad-spectrum-canvas',
    }));


function radiationWindow() {
    let w = $(window).width() * 0.75;
    let h = $(window).height() * 0.5;
    let offty = 20;

    if ($(window).width() < 450 || $(window).height() < 450) {
        w = $(window).width() - 5;
        h = $(window).height() - 5;
        offty = 0;
    }

    rad_panel = $.jsPanel({
        id: 'radiation',
        headerTitle: '<i class="fa fa-circle-radiation"></i> Radiation',
        headerControls: {
            controls: 'closeonly',
            iconfont: 'jsglyph',
        },
        content: rad_content,
        onclosed: () => {
            clearTimeout(rad_update_tid);
            rad_spectrum_chart = null;
        },
    }).resize({
        width: w,
        height: h
    }).reposition({
        my: 'center-top',
        at: 'center-top',
        of: 'window',
        offsetY: offty
    })
    .front();

    updateRadiationData();
}

function updateRadiationData() {
    clearTimeout(rad_update_tid);

    $.get(local_uri_prefix + "radiation/sensors/all_sensors.json")
    .done(function(data) {
        data = kismet.sanitizeObject(data);

        for (const sk in data) {
            var datasets = [
                {
                    label: sk,
                    data: data[sk]['radiation.sensor.aggregate_spectrum'],
                }
            ];

            if (rad_spectrum_chart == null) {
                var canvas = $('#k-rad-spectrum-canvas');

                // We need to fill the labels even though we don't use them
                var labels = Array.apply(null, Array(500)).map(function (x, i) { return i; })

                rad_spectrum_chart = new Chart(canvas, {
                    type: 'bar',
                    data: {
                        labels: labels,
                        datasets: datasets,
                    },
                    options: {
                        animation: false,
                        responsive: true,
                        maintainAspectRatio: false,
                        scales: {
                            y: {
                                title: {
                                    text: 'Count',
                                    display: true,
                                },
                                ticks: {
                                    display: false,   
                                },
                            },
                            x: {
                                title: {
                                    text: 'Energy',
                                    display: true,
                                },
                                ticks: {
                                    display: false,   
                                },
                            }
                        },
                    },
                });
            } else {
                rad_spectrum_chart.data.datasets[0].data = data[sk]['radiation.sensor.aggregate_spectrum'];
                rad_spectrum_chart.update('none');
            }
        }
    })
    .always(() => {
        rad_update_tid = setTimeout(() => {
            updateRadiationData();
        }, 1000)
    });
}
