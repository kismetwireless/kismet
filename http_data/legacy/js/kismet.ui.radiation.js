
"use strict";

let local_uri_prefix = "";
if (typeof(KISMET_URI_PREFIX) !== 'undefined')
    local_uri_prefix = KISMET_URI_PREFIX;

$('<link>')
    .attr({
        type: 'text/css', 
        rel: 'stylesheet',
        href: local_uri_prefix + 'css/kismet.ui.radiation.css'
    })
    .appendTo('head');

kismet_ui_iconbar.AddIconbarItem({
    id: 'radiation',
    priority: 1,
    createCallback: (div) => {
        div.append('<div id="radiation-toolbar-sideby" class="rad-side"></div>')

        $('#radiation-toolbar-sideby', div).append('<div id="radiation-toolbar-cps-stack" class="rad-dual-stack"><div id="radiation-toolbar-cps" class="radiation-toolbar-cps">n/a</div><div>CPS</div></div>');

        $('#radiation-toolbar-sideby', div).append('<div id="radiation-toolbar-usv-stack" class="rad-dual-stack"><div id="radiation-toolbar-usv" class="radiation-toolbar-usv">n/a</div><div>uSv</div></div>');

        let show_cps = kismet.getStorage('kismet.ui.radiation.showcps', false);
        let show_usv = kismet.getStorage('kismet.ui.radiation.showusv', false);

        if (!show_cps) {
            $('#radiation-toolbar-cps-stack', div).hide();
        }

        if (!show_usv) {
            $('#radiation-toolbar-usv-stack', div).hide();
        }

        kismet_ui_base.SubscribeEventbus("RADIATION", [], (data) => {
            let show_cps = kismet.getStorage('kismet.ui.radiation.showcps', false);
            let show_usv = kismet.getStorage('kismet.ui.radiation.showusv', false);

            if (!show_cps) {
                $('#radiation-toolbar-cps-stack', div).hide();
            } else {
                $('#radiation-toolbar-cps-stack', div).show();
            }

            if (!show_usv) {
                $('#radiation-toolbar-usv-stack', div).hide();
            } else {
                $('#radiation-toolbar-usv-stack', div).show();
            }

            let max_cps = 0;
            let max_usv = 0;

            for (const di in data) {
                const d = data[di];

                let cps = d['radiation.sensor.cps_rrd']['kismet.common.rrd.last_value'];
                let usv = d['radiation.sensor.usv_rrd']['kismet.common.rrd.last_value'];

                if (max_cps < cps) {
                    max_cps = cps;
                }

                if (max_usv < usv) {
                    max_usv = usv;
                }
            }

            $('#radiation-toolbar-cps').html(max_cps.toFixed(2));
            $('#radiation-toolbar-usv').html(max_usv.toFixed(2));
        })
    }
})

kismet_ui_sidebar.AddSidebarItem({
    id: 'radiation_sidebar',
    listTitle: '<i class="fa fa-circle-radiation"></i> Radiation',
    clickCallback: function() {
        radiationWindow();
    },
});

kismet_ui_settings.AddSettingsPane({
    id: 'radiation',
    listTitle: 'Radiation Sensors',
    create: (elem) => {
        elem.append('<form><fieldset id="fs_rad"><legend>Radiation Sensors</legend><div id="radconfig"></div></fieldset></form>');

        let config = $('#radconfig', elem);

        config.append('<p><b>CAUTION</b>: Radiation exposure counts and dosages are dependent on the radiation detector used.  Most radiation detectors have maximum speeds at which detection can reliably occur.  Each radiation detectors <i>must be properly calibrated</i> and properly oriented for detection.</p>');
        config.append('<p><i>BE SAFE.</i>  <b>NEVER</b> trust the Kismet display of radiation data for personal safety!</p>');

        config.append('<div><input type="checkbox" id="r_showcps"><label for="r_showcps">Show counts per second in toolbar</label></div>');
        config.append('<div><input type="checkbox" id="r_showusv"><label for="r_showusv">Show uSv per second in toolbar</labeln></div>');

        let show_cps = kismet.getStorage('kismet.ui.radiation.showcps', false);
        let show_usv = kismet.getStorage('kismet.ui.radiation.showusv', false);

        if (show_cps) {
            $('#r_showcps', elem).prop('checked', 'checked');
        }

        if (show_usv) {
            $('#r_showusv', elem).prop('checked', 'checked');
        }

        $('#r_showcps', elem).checkboxradio();
        $('#r_showusv', elem).checkboxradio();

        $('form', elem).on('change', () => {
            kismet_ui_settings.SettingsModified();
        });

    },
    save: (elem) => {
        kismet.putStorage('kismet.ui.radiation.showcps', $('#r_showcps', elem).is(':checked'));
        kismet.putStorage('kismet.ui.radiation.showusv', $('#r_showusv', elem).is(':checked'));
        
    }
})

let rad_update_tid;
let rad_panel = null;

/*
var rad_content = 
    $('<div class="k-rad-contentdiv">')
    .append($('<div>Counts per Second (CPS)</div>'))
    .append($('<canvas>', {
        id: 'k-rad-cps-canvas',
        class: 'k-rad-cps-canvas',
    }))
    .append($('<div>Dose per Second (uSv)</div>'))
    .append($('<canvas>', {
        id: 'k-rad-usv-canvas',
        class: 'k-rad-usv-canvas',
    }))
    .append($('<div>Energy Spectrum</div>'))
    .append($('<canvas style="width: 100%; height: 200px;">', {
        id: 'k-rad-spectrum-canvas',
        class: 'k-rad-spectrum-canvas',
    }));
    */
let rad_content =
    $('<div class="k-rad-contentdiv"><div id="rad-tabs" class="tabs-min"></div>');

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
        id: 'radiation-panel',
        headerTitle: '<i class="fa fa-circle-radiation"></i> Radiation',
        headerControls: {
            controls: 'closeonly',
            iconfont: 'jsglyph',
        },
        content: rad_content,
        onclosed: () => {
            clearTimeout(rad_update_tid);
            rad_panel = null;
        },
        resizable: {
            stop: function(event, ui) {
                let tabs = $('#rad-tabs', this.content);
                try {
                    tabs.tabs('refresh');
                } catch (e) { }
            }
        },
    }).resize({
        width: w,
        height: h,
    }).reposition({
        my: 'center-top',
        at: 'center-top',
        of: 'window',
        offsetY: offty,
    })
    .front();

    rad_panel.rad_spectrum_chart = null;

    rad_panel.rad_cps_chart_m = null;
    rad_panel.rad_cps_chart_h = null;
    rad_panel.rad_cps_chart_d = null;

    rad_panel.rad_usv_chart_m = null;
    rad_panel.rad_usv_chart_h = null;
    rad_panel.rad_usv_chart_d = null;

    kismet_ui_tabpane.AddTab({
        id: 'rad-summary',
        tabTitle: 'Summary',
        createCallback: (div) => {
            div.append($('<div>', {
                class: 'rad-flex-stack rad-flex-box',
            })
                .append($('<div>', {
                    class: 'rad-flex-row',
                })
                    .append($('<div>', {
                        class: 'rad-flex-header',
                    }).html('Counts Per Second'))
                    .append($('<div>', {
                            id: 'rad-summary-cps',
                        }))
                )

                .append($('<div>', {
                        class: 'rad-flex-row',
                    })
                        .append($('<div>', {
                            class: 'rad-flex-header',
                        }).html('Dosage (uSv)'))
                        .append($('<div>', {
                            id: 'rad-summary-usv',
                        }))
                )
            )
            div.append($('<div>', {
                class: 'rad-flex-stack rad-flex-box',
            })
                .append($('<p>'))
                .append($('<p>').html('<b>CPS</b> or <b>Counts Per Second</b> is a raw count of events per second ' +
                'registered by a radiation detector.  Different sensors are sensitive to particles of different ' +
                'energy levels, and may be more sensitive to some energy levels than others.'))
                .append($('<p>').html('CPS can not be directly converted to a dosage level, but can be a ' +
                'general indication of radioactivity in an area.'))
                .append($('<p>').html('<b>Dosage</b> is reported in <i>micro-sieverts</i> or <b>uSv</b>. ' +
                'Dose can only be reported by a radiation detector which has been internally calibrated to calculate ' +
                'dose from count events.'))
                .append($('<p>').html('<i><b>Never</b> use the values reported in Kismet for determining ' +
                'if an area is radiologically safe.  Kismet integrates with sampling hardware for information ' +
                'and logging purposes, never use this information to determine if you are safe!</i>'))
            )
        },
        priority: -1003,
    }, 'rad-tabs');

    kismet_ui_tabpane.AddTab({
        id: 'rad-cps',
        tabTitle: 'Counts',
        createCallback: (div) => {
            div.append($('<div>', {
                class: 'rad-flex-stack rad-flex-box',
            })
                .append($('<div>', {
                    class: 'k-rad-graph-title'
                }).html('Past Minute'))
                .append($('<div>', {
                    style: 'width: 100%; min-height: 200px; height: 250px;'
                })
                    .append($('<canvas>', {
                        id: 'k-rad-cps-m-canvas',
                    }))
                )

                .append($('<div>', {
                    class: 'k-rad-graph-title'
                }).html('Past Hour'))
                .append($('<div>', {
                    style: 'width: 100%; min-height: 200px; height: 250px;'
                })
                    .append($('<canvas>', {
                        id: 'k-rad-cps-h-canvas',
                    }))
                )
            );
        },
        priority: -1002,
    }, 'rad-tabs');

    kismet_ui_tabpane.AddTab({
        id: 'rad-usv',
        tabTitle: 'Dosage',
        createCallback: (div) => {
            div.append($('<div>', {
                    class: 'rad-flex-stack rad-flex-box',
                })
                    .append($('<div>', {
                        class: 'k-rad-graph-title'
                    }).html('Past Minute'))
                    .append($('<div>', {
                            style: 'width: 100%; min-height: 200px; height: 250px;'
                        })
                            .append($('<canvas>', {
                                id: 'k-rad-usv-m-canvas',
                            }))
                    )

                    .append($('<div>', {
                        class: 'k-rad-graph-title'
                    }).html('Past Hour'))
                    .append($('<div>', {
                            style: 'width: 100%; min-height: 200px; height: 250px;'
                        })
                            .append($('<canvas>', {
                                id: 'k-rad-usv-h-canvas',
                            }))
                    )
            );
        },
        priority: -1001,
    }, 'rad-tabs');

    kismet_ui_tabpane.MakeTabPane($('#rad-tabs', rad_content), 'rad-tabs');

    updateRadiationData();
}

function updateRadiationData() {
    clearTimeout(rad_update_tid);

    if (rad_panel == null) {
        return;
    }

    $.get(local_uri_prefix + "radiation/sensors/all_sensors.json")
    .done(function(data) {
        data = kismet.sanitizeObject(data);

        let step = kismet.getStorage('kismet.ui.graph.stepped', false);

        let rad_m_datasets = [];
        let rad_h_datasets = [];

        let rad_usv_m_datasets = [];
        let rad_usv_h_datasets = [];

        for (const sk in data) {
            let cps = data[sk]['radiation.sensor.cps_rrd']['kismet.common.rrd.last_value'];
            let usv = data[sk]['radiation.sensor.usv_rrd']['kismet.common.rrd.last_value'];

            if (cps !== 0) {
                $('#rad-summary-cps').html(cps);
            } else {
                $('#rad-summary-cps').html('<i>n/a</i>')
            }

            if (usv !== 0) {
                $('#rad-summary-usv').html(usv);
            } else {
                $('#rad-summary-usv').html('<i>n/a</i>');
            }

            let rad_m_linedata =
                kismet.RecalcRrdData2(data[sk]['radiation.sensor.cps_rrd'], kismet.RRD_SECOND, {transform: kismet.RrdDrag, transformopt: {backfill: true}});

            let rad_h_linedata =
                kismet.RecalcRrdData2(data[sk]['radiation.sensor.cps_rrd'], kismet.RRD_MINUTE, {transform: kismet.RrdDrag, transformopt: {backfill: true}});

            rad_m_datasets.push({label: sk, data: rad_m_linedata, stepped: step});
            rad_h_datasets.push({label: sk, data: rad_h_linedata, stepped: step});

            let rad_usv_m_linedata =
                kismet.RecalcRrdData2(data[sk]['radiation.sensor.usv_rrd'], kismet.RRD_SECOND, {transform: kismet.RrdDrag, transformopt: {backfill: true}});

            let rad_usv_h_linedata =
                kismet.RecalcRrdData2(data[sk]['radiation.sensor.usv_rrd'], kismet.RRD_MINUTE, {transform: kismet.RrdDrag, transformopt: {backfill: true}});

            rad_usv_m_datasets.push({label: sk, data: rad_usv_m_linedata, stepped: step});
            rad_usv_h_datasets.push({label: sk, data: rad_usv_h_linedata, stepped: step});
        }

        if (rad_panel.rad_cps_chart_m == null) {
            let canvas_e = $('#k-rad-cps-m-canvas', rad_panel.content);

            let pointtitles = new Array();
            for (let x = 60; x > 0; x--) {
                if (x % 5 === 0) {
                    pointtitles.push(x + 's');
                } else {
                    pointtitles.push(' ');
                }
            }
            rad_panel.rad_cps_chart_m = new Chart(canvas_e, {
                type: 'line',
                data: {
                    labels: pointtitles,
                    datasets: rad_m_datasets,
                },
                options: {
                    animation: false,
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: {
                            position: "left",
                            title: {
                                text: 'Count',
                                display: true,
                            },
                            ticks: {
                                beginAtZero: true,
                            }
                        },
                    },
                },
            });
        } else {
            rad_panel.rad_cps_chart_m.data.datasets = rad_m_datasets;
            rad_panel.rad_cps_chart_m.update('none');
        }

        if (rad_panel.rad_cps_chart_h == null) {
            let canvas_e = $('#k-rad-cps-h-canvas', rad_panel.content);

            let pointtitles = new Array();
            for (let x = 60; x > 0; x--) {
                if (x % 5 === 0) {
                    pointtitles.push(x + 'm');
                } else {
                    pointtitles.push(' ');
                }
            }
            rad_panel.rad_cps_chart_h = new Chart(canvas_e, {
                type: 'line',
                data: {
                    labels: pointtitles,
                    datasets: rad_h_datasets,
                },
                options: {
                    animation: false,
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: {
                            position: "left",
                            title: {
                                text: 'Count',
                                display: true,
                            },
                            ticks: {
                                beginAtZero: true,
                            }
                        },
                    },
                },
            });
        } else {
            rad_panel.rad_cps_chart_h.data.datasets = rad_h_datasets;
            rad_panel.rad_cps_chart_h.update('none');
        }

        if (rad_panel.rad_usv_chart_m == null) {
            let canvas_e = $('#k-rad-usv-m-canvas', rad_panel.content);

            let pointtitles = new Array();
            for (let x = 60; x > 0; x--) {
                if (x % 5 === 0) {
                    pointtitles.push(x + 's');
                } else {
                    pointtitles.push(' ');
                }
            }

            rad_panel.rad_usv_chart_m = new Chart(canvas_e, {
                type: 'line',
                data: {
                    labels: pointtitles,
                    datasets: rad_usv_m_datasets,
                },
                options: {
                    animation: false,
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: {
                            position: "left",
                            title: {
                                text: 'uSv',
                                display: true,
                            },
                            ticks: {
                                beginAtZero: true,
                            }
                        },
                    },
                },
            });
        } else {
            rad_panel.rad_usv_chart_m.data.datasets = rad_usv_m_datasets;
            rad_panel.rad_usv_chart_m.update('none');
        }

        if (rad_panel.rad_usv_chart_h == null) {
            let canvas_e = $('#k-rad-usv-h-canvas', rad_panel.content);

            let pointtitles = new Array();
            for (let x = 60; x > 0; x--) {
                if (x % 5 === 0) {
                    pointtitles.push(x + 'm');
                } else {
                    pointtitles.push(' ');
                }
            }

            rad_panel.rad_usv_chart_h = new Chart(canvas_e, {
                type: 'line',
                data: {
                    labels: pointtitles,
                    datasets: rad_usv_h_datasets,
                },
                options: {
                    animation: false,
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: {
                            position: "left",
                            title: {
                                text: 'uSv',
                                display: true,
                            },
                            ticks: {
                                beginAtZero: true,
                            }
                        },
                    },
                },
            });
        } else {
            rad_panel.rad_usv_chart_h.data.datasets = rad_usv_h_datasets;
            rad_panel.rad_usv_chart_h.update('none');
        }
/*
            if (rad_panel.rad_spectrum_chart == null) {
                var canvas = $('#k-rad-spectrum-canvas');

                // We need to fill the labels even though we don't use them
                var labels = Array.apply(null, Array(500)).map(function (x, i) { return i; })

                rad_panel.rad_spectrum_chart = new Chart(canvas, {
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
            */
    })
    .always(() => {
        rad_update_tid = setTimeout(() => {
            updateRadiationData();
        }, 1000)
    });
}
