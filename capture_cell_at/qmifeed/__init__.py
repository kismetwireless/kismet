"""The QMI cell feed behind ``qmifeed=``.

``kismet_qmi_feed.py`` is the command ``kismet_cap_cell_at`` spawns for
``qmifeed=auto``: it polls ``qmicli`` and writes one cell_observation JSON object
per line. Standard library only; it needs ``qmicli`` on ``$PATH`` and nothing
else from outside this tree.

Submodules:
    detect              -- find QMI/MBIM control devices and their qmicli open flags
    parse               -- qmicli text output -> typed records
    kismet_cell_bridge  -- one parsed cell-location-info -> cell_observation dicts
    kismet_qmi_feed     -- the poll loop (run by path)
"""
