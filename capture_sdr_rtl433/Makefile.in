include ../Makefile.inc

MONITOR_BIN = kismet_cap_sdr_rtl433
MQTTMONITOR_BIN = kismet_cap_sdr_rtl433_mqtt

all: 
	$(PYTHON2) ./setup.py build

install:
	$(PYTHON2) ./setup.py install
	# These are now part of the setup.py install
	# $(INSTALL) -o $(INSTUSR) -g $(INSTGRP) $(MONITOR_BIN) $(BIN)/$(MONITOR_BIN)
	# $(INSTALL) -o $(INSTUSR) -g $(INSTGRP) $(MQTTMONITOR_BIN) $(BIN)/$(MQTTMONITOR_BIN)

clean:
	@-$(PYTHON2) ./setup.py clean

