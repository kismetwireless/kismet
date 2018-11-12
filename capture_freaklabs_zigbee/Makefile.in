include ../Makefile.inc

MONITOR_BIN = kismet_cap_freaklabs_zigbee

all: 
	$(PYTHON2) ./setup.py build

install:
	$(PYTHON2) ./setup.py install
	# $(INSTALL) -o $(INSTUSR) -g $(INSTGRP) $(MONITOR_BIN) $(BIN)/$(MONITOR_BIN)

clean:
	@-$(PYTHON2) ./setup.py clean

