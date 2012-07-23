# You will need kismet newcore sources
KIS_SRC_DIR ?= /usr/src/kismet
KIS_INC_DIR ?= $(KIS_SRC_DIR)

include $(KIS_SRC_DIR)/Makefile.inc

BLDHOME	= .
top_builddir = $(BLDHOME)

PLUGINLDFLAGS += -shared -rdynamic
LIBS	+= -lstdc++ -lbluetooth -lpthread
CFLAGS 	+= -I$(KIS_INC_DIR) -g -fPIC
CXXFLAGS += -I$(KIS_INC_DIR) -g -fPIC

SRVOBJS = packetsource_linuxbt.o phy_btscan.o kismet_btscan.o
SRVOUT	= btscan.so

CLIOBJS	= btscan_ui.o
CLIOUT 	= btscan_ui.so

all:	$(SRVOUT) 

$(CLIOUT):	$(CLIOBJS)
	$(LD) $(PLUGINLDFLAGS) $(CLIOBJS) -o $(CLIOUT) $(LIBS)

$(SRVOUT):	$(SRVOBJS)
	$(LD) $(PLUGINLDFLAGS) $(SRVOBJS) -o $(SRVOUT) $(LIBS)

install:	$(SRVOUT) 
	mkdir -p $(DESTDIR)/$(plugindir)
	$(INSTALL) -o $(INSTUSR) -g $(INSTGRP) -m 644 $(SRVOUT) $(DESTDIR)/$(plugindir)/$(SRVOUT)
	#mkdir -p $(DESTDIR)/$(plugindir)_client
	#install -o $(INSTUSR) -g $(INSTGRP) -m 644 $(CLIOUT) $(DESTDIR)/$(plugindir)_client/$(CLIOUT)

userinstall:	$(SRVOUT) 
	mkdir -p ${HOME}/.kismet/plugins/
	$(INSTALL) -v $(SRVOUT) ${HOME}/.kismet/plugins/$(SRVOUT)
	#mkdir -p ${HOME}/.kismet/client_plugins/
	#install -v $(CLIOUT) ${HOME}/.kismet/client_plugins/$(CLIOUT)

clean:
	@-rm -f *.o
	@-rm -f *.so

.c.o:
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $*.c -o $@ 

.cc.o:
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $*.cc -o $@ 

.SUFFIXES: .c .cc .o
