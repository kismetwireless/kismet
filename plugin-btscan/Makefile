# You will need kismet newcore sources
KIS_SRC_DIR ?= /usr/src/kismet
KIS_INC_DIR ?= $(KIS_SRC_DIR)

include $(KIS_SRC_DIR)/Makefile.inc

BLDHOME	= .
top_builddir = $(BLDHOME)

PLUGINLDFLAGS ?= $(LDFLAGS)
PLUGINLDFLAGS += -shared -rdynamic
LIBS	+= -lstdc++ -lbluetooth -lpthread -lncurses -lpanel
CFLAGS 	+= -I/usr/include -I$(KIS_INC_DIR) -g -fPIC

SRVOBJS = packetsource_linuxbt.o tracker_btscan.o dumpfile_btscantxt.o kismet_btscan.o
SRVOUT	= btscan.so

CLIOBJS	= btscan_ui.o
CLIOUT 	= btscan_ui.so

all:	$(SRVOUT) $(CLIOUT)

$(CLIOUT):	$(CLIOBJS)
	$(LD) $(PLUGINLDFLAGS) $(CLIOBJS) -o $(CLIOUT) $(LIBS)

$(SRVOUT):	$(SRVOBJS)
	$(LD) $(PLUGINLDFLAGS) $(SRVOBJS) -o $(SRVOUT) $(LIBS)

install:	$(SRVOUT) $(CLIOUT)
	mkdir -p $(DESTDIR)$(prefix)/lib/kismet/
	install -o $(INSTUSR) -g $(INSTGRP) -m 644 $(SRVOUT) $(DESTDIR)$(prefix)/lib/kismet/$(SRVOUT)
	mkdir -p $(DESTDIR)$(prefix)/lib/kismet_client/
	install -o $(INSTUSR) -g $(INSTGRP) -m 644 $(CLIOUT) $(DESTDIR)$(prefix)/lib/kismet_client/$(CLIOUT)

userinstall:	$(SRVOUT) $(CLIOUT)
	mkdir -p ${HOME}/.kismet/plugins/
	install -v $(SRVOUT) ${HOME}/.kismet/plugins/$(SRVOUT)
	mkdir -p ${HOME}/.kismet/client_plugins/
	install -v $(CLIOUT) ${HOME}/.kismet/client_plugins/$(CLIOUT)

clean:
	@-rm -f *.o
	@-rm -f *.so

.c.o:
	$(CC) $(CFLAGS) -c $*.c -o $@ 

.cc.o:
	$(CXX) $(CFLAGS) -c $*.cc -o $@ 

.SUFFIXES: .c .cc .o
