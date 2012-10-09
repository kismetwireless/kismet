# You will need kismet newcore sources
KIS_SRC_DIR ?= /usr/src/kismet
KIS_INC_DIR ?= $(KIS_SRC_DIR)

include $(KIS_SRC_DIR)/Makefile.inc

BLDHOME	= .
top_builddir = $(BLDHOME)

PLUGINLDFLAGS += -shared -rdynamic
LIBS	+= -lstdc++ -lusb -lpthread
CFLAGS 	+= -I$(KIS_INC_DIR) -g -fPIC
CXXFLAGS 	+= -I$(KIS_INC_DIR) -g -fPIC

#SRVOBJS = packetsource_raven.o packetsource_serialdev.o \
#			packet_dot15d4.o packet_dot15d4_types.o \
#			tracker_dot15d4.o kismet_dot15d4.o
SRVOBJS	= packetsource_serialdev.o packet_dot15d4_types.o \
			phy_dot15d4.o kismet_dot15d4.o
SRVOUT	= dot15dot4.so

all:	$(SRVOUT) $(CLIOUT)

$(CLIOUT):	$(CLIOBJS)
	$(LD) $(PLUGINLDFLAGS) $(CLIOBJS) -o $(CLIOUT) $(LIBS)

$(SRVOUT):	$(SRVOBJS)
	$(LD) $(PLUGINLDFLAGS) $(SRVOBJS) -o $(SRVOUT) $(LIBS)

install:	$(SRVOUT) $(CLIOUT)
	mkdir -p $(DESTDIR)/$(plugindir)
	$(INSTALL) -o $(INSTUSR) -g $(INSTGRP) -m 644 $(SRVOUT) $(DESTDIR)/$(plugindir)/$(SRVOUT)

userinstall:	$(SRVOUT) $(CLIOUT)
	mkdir -p ${HOME}/.kismet/plugins/
	$(INSTALL) -v $(SRVOUT) ${HOME}/.kismet/plugins/$(SRVOUT)

clean:
	@-rm -f *.o
	@-rm -f *.so

.c.o:
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $*.c -o $@ 

.cc.o:
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $*.cc -o $@ 

.SUFFIXES: .c .cc .o
