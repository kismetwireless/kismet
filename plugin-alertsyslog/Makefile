# You will need kismet newcore sources
KIS_SRC_DIR ?= /usr/src/kismet
KIS_INC_DIR ?= $(KIS_SRC_DIR)

include $(KIS_SRC_DIR)/Makefile.inc

BLDHOME	= .
top_builddir = $(BLDHOME)

PLUGINLDFLAGS += -shared -rdynamic
LIBS	+= -lstdc++ 
CFLAGS 	+= -I/usr/include -I$(KIS_INC_DIR) -g -fPIC
CXXFLAGS 	+= -I/usr/include -I$(KIS_INC_DIR) -g -fPIC

PLUGOBJS = alertsyslog.o
PLUGOUT = alertsyslog.so

all:	$(PLUGOUT)

$(PLUGOUT):	$(PLUGOBJS)
	$(LD) $(PLUGINLDFLAGS) $(PLUGOBJS) -o $(PLUGOUT) $(LIBS)

install:	$(PLUGOUT)
	mkdir -p $(DESTDIR)/$(plugindir)
	install -o $(INSTUSR) -g $(INSTGRP) -m 644 $^ $(DESTDIR)/$(plugindir)/$^

userinstall:	$(PLUGOUT)
	mkdir -p ${HOME}/.kismet/plugins/
	install $(PLUGOUT) ${HOME}/.kismet/plugins/$(PLUGOUT)

clean:
	@-rm -f *.o
	@-rm -f *.so

.c.o:
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $*.c -o $@ 

.cc.o:
	$(CXX) $(CXXFLAGS) $(CXXFLAGS) -c $*.cc -o $@ 

.SUFFIXES: .c .cc .o
