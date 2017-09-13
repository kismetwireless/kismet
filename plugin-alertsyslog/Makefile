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

PLUGOBJS = alertsyslog.cc.o
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
	@-rm -f *.d

%.c.o:	%.c
%.c.o : %.c %.c.d
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $*.c -o $@

%.cc.o: %.cc
%.cc.o:	%.cc %.cc.d
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -c $*.cc -o $@

%.c.d:  %.c
	$(CC) -MM $(CFLAGS) $(CPPFLAGS) $*.c | sed -e "s/\.o/\.c.o/" > $*.c.d

%.cc.d: %.cc
	$(CXX) -MM $(CXXFLAGS) $(CPPFLAGS) $*.cc | sed -e "s/\.o/\.cc.o/" > $*.cc.d

.SUFFIXES: .c .cc .o
