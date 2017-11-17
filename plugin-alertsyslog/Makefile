# Plugin name
PLUGIN_NAME ?= alertsyslog

# You will need kismet git-master sources if not compiling in the main tree
KIS_SRC_DIR ?= /usr/src/kismet
KIS_INC_DIR ?= $(KIS_SRC_DIR)

-include $(KIS_SRC_DIR)/Makefile.inc

BLDHOME	= .
top_builddir = $(BLDHOME)

# Set sane values if we don't have the base config
INSTALL ?= /usr/bin/install
plugindir ?= $(shell pkg-config --variable=plugindir kismet)

ifeq ("$(plugindir)", "")
	plugindir := "/usr/local/lib/kismet/"
	plugingeneric := "1"
endif

INSTUSR ?= root
INSTGRP ?= root

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
ifeq ("$(plugingeneric)", "1")
	echo "No kismet install found in pkgconfig, assuming /usr/local"
endif

	mkdir -p $(DESTDIR)/$(plugindir)/$(PLUGIN_NAME)
	$(INSTALL) -o $(INSTUSR) -g $(INSTGRP) -m 444 manifest.conf $(DESTDIR)/$(plugindir)/$(PLUGIN_NAME)/manifest.conf
	$(INSTALL) -o $(INSTUSR) -g $(INSTGRP) -m 644 $^ $(DESTDIR)/$(plugindir)/$(PLUGIN_NAME)/$^

userinstall:	$(PLUGOUT)
	mkdir -p ${HOME}/.kismet/plugins/$(PLUGIN_NAME)
	install manifest.conf ${HOME}/.kismet/plugins/$(PLUGIN_NAME)/manifest.conf
	install $^ ${HOME}/.kismet/plugins/$(PLUGIN_NAME)/$^

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

.PRECIOUS: %.Td %.c.d %.cc.d
.SUFFIXES: .c .cc .o
