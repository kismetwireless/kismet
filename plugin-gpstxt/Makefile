# You will need kismet newcore sources
KIS_SRC_DIR ?= /usr/src/kismet
KIS_INC_DIR ?= $(KIS_SRC_DIR)

include $(KIS_SRC_DIR)/Makefile.inc

BLDHOME	= .
top_builddir = $(BLDHOME)

PLUGINLDFLAGS += -shared -rdynamic
LIBS	+= -lstdc++ 
CFLAGS 	+= -I$(KIS_INC_DIR) -g -fPIC
CXXFLAGS 	+= -I$(KIS_INC_DIR) -g -fPIC

PLUGOBJS = gpstxt.o
PLUGOUT = gpstxt.so

all:	$(PLUGOUT)

$(PLUGOUT):	$(PLUGOBJS)
	$(LD) $(PLUGINLDFLAGS) $(PLUGOBJS) -o $(PLUGOUT) $(LIBS)

install:	$(PLUGOUT)
	mkdir -p $(DESTDIR)/$(plugindir)
	$(INSTALL) -o $(INSTUSR) -g $(INSTGRP) -m 644 $^ $(DESTDIR)/$(plugindir)/$^

userinstall:	$(PLUGOUT)
	mkdir -p ${HOME}/.kismet/plugins/
	$(INSTALL) $(PLUGOUT) ${HOME}/.kismet/plugins/$(PLUGOUT)

clean:
	@-rm -f *.o
	@-rm -f *.so

.c.o:
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $*.c -o $@ 

.cc.o:
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $*.cc -o $@ 

.SUFFIXES: .c .cc .o
