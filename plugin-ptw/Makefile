# You will need kismet newcore sources
KIS_SRC_DIR ?= /usr/src/kismet
KIS_INC_DIR ?= $(KIS_SRC_DIR)

include $(KIS_SRC_DIR)/Makefile.inc

BLDHOME	= .
top_builddir = $(BLDHOME)

PLUGINLDFLAGS ?= $(LDFLAGS)
PLUGINLDFLAGS += -shared -rdynamic
LIBS	+= -lstdc++ -lssl -lpthread -lcrypto
CFLAGS 	+= -I/usr/include -I$(KIS_INC_DIR) -g -fPIC

PLUGOBJS = aircrack-crypto.o aircrack-ptw2-lib.o aircrack-kismet.o
PLUGOUT = aircrack-kismet.so

all:	$(PLUGOUT)

$(PLUGOUT):	$(PLUGOBJS)
	$(LD) $(PLUGINLDFLAGS) $(PLUGOBJS) -o $(PLUGOUT) $(LIBS)

install:	$(PLUGOUT)
	mkdir -p $(DESTDIR)$(prefix)/lib/kismet/

	install -o $(INSTUSR) -g $(INSTGRP) -m 644 $^ $(DESTDIR)$(prefix)/lib/kismet/$^

userinstall:	$(PLUGOUT)
	mkdir -p ${HOME}/.kismet/plugins/
	install $(PLUGOUT) ${HOME}/.kismet/plugins/$(PLUGOUT)

clean:
	@-rm -f *.o
	@-rm -f *.so

.c.o:
	$(CC) $(CFLAGS) -c $*.c -o $@ 

.cc.o:
	$(CXX) $(CFLAGS) -c $*.cc -o $@ 

.SUFFIXES: .c .cc .o
