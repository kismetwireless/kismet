# You will need kismet newcore sources
KIS_SRC_DIR ?= /usr/src/kismet
KIS_INC_DIR ?= $(KIS_SRC_DIR)

include $(KIS_SRC_DIR)/Makefile.inc

BLDHOME	= .
top_builddir = $(BLDHOME)

LDFLAGS	+= -shared -rdynamic 
LIBS	+= -lstdc++ 
CFLAGS 	+= -I/usr/include -I$(KIS_INC_DIR) -g -fPIC

CLIOBJS = spectools_ui.o
CLIOUT	= spectools_ui.so

SRVOBJS = spectool_netclient.o spectool_kismet.o
SRVOUT	= spectool_net.so

all:	$(SRVOUT) $(CLIOUT)

$(CLIOUT):	$(CLIOBJS)
	$(LD) $(LDFLAGS) $(CLIOBJS) -o $(CLIOUT) $(LIBS)

$(SRVOUT):	$(SRVOBJS)
	$(LD) $(LDFLAGS) $(SRVOBJS) -o $(SRVOUT) $(LIBS)

install:	$(SRVOUT) $(CLIOUT)
	install -D $(SRVOUT) $(DESTDIR)$(prefix)/lib/kismet/$(SRVOUT)
	install -D $(CLIOUT) $(DESTDIR)$(prefix)/lib/kismet_client/$(CLIOUT)

userinstall:	$(SRVOUT) $(CLIOUT)
	install -v -D $(SRVOUT) ${HOME}/.kismet/plugins/$(SRVOUT)
	install -v -D $(CLIOUT) ${HOME}/.kismet/client_plugins/$(CLIOUT)

clean:
	@-rm -f *.o
	@-rm -f *.so

.c.o:
	$(CC) $(CFLAGS) -c $*.c -o $@ 

.cc.o:
	$(CXX) $(CFLAGS) -c $*.cc -o $@ 

.SUFFIXES: .c .cc .o
