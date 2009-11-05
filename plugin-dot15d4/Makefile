# You will need kismet newcore sources
KIS_SRC_DIR ?= /usr/src/kismet
KIS_INC_DIR ?= $(KIS_SRC_DIR)

include $(KIS_SRC_DIR)/Makefile.inc

BLDHOME	= .
top_builddir = $(BLDHOME)

LDFLAGS	+= -shared -rdynamic 
LIBS	+= -lstdc++ -lusb -lpthread
CFLAGS 	+= -I/usr/include -I$(KIS_INC_DIR) -g -fPIC

SRVOBJS = packetsource_raven.o packet_dot15d4.o packet_dot15d4_types.o \
			tracker_dot15d4.o kismet_dot15d4.o
SRVOUT	= dot15dot4.so

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

clean:
	@-rm -f *.o
	@-rm -f *.so

.c.o:
	$(CC) $(CFLAGS) -c $*.c -o $@ 

.cc.o:
	$(CXX) $(CFLAGS) -c $*.cc -o $@ 

.SUFFIXES: .c .cc .o
