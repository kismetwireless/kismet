# Installation goes here
KIS_DEST_DIR ?= /usr/local
# You will need kismet newcore sources
KIS_SRC_DIR ?= /usr/src/kismet
KIS_INC_DIR ?= $(KIS_SRC_DIR)

BLDHOME	= .
top_builddir = $(BLDHOME)
CXX	= g++
CC	= gcc
LD	= g++
LDFLAGS	= -shared -rdynamic 
LIBS	= -lstdc++ -lusb -lpthread
CFLAGS 	= -I/usr/include -I$(KIS_INC_DIR) -g -fPIC

# CLIOBJS = spectools_ui.o
# CLIOUT	= spectools_ui.so

SRVOBJS = packetsource_raven.o packet_dot15d4.o packet_dot15d4_types.o \
			tracker_dot15d4.o kismet_dot15d4.o
SRVOUT	= dot15dot4.so

all:	$(SRVOUT) $(CLIOUT)

$(CLIOUT):	$(CLIOBJS)
	$(LD) $(LDFLAGS) $(CLIOBJS) -o $(CLIOUT) $(LIBS)

$(SRVOUT):	$(SRVOBJS)
	$(LD) $(LDFLAGS) $(SRVOBJS) -o $(SRVOUT) $(LIBS)

install:	$(SRVOUT) $(CLIOUT)
	install -D $(SRVOUT) $(KIS_DEST_DIR)/lib/kismet/$(SRVOUT)
	install -D $(CLIOUT) $(KIS_DEST_DIR)/lib/kismet_client/$(CLIOUT)

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
