# Kismet wireless sniffer

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
LIBS	= -lstdc++ 
CFLAGS 	= -I/usr/include -I$(KIS_INC_DIR) -g -fPIC

PLUGOBJS = autowep-kismet.o
PLUGOUT = autowep-kismet.so

all:	$(PLUGOUT)

$(PLUGOUT):	$(PLUGOBJS)
	$(LD) $(LDFLAGS) $(PLUGOBJS) -o $(PLUGOUT) $(LIBS)

install:	$(PLUGOUT)
	install -D $^ $(KIS_DEST_DIR)/lib/kismet/$^

userinstall:	$(PLUGOUT)
	install -D $(PLUGOUT) ${HOME}/.kismet/plugins/$(PLUGOUT)

clean:
	@-rm -f *.o
	@-rm -f *.so

.c.o:
	$(CC) $(CFLAGS) -c $*.c -o $@ 

.cc.o:
	$(CXX) $(CFLAGS) -c $*.cc -o $@ 

.SUFFIXES: .c .cc .o
