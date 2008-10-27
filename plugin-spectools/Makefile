# Kismet wireless sniffer

KIS_INC_DIR		= ../

HOME	= .
top_builddir = $(HOME)
CXX	= g++
CC	= gcc
LD	= g++
LDFLAGS	= -shared -rdynamic 
LIBS	= -lstdc++ 
CFLAGS 	= -I/usr/include -I$(KIS_INC_DIR) -g -fPIC

CLIOBJS = spectools_ui.o
CLIOUT	= spectools_ui.so

all:	$(LIBOUT) $(CLIOUT)

$(CLIOUT):	$(CLIOBJS)
	$(LD) $(LDFLAGS) $(CLIOBJS) -o $(CLIOUT) $(LIBS)

clean:
	@-rm -f *.o
	@-rm -f *.so

.c.o:
	$(CC) $(CFLAGS) -c $*.c -o $@ 

.cc.o:
	$(CXX) $(CFLAGS) -c $*.cc -o $@ 

.SUFFIXES: .c .cc .o
