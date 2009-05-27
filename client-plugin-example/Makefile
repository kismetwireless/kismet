# Kismet wireless sniffer

VERSION_MAJOR	= 2005
VERSION_MINOR	= 00
VERSION_TINY	= devel-newcore

KIS_INC_DIR		= ../

HOME	= .
CXX	= g++
CC	= gcc
LD	= g++
LDFLAGS	= -shared -rdynamic
LIBS	= -lstdc++ 
CFLAGS	= -fPIC
CXXFLAGS = -fPIC -pthread -DVERSION_MAJOR=\"$(VERSION_MAJOR)\" -DVERSION_MINOR=\"$(VERSION_MINOR)\" -DVERSION_TINY=\"$(VERSION_TINY)\" -DTIMESTAMP=\"`cat TIMESTAMP`\"
CPPFLAGS = -I/usr/include -I$(KIS_INC_DIR)

PLUGOBJS = kcliplug.o

kcliplugin.so:	$(PLUGOBJS)
	$(LD) $(LDFLAGS) $(PLUGOBJS) -o kcliplugin.so $(LIBS)

.c.o:
	$(CC) $(CFLAGS) -c $*.c -o $@ 

.cc.o:
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $*.cc -o $@ 

.SUFFIXES: .c .cc .o
