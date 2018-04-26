include ../../Makefile.inc

DESTDIR ?= /

all:	
	$(PYTHON2) ./setup.py build
	
install:
	$(PYTHON2) ./setup.py install --root=$(DESTDIR)

clean:
	@-$(PYTHON2) ./setup.py clean

