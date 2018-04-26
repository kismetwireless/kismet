include ../../Makefile.inc

DESTDIR ?= /

all:	
	$(PYTHON2) ./setup.py build
	
install:
	$(PYTHON2) ./setup.py install --root=$(DESTDIR)

protobuf:
	$(PROTOCBIN) -I ../../protobuf_definitions --python_out=./KismetExternal ../../protobuf_definitions/*.proto

clean:
	@-$(PYTHON2) ./setup.py clean

