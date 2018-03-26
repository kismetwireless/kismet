include ../../Makefile.inc

all:	
	$(PYTHON2) ./setup.py build
	
install:
	$(PYTHON2) ./setup.py install

protobuf:
	$(PROTOCBIN) -I ../../protobuf_definitions --python_out=./KismetExternal ../../protobuf_definitions/*.proto

clean:
	@-$(PYTHON2) ./setup.py clean

