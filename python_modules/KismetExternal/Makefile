include ../../Makefile.inc

all:	
	$(PYTHON3) ./setup.py build
	
install:
	$(PYTHON3) ./setup.py install

protobuf:
	$(PROTOCBIN) -I ../../protobuf_definitions --python_out=./KismetExternal ../../protobuf_definitions/*.proto

clean:
	@-$(PYTHON3) ./setup.py clean

