include ../../Makefile.inc

all:	
	$(PYTHON3) ./setup.py build
	
install:
	$(PYTHON3) ./setup.py install

protobuf:
	$(PROTOCBIN) -I ../../protobuf_definitions --python_out=./KismetExternal ../../protobuf_definitions/*.proto
	@-echo "You now need to edit the includes for each generated file to fix python3 support, unless your protoc has included the 2017 fixes."

clean:
	@-$(PYTHON3) ./setup.py clean

