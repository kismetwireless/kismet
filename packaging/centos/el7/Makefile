APPNAME=kismet
VERSION=0
SNAP_DATE=$(shell date +%Y%m%d)
SNAP_REV=$(shell git rev-parse --short HEAD)
SNAP_TARBALL=$(shell echo $(APPNAME)-git-$(VERSION)-$(SNAP_DATE).$(SNAP_REV))
RPMBUILD_ROOT=$(HOME)/rpmbuild
SRC_ROOT=$(shell pwd | sed -e 's,/packaging/centos/el7,,')
ARCH=$(shell arch)

default: stable

stable: buildroot
	cp $(APPNAME).spec $(RPMBUILD_ROOT)/SPECS/$(APPNAME).spec
	spectool -g -S -C $(RPMBUILD_ROOT)/SOURCES $(RPMBUILD_ROOT)/SPECS/$(APPNAME).spec
	rpmbuild --define "_topdir $(HOME)/rpmbuild" -bb $(RPMBUILD_ROOT)/SPECS/$(APPNAME).spec

snapshot: spec tarball
	cp $(APPNAME)-git.spec $(RPMBUILD_ROOT)/SPECS/$(APPNAME)-git.spec
	rpmbuild --define "_topdir $(HOME)/rpmbuild" -bb $(RPMBUILD_ROOT)/SPECS/$(APPNAME)-git.spec

spec: buildroot
	cat $(APPNAME)-git.spec.in \
		| sed -s 's,^\(Version:.*\)\@VERSION\@,\1$(VERSION),' \
		| sed -s 's,^\(%define relver.*\)\@RELEASE\@,\1 $(SNAP_DATE).$(SNAP_REV),' \
		| sed -s 's,^\(Source:.*\)\@TARBALL\@,\1$(SNAP_TARBALL).tar.xz,' \
		> $(APPNAME)-git.spec

tarball: buildroot 
	
	-rm -f $(BUILD_TMP)/rpmbuild/SOURCES/$(SNAP_TARBALL).tar.xz

	tar --exclude ".git" --transform "s,$(SRC_ROOT),$(SNAP_TARBALL)," -PcJf \
		$(RPMBUILD_ROOT)/SOURCES/$(SNAP_TARBALL).tar.xz \
		$(SRC_ROOT)

buildroot:
	mkdir -p $(RPMBUILD_ROOT)/{BUILD,RPMS,SOURCES,SPECS,SRPMS} 

clean:
	-rm $(APPNAME)-git.spec
	-rm -fr $(RPMBUILD_ROOT)/BUILD/$(APPNAME)*
	-rm -fr $(RPMBUILD_ROOT)/BUILDROOT/$(APPNAME)*
	-rm -fr $(RPMBUILD_ROOT)/RPMS/$(ARCH)/$(APPNAME)*
	-rm $(RPMBUILD_ROOT)/SOURCES/$(APPNAME)* 
	-rm $(RPMBUILD_ROOT)/SPECS/$(APPNAME)* 

distclean: clean
	-rm -fri $(RPMBUILD_ROOT)
