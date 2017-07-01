APPNAME=kismet
VERSION=0
SNAP_DATE=$(shell date +%Y%m%d)
SNAP_REV=unknown
RPMBUILD_ROOT=$(HOME)/rpmbuild
SRC_ROOT=$(shell pwd | sed -e 's,/packaging/centos/el7,,')
ARCH=$(shell arch)

latest: dist
	rpmbuild -bb $(RPMBUILD_ROOT)/SPECS/$(APPNAME)-git.spec

stable: buildroot
	cp $(APPNAME).spec $(RPMBUILD_ROOT)/SPECS/$(APPNAME).spec
	spectool -g -S -C $(RPMBUILD_ROOT)/SOURCES $(RPMBUILD_ROOT)/SPECS/$(APPNAME).spec
	rpmbuild -bb $(RPMBUILD_ROOT)/SPECS/$(APPNAME).spec

dist: buildroot
	$(eval SNAP_REV=$(shell git rev-parse --short HEAD))
	$(eval TARBALL=$(shell echo $(APPNAME)-git-$(VERSION)-$(SNAP_DATE).$(SNAP_REV)))
	
	-rm -f $(BUILD_TMP)/rpmbuild/SOURCES/$(TARBALL).tar.xz

	tar --exclude ".git" --transform "s,$(SRC_ROOT),$(TARBALL)," -PcJf \
		$(RPMBUILD_ROOT)/SOURCES/$(TARBALL).tar.xz \
		$(SRC_ROOT)

	cat $(APPNAME)-git.spec.in \
		| sed -s 's,^\(Version:.*\)\@VERSION\@,\1$(VERSION),' \
		| sed -s 's,^\(%define relver.*\)\@RELEASE\@,\1 $(SNAP_DATE).$(SNAP_REV),' \
		| sed -s 's,^\(Source:.*\)\@TARBALL\@,\1$(TARBALL).tar.xz,' \
		> $(RPMBUILD_ROOT)/SPECS/$(APPNAME)-git.spec

buildroot:
	mkdir -p $(RPMBUILD_ROOT)/{BUILD,RPMS,SOURCES,SPECS,SRPMS} 

clean:
	-rm -fr $(RPMBUILD_ROOT)/BUILD/kismet*
	-rm -fr $(RPMBUILD_ROOT)/BUILDROOT/kismet*
	-rm -fr $(RPMBUILD_ROOT)/RPMS/$(ARCH)/kismet*
	-rm $(RPMBUILD_ROOT)/SOURCES/$(APPNAME)* 
	-rm $(RPMBUILD_ROOT)/SPECS/$(APPNAME)* 

distclean: clean
	-rm -fri $(RPMBUILD_ROOT)
