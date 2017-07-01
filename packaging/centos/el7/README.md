# CentOS 7 Packaging

Packages for the latest stable release or the currently cloned source can be
built using GNU Make. 

An RPM build environment will be created under the current users home directory.

Packages will reside in $(HOME)/rpmbuild/RPMS/x86_64.

## Prerequisites

    $ sudo yum install rpm-build redhat-rpm-config rpmdevtools yum-utils

## Package Stable

    $ sudo yum-builddep kismet.spec
    $ make

## Package Source Snapshot

    $ make spec
    $ sudo yum-builddep kismet-git.spec
    $ make snapshot
