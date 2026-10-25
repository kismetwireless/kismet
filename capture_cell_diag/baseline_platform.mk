# baseline_platform.mk -- the no-autoconf config BOTH capture drivers' standalone
# builds share. Included by capture_cell_diag/standalone.mk and
# capture_cell_at/standalone.mk; the includer sets BASELINE_DIR first.
#
# ONE fragment, not two copies: the two drivers link the same capture framework,
# so a config.h rule that learned a platform in one makefile and not the other
# would build one driver and leave its sibling broken.
#
# WHAT IT DECIDES, AND FROM WHAT
# --------------------
#   target OS   `uname -s`, overridable as BASELINE_TARGET_OS=<Linux|Darwin> for a
#               cross-compile (uname measures the BUILD host, not the target).
#               Linux -> SYS_LINUX, Darwin -> SYS_DARWIN -- the same mapping the
#               top-level configure.ac makes. Anything else is refused up front:
#               it has never been tested.
#   websockets  LWS=auto (default) probes `pkg-config 'libwebsockets >= 3.1.0'`,
#               the same floor ./configure enforces; LWS=1 / LWS=0 force it.
#
# libwebsockets is a CONFIG CHOICE here, not a structural dependency: every lws
# include, every `struct lws_*` member and every lws call site in
# capture_framework.{c,h} sits under `#ifdef HAVE_LIBWEBSOCKETS`, with `#else`
# stubs. With lws undefined, both drivers link on macOS against libSystem alone.
#
# What a no-lws build loses: the remote-capture websocket transport
# (`--connect ws://...`). Local IPC capture -- the path Kismet uses to run a
# helper on the same host, and the only path the celltools tests use -- is
# unaffected. The generated config.h and the build output both say so.

# The target OS. `?=` so a cross-compile states it rather than inheriting the
# build host's (`uname` measures the wrong machine in exactly that case).
BASELINE_TARGET_OS ?= $(shell uname -s)

ifeq ($(BASELINE_TARGET_OS),Linux)
BASELINE_SYS_DEFINE = SYS_LINUX
else ifeq ($(BASELINE_TARGET_OS),Darwin)
BASELINE_SYS_DEFINE = SYS_DARWIN
else
BASELINE_SYS_DEFINE =
endif

# The floor ./configure enforces (configure.ac PKG_CHECK_MODULES). A build that
# used an older lws than the configured tree would accept is not the same build.
BASELINE_LWS_PC = libwebsockets >= 3.1.0

LWS ?= auto
ifeq ($(LWS),auto)
# pkg-config first; a pkg-config-less host that still has the header in the
# system include root is answered by the header, so a Linux host with lws
# installed but no pkg-config still gets an lws build.
BASELINE_LWS := $(shell \
    if command -v pkg-config >/dev/null 2>&1; then \
        pkg-config --exists '$(BASELINE_LWS_PC)' && echo 1 || echo 0; \
    elif [ -f /usr/include/libwebsockets.h ]; then echo 1; \
    else echo 0; fi)
else
BASELINE_LWS := $(LWS)
endif

# Flags for WHEN the link needs lws. The link keys off the config.h actually in
# use, not off BASELINE_LWS: a configured tree's ../config.h is COPIED (one
# config per link), and it may define HAVE_LIBWEBSOCKETS whatever the probe says.
#
# The openssl cflags are not optional on Homebrew. lws 5.0's
# <libwebsockets.h> includes <openssl/ssl.h>, but brew's libwebsockets.pc has no
# `Requires: openssl` and brew's openssl@3 is keg-only, so the lws cflags alone
# fail with "'openssl/ssl.h' file not found". Where the lws .pc already implies
# openssl, or openssl sits in the system include root, this adds nothing.
BASELINE_LWS_CFLAGS := $(shell pkg-config --cflags '$(BASELINE_LWS_PC)' 2>/dev/null) \
                       $(shell pkg-config --cflags openssl 2>/dev/null)
BASELINE_LWS_LIBS   := $(shell pkg-config --libs '$(BASELINE_LWS_PC)' 2>/dev/null || echo -lwebsockets)

# This fragment's own path, captured at include time: generated files depend on
# it, so a changed recipe regenerates them rather than serving a cached copy
# (see the version.c rule below).
BASELINE_PLATFORM_MK := $(lastword $(MAKEFILE_LIST))

# The link-time libraries the config.h in use requires. A recipe fragment, run
# by the shell at link time -- after config.h exists -- not at parse time.
BASELINE_CONFIG_LIBS = \
    $$(grep -q '^\#define HAVE_LIBWEBSOCKETS' $(BASELINE_DIR)/config.h && echo '$(BASELINE_LWS_LIBS)') \
    $$(grep -q '^\#define HAVE_CAPABILITY' $(BASELINE_DIR)/config.h && echo -lcap)

# The platform guard. The generated config.h names the actual OS (asserting
# SYS_LINUX everywhere would pull in <linux/sched.h> via capture_framework.c),
# so Linux and Darwin are both supported targets; only an OS with no mapping
# above is refused.
baseline-platform-guard:
	@if [ -z "$(BASELINE_SYS_DEFINE)" ]; then \
	    echo "*** ERROR: 'baseline' has no platform mapping for '$(BASELINE_TARGET_OS)' ***" >&2; \
	    echo "" >&2; \
	    echo "Supported targets: Linux (SYS_LINUX) and Darwin (SYS_DARWIN) -- the" >&2; \
	    echo "mapping the top-level configure.ac makes.  Any other OS has never been" >&2; \
	    echo "built here, so this refuses rather than guess." >&2; \
	    echo "" >&2; \
	    echo "Cross-compiling?  Name the TARGET, since uname measures the build host:" >&2; \
	    echo "    make -f standalone.mk baseline BASELINE_TARGET_OS=Linux CC=<linux-cc>" >&2; \
	    exit 1; \
	fi

# config.h: COPIED from ../config.h when a configured tree has one, generated
# otherwise. Copying rather than always generating is deliberate -- capture_
# framework.c's own `#include "config.h"` resolves against ITS directory (..)
# before any -I, so on a configured tree it reads ../config.h no matter what we
# put on the include path. Generating a DIFFERENT config here would then compile
# the two halves of one link against two different configs, and USE_MMAP_RBUF
# alone is enough for that to matter. One config per link, always.
#
# Rewritten on EVERY run and replaced only when the content changed. Without
# that, the first config a host generated would be the one it kept: LWS=0 after
# an lws build, or a ./configure after a standalone build, would silently do
# nothing. The compare keeps the mtime still when nothing
# changed, so an unchanged config does not force a relink.
$(BASELINE_DIR)/config.h: baseline-config-force
	@mkdir -p $(BASELINE_DIR)
	@if [ -f ../config.h ]; then \
	    cp ../config.h $@.tmp; \
	    src="../config.h (configured tree)"; \
	else \
	    { \
	      echo '/* Generated by capture_cell_diag/baseline_platform.mk -- NOT autoconf output.'; \
	      echo ''; \
	      echo '   The MINIMUM ../config.h surface every source in this link consumes:'; \
	      echo ''; \
	      echo '     SYS_LINUX | SYS_DARWIN   HAVE_LIBWEBSOCKETS   HAVE_CAPABILITY   STATUS_MAX'; \
	      echo ''; \
	      echo '   STATUS_MAX is a VALUE macro used in ordinary code (buffer sizes), so an'; \
	      echo '   #ifdef-only survey misses it; the omission surfaces as undeclared-'; \
	      echo '   identifier errors deep inside capture_framework.c.'; \
	      echo ''; \
	      echo '   HAVE_CAPABILITY is deliberately left undefined: it pulls in'; \
	      echo '   <sys/capability.h> and -lcap, so a standalone-built helper does not'; \
	      echo '   drop privileges via libcap. The ../config.h copy is PREFERRED whenever'; \
	      echo '   a configured tree has one.'; \
	      echo ''; \
	      echo '   HAVE_LIBWEBSOCKETS is defined only when libwebsockets >= 3.1.0 was'; \
	      echo '   found (or LWS=1). Without it the remote-capture websocket transport is'; \
	      echo '   compiled out; local IPC capture is unaffected. */'; \
	      echo '#ifndef __KIS_STANDALONE_CONFIG_H__'; \
	      echo '#define __KIS_STANDALONE_CONFIG_H__'; \
	      echo '#define $(BASELINE_SYS_DEFINE) 1'; \
	      if [ "$(BASELINE_LWS)" = "1" ]; then echo '#define HAVE_LIBWEBSOCKETS 1'; fi; \
	      echo '#define STATUS_MAX 1024'; \
	      echo '#endif'; \
	    } > $@.tmp; \
	    src="generated ($(BASELINE_SYS_DEFINE), no ../config.h; standalone)"; \
	fi; \
	if cmp -s $@.tmp $@; then rm -f $@.tmp; else mv $@.tmp $@; echo "  config.h  <- $$src"; fi; \
	if grep -q '^#define HAVE_LIBWEBSOCKETS' $@; then \
	    echo "  websockets: ON  (links $(BASELINE_LWS_LIBS))"; \
	else \
	    echo "  websockets: OFF -- remote-capture (--connect ws://) compiled out; local IPC unaffected"; \
	fi

# version.c is NOT tracked -- the autoconf build generates it via
# tools/mkversion.sh, which writes into the tree root. Rendering our own copy
# inside $(BASELINE_DIR) keeps this target from mutating the parent tree (and
# from racing a real ./configure for the same file).
#
# It depends on the makefile that renders it. With no prerequisite, a host that
# built it once would keep that copy forever, so a symbol added to the recipe
# (e.g. VERSION_POC_NAME, which capture_framework.c's cf_version_string()
# references) would fail the baseline link with "undefined reference" on a host
# where nothing but the recipe had changed.
$(BASELINE_DIR)/version.c: $(BASELINE_PLATFORM_MK)
	@mkdir -p $(BASELINE_DIR)
	@{ \
	  echo '/* Generated by capture_cell_diag/baseline_platform.mk (baseline target). */'; \
	  echo 'const char *VERSION_POC_NAME = "KismetCell";'; \
	  echo 'const char *VERSION_MAJOR = "0";'; \
	  echo 'const char *VERSION_MINOR = "0";'; \
	  echo 'const char *VERSION_TINY = "0";'; \
	  echo 'const char *VERSION_GIT_COMMIT = "standalone";'; \
	  echo 'const char *VERSION_BUILD_TIME = "standalone";'; \
	} > $@
	@echo "  version.c <- generated (standalone)"

.PHONY: baseline-platform-guard baseline-config-force
baseline-config-force:
