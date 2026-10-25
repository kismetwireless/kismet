# celltools/Makefile -- the entry point for the Python harnesses in this
# directory. See README.md.
#
# Deliberately a plain makefile, not generated from a Makefile.in by
# ./configure. Everything here is stdlib + pytest and compiles nothing, so
# requiring a configured tree would make these checks unrunnable in exactly the
# state where they are most worth running: a fresh clone nobody has built yet.
# `make -C celltools check` works on a clone that has never seen ./configure.
#
# PYTHON overrides the interpreter; any Python 3 with pytest installed will do.
# There is no project virtualenv and there must not be one -- see README.md.

PYTHON ?= python3
PYTEST_ARGS ?= -q

.PHONY: check
check: pytest-available
	$(PYTHON) -m pytest $(PYTEST_ARGS) $(dir $(lastword $(MAKEFILE_LIST)))tests

# An interpreter without pytest otherwise fails with a bare "No module named
# pytest" and exit 2, which reads like a failing suite. Say what to change
# instead. On a development workstation the system python3 often has no
# pytest while the checkout's venv does.
.PHONY: pytest-available
pytest-available:
	@$(PYTHON) -c 'import pytest' 2>/dev/null || { \
	    echo "*** celltools: '$(PYTHON)' has no pytest, so no test can run." >&2; \
	    echo "*** Point PYTHON at an interpreter that has it, e.g. a venv's:" >&2; \
	    echo "***   make -C celltools check PYTHON=/path/to/venv/bin/python" >&2; \
	    exit 2; \
	 }

.PHONY: preflight
preflight:
	$(dir $(lastword $(MAKEFILE_LIST)))kismet-host-preflight.sh
