# Copyright (C) 2023 Gramine contributors
# SPDX-License-Identifier: BSD-3-Clause

# Build APSI as follows:
#
# - make               -- create non-SGX no-debug-log manifest
# - make SGX=1         -- create SGX no-debug-log manifest
# - make SGX=1 DEBUG=1 -- create SGX debug-log manifest
#
# Any of these invocations clones APSI' git repository and builds APSI in
# default configuration and in the latest-to-date (6.0.5) version.
#
# By default, APSI uses poll/epoll mechanism of Linux. To build APSI with
# select, use `make USE_SELECT=1`. For correct re-builds, always clean up
# APSI source code beforehand via `make distclean`.
#
# Use `make clean` to remove Gramine-generated files and `make distclean` to
# additionally remove the cloned APSI git repository.

################################# CONSTANTS ###################################

# directory with arch-specific libraries, used by APSI
# the below path works for Debian/Ubuntu; for CentOS/RHEL/Fedora, you should
# overwrite this default like this: `ARCH_LIBDIR=/lib64 make`
ARCH_LIBDIR ?= /lib/$(shell $(CC) -dumpmachine)

SRCDIR = src

ifeq ($(DEBUG),1)
GRAMINE_LOG_LEVEL = debug
else
GRAMINE_LOG_LEVEL = error
endif

.PHONY: all
all: sealAPSI.manifest
ifeq ($(SGX),1)
all: sealAPSI.manifest.sgx sealAPSI.sig
endif

################################ APSI MANIFEST ###############################

# The template file is a Jinja2 template and contains almost all necessary
# information to run APSI under Gramine / Gramine-SGX. We create
# sealAPSI.manifest (to be run under non-SGX Gramine) by replacing variables
# in the template file using the "gramine-manifest" script.

sealAPSI.manifest: sealAPSI.manifest.template
	gramine-manifest \
		-Dlog_level=$(GRAMINE_LOG_LEVEL) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		$< > $@

# Manifest for Gramine-SGX requires special "gramine-sgx-sign" procedure. This
# procedure measures all APSI trusted files, adds the measurement to the
# resulting manifest.sgx file (among other, less important SGX options) and
# creates sealAPSI.sig (SIGSTRUCT object).

# Make on Ubuntu <= 20.04 doesn't support "Rules with Grouped Targets" (`&:`),
# see the helloworld example for details on this workaround.
sealAPSI.sig sealAPSI.manifest.sgx: sgx_outputs
	@:

.INTERMEDIATE: sgx_outputs
sgx_outputs: sealAPSI.manifest $(SRCDIR)/src/sealAPSI
	gramine-sgx-sign \
		--manifest sealAPSI.manifest \
		--output sealAPSI.manifest.sgx


############################## RUNNING TESTS ##################################

.PHONY: start-native-server
start-native-server: all
	./sealAPSI --save '' --protected-mode no

ifeq ($(SGX),)
GRAMINE = gramine-direct
else
GRAMINE = gramine-sgx
endif

# Note that command-line arguments are hardcoded in the manifest file.
.PHONY: start-gramine-server
start-gramine-server: all
	$(GRAMINE) sealAPSI

################################## CLEANUP ####################################

.PHONY: clean
clean:
	$(RM) *.token *.sig *.manifest.sgx *.manifest *.rdb

.PHONY: distclean
distclean: clean
	$(RM) -r $(SRCDIR) APSI.tar.gz
