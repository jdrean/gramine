# Copyright (C) 2023 Gramine contributors
# SPDX-License-Identifier: BSD-3-Clause

# Build Redis as follows:
#
# - make               -- create non-SGX no-debug-log manifest
# - make SGX=1         -- create SGX no-debug-log manifest
# - make SGX=1 DEBUG=1 -- create SGX debug-log manifest
#
# Any of these invocations clones Redis' git repository and builds Redis in
# default configuration and in the latest-to-date (6.0.5) version.
#
# By default, Redis uses poll/epoll mechanism of Linux. To build Redis with
# select, use `make USE_SELECT=1`. For correct re-builds, always clean up
# Redis source code beforehand via `make distclean`.
#
# Use `make clean` to remove Gramine-generated files and `make distclean` to
# additionally remove the cloned Redis git repository.

################################# CONSTANTS ###################################

# directory with arch-specific libraries, used by Redis
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
all: sealexamples.manifest
ifeq ($(SGX),1)
all: sealexamples.manifest.sgx sealexamples.sig
endif

################################ REDIS MANIFEST ###############################

# The template file is a Jinja2 template and contains almost all necessary
# information to run Redis under Gramine / Gramine-SGX. We create
# sealexamples.manifest (to be run under non-SGX Gramine) by replacing variables
# in the template file using the "gramine-manifest" script.

sealexamples.manifest: sealexamples.manifest.template
	gramine-manifest \
		-Dlog_level=$(GRAMINE_LOG_LEVEL) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		$< > $@

# Manifest for Gramine-SGX requires special "gramine-sgx-sign" procedure. This
# procedure measures all Redis trusted files, adds the measurement to the
# resulting manifest.sgx file (among other, less important SGX options) and
# creates sealexamples.sig (SIGSTRUCT object).

# Make on Ubuntu <= 20.04 doesn't support "Rules with Grouped Targets" (`&:`),
# see the helloworld example for details on this workaround.
sealexamples.sig sealexamples.manifest.sgx: sgx_outputs
	@:

sealexamples: ~/SEAL/build/bin/sealexamples
	cp $< $@

.INTERMEDIATE: sgx_outputs
sgx_outputs: sealexamples.manifest sealexamples
	gramine-sgx-sign \
		--manifest sealexamples.manifest \
		--output sealexamples.manifest.sgx


############################## RUNNING TESTS ##################################

ifeq ($(SGX),)
GRAMINE = gramine-direct
else
GRAMINE = gramine-sgx
endif

# Note that command-line arguments are hardcoded in the manifest file.
.PHONY: run_enclave
run_enclave: all
	@echo "Starting enclave measurement at $$(date +%s.%N)..."
	$(GRAMINE) sealexamples
	@echo "Enclave started at $$(date +%s.%N)"

################################## CLEANUP ####################################

.PHONY: clean
clean:
	$(RM) *.token *.sig *.manifest.sgx *.manifest *.rdb

.PHONY: distclean
distclean: clean
	$(RM) -r $(SRCDIR) redis.tar.gz
