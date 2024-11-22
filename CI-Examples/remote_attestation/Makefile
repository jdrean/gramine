# Set the default target
.PHONY: all
all: attestation attestation.manifest
ifeq ($(SGX),1)
all: attestation attestation.manifest.sgx attestation.sig
endif

# Compiler settings
CC ?= gcc
CFLAGS = -Wall -Wextra

# You'll need to adjust this path to where your Gramine source is
GRAMINE_SRC ?= ../../

CFLAGS += -I$(GRAMINE_SRC)/pal/src/host/linux-sgx

SOURCES = attestation.c $(GRAMINE_SRC)/pal/src/host/linux-sgx/enclave_api.S rw_file.c

LDFLAGS = -pthread
LIBS = -lmbedtls -lmbedcrypto -lmbedx509

attestation: $(SOURCES)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

# Generate the manifest files
%.manifest: %.manifest.template
	gramine-manifest \
		-Dlog_level=debug \
		-Darch_libdir=/lib/x86_64-linux-gnu \
		$< > $@

# Generate the SGX-specific manifest
%.manifest.sgx: %.manifest
	gramine-sgx-sign \
		--manifest $< \
		--output $@

.PHONY: clean
clean:
	$(RM) attestation *.manifest *.manifest.sgx *.sig *.token *.o

.PHONY: distclean
distclean: clean