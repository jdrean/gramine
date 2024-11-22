# Set the default target
.PHONY: all
all: attestation

# Compiler settings
CC ?= gcc
CFLAGS = -Wall -Wextra -g

# Gramine paths - adjust these according to your Gramine installation
GRAMINE_DIR ?= /usr/local
GRAMINE_PKGCONFIG = $(GRAMINE_DIR)/lib/pkgconfig
GRAMINE_LIBDIR = $(GRAMINE_DIR)/lib/gramine
GRAMINE_INCLUDE = $(GRAMINE_DIR)/include

# Include paths
CFLAGS += -I$(GRAMINE_INCLUDE)
CFLAGS += -I$(GRAMINE_INCLUDE)/arch/x86_64/linux-sgx

# Libraries
LDFLAGS = -pthread
LIBS = -lmbedtls -lmbedcrypto -lmbedx509

attestation: attestation.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(LIBS)

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