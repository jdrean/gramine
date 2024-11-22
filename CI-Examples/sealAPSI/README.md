# APSI

This directory contains the Makefile and the template manifest for the most
recent version of APSI (as of this writing, version 6.0.5).

The Makefile and the template manifest contain extensive comments and are made
self-explanatory. Please review them to gain understanding of Gramine and
requirements for applications running under Gramine. If you want to contribute a
new example to Gramine and you take this APSI example as a template, we
recommend to remove the comments from your copies as they only add noise (see
e.g. Memcached for a "stripped-down" example).


# Quick Start

```sh
# build APSI and the final manifest
make SGX=1

# run original APSI against a benchmark (APSI-benchmark supplied with APSI)
./APSI-server --save '' &
src/src/APSI-benchmark
kill %%

# run APSI in non-SGX Gramine against a benchmark (args are hardcoded in manifest)
gramine-direct APSI-server &
src/src/APSI-benchmark
kill %%

# run APSI in Gramine-SGX against a benchmark (args are hardcoded in manifest)
gramine-sgx APSI-server &
src/src/APSI-benchmark
kill %%
```

# Why this APSI configuration?

Notice that we run APSI with the `save ''` setting. This setting disables
saving DB to disk (both RDB snapshots and AOF logs). We use this setting
because:

- saving DB to disk is a slow operation (APSI uses fork internally which is
  implemented as a slow checkpoint-and-restore in Gramine and requires creating
  a new SGX enclave);
- saved RDB snapshots and AOF logs must be encrypted and integrity-protected for
  DB confidentiality reasons, which requires marking the corresponding
  directories and files as `encrypted` in Gramine manifest; we skip it for
  simplicity.

In Gramine case, this setting is hardcoded in the manifest file, see
`loader.argv` there.

# APSI with Select

By default, APSI uses the epoll mechanism of Linux to monitor client
connections. To test APSI with select, add `USE_SELECT=1`, e.g., `make SGX=1
USE_SELECT=1`.
