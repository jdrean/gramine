host_tyche_driver_h = configure_file(
    input: 'host_tyche_driver.h.in',
    output: 'host_tyche_driver.h',
    configuration: conf_tyche,
)

pal_sgx_inc = [
    include_directories(
        '.',
    ),
]

# Page table includes.
tyche_pts_include = conf_tyche.get('CONFIG_TYCHE_PTS') / 'include'
tyche_pts_src = [
  conf_tyche.get('CONFIG_TYCHE_PTS') / 'src/lib.c',
  conf_tyche.get('CONFIG_TYCHE_PTS') / 'src/x86_64_pt.c',
]

tyche_inc = [
    includes_pal_common,
    pal_sgx_inc,
    include_directories(
        '../../../include/arch/@0@/linux'.format(host_machine.cpu_family()),
        '../../../include/host/linux-common',
        conf_tyche.get('CONFIG_TYCHE_DRIVER_INCLUDE'),
        conf_tyche.get('CONFIG_TYCHE_CONTALLOC_INCLUDE'),
        conf_tyche.get('CONFIG_TYCHE_DRIVER_CAPA_INCLUDE'),
        conf_tyche.get('CONFIG_TYCHE_DRIVER_COMMON_INCLUDE'),
        conf_tyche.get('CONFIG_TYCHE_DRIVER_DLL_INCLUDE'),
        conf_tyche.get('CONFIG_TYCHE_SDK_INCLUDE'),
        tyche_pts_include,
    ),
]

# below headers are SGX-infrastructure generic and required by e.g. RA-TLS libs
install_headers('sgx_arch.h', 'sgx_attest.h', subdir : 'gramine')

cflags_pal_sgx = [
    cflags_pal_common,
    '-DHOST_TYPE=Linux-Tyche',
    # Some of the code uses `alignof` on expressions, which is a GNU extension. Silence Clang - it
    # complains but does support it.
    '-Wno-gnu-alignof-expression',
    # Tyche specific configuration
    conf_tyche.get('RUN_WITH_KVM'),
    '-DTYCHE_NO_ELF=1',
    '-DTYCHE_USER_SPACE=2',
]

pal_sgx_generated_offsets_print = executable('pal-sgx-generated-offsets-print',
    'generated_offsets.c',
    generated_offsets_print_src,
    include_directories: tyche_inc,
    c_args: cflags_pal_sgx,
)

pal_sgx_asm_offsets_h = custom_target('asm-offsets.h[pal-sgx]',
    command: [pal_sgx_generated_offsets_print, '--h'],
    capture: true,
    output: 'asm-offsets.h',
)

pal_sgx_offsets_py = custom_target('_graminelibos_offsets.py',
    command: [pal_sgx_generated_offsets_print, '--py'],
    capture: true,
    output: '_graminelibos_offsets.py',

    install: true,
    install_dir: python3_platlib,
)

pal_sgx_map = custom_target('pal.map',
    command: [gen_pal_map_prog, '@INPUT@', '@OUTPUT@'],
    input: ['../../pal_symbols', 'pal.map.template'],
    output: 'pal.map',
)

pal_sgx_lds = meson.current_source_dir() / 'enclave.lds'

libpal_sgx = shared_library('pal',
    'common_manifest_sgx_parser.c',
    'enclave_api.S',
    'enclave_ecalls.c',
    'enclave_edmm.c',
    'enclave_entry.S',
    'enclave_framework.c',
    'enclave_ocalls.c',
    'enclave_platform.c',
    'enclave_xstate.c',
    'pal_console.c',
    'pal_devices.c',
    'pal_eventfd.c',
    'pal_events.c',
    'pal_exception.c',
    'pal_files.c',
    'pal_main.c',
    'pal_memory.c',
    'pal_misc.c',
    'pal_object.c',
    'pal_pipes.c',
    'pal_process.c',
    'pal_rtld.c',
    'pal_sockets.c',
    'pal_streams.c',
    'pal_threading.c',
    pal_sgx_asm_offsets_h,
    pal_common_sources,
    pal_linux_common_sources_enclave,
    host_tyche_driver_h,

    include_directories: tyche_inc,

    c_args: [
        cflags_pal_sgx,
        cflags_sanitizers,
        cflags_custom_stack_protector,
        '-DIN_ENCLAVE',
    ],

    link_args: [
        '-nostdlib',

        # For PAL symbol resolution, we use old-style hash (DT_HASH) table instead of the default
        # GNU hash (DT_GNU_HASH) table -- to figure out the number of dynamic symbols in the SYMTAB
        # symbol table
        '-Wl,--hash-style=sysv',

        # PAL is expected to be linked with RELRO (Relocation Read-Only)
        '-Wl,-zrelro',
        '-Wl,-znow',

        '-Wl,-zcombreloc',
        '-Wl,-zdefs',
        '-Wl,--version-script=@0@'.format(pal_sgx_map.full_path()),
        '-Wl,-T@0@'.format(pal_sgx_lds),
        '-Wl,--eh-frame-hdr',
    ],

    link_depends: [
        pal_sgx_map,
        pal_sgx_lds,
    ],

    dependencies: [
        common_dep,
        cryptoadapter_dep,
        ioctls_dep,
    ],

    install: true,
    install_dir: pkglibdir / 'tyche',
)

# host (untrusted runtime)
libpal_sgx_host = executable('loader',
    'common_manifest_sgx_parser.c',
    'host_ecalls.c',
    'host_entry.S',
    'host_exception.c',
    'host_framework.c',
    'host_log.c',
    'host_main.c',
    'host_ocalls.c',
    'host_perf_data.c',
    'host_platform.c',
    'host_process.c',
    'host_profile.c',
    'host_syscall.c',
    'host_thread.c',
    pal_linux_common_sources_host,
    pal_sgx_asm_offsets_h,
    # aesm_proto_ch,
    conf_tyche.get('FILE_TYCHE_BACKEND_C'),
    host_tyche_driver_h,
    tyche_pts_src,
    'pal_pt_mapper.c',
    'host_pal_shared_memory.c',

    include_directories: tyche_inc,
    c_args: [
        cflags_pal_sgx,
        cflags_sanitizers,

        # host part of PAL uses stack protector with standard parameters (not the ones defined for
        # PAL/LibOS)
        '-fstack-protector-strong',

        # Tyche specific configuration
        conf_tyche.get('RUN_WITH_KVM'),
        '-DTYCHE_NO_ELF=1',
        '-DTYCHE_USER_SPACE=2',
    ],
    link_args: [
        '-Wl,-zrelro',
        '-Wl,-znow',
    ],
    pie: true,

    dependencies: [
        common_dep,
        protobuf_dep,
        vtune_dep,
        dl_dep,
    ],

    install: true,
    install_dir: pkglibdir / 'tyche',
)

libpal_sgx_dep = declare_dependency(
    link_with: libpal_sgx,
    include_directories: includes_pal_common,
)

if debug
    custom_target('libpal.so.map',
        input: libpal_sgx,
        command: gen_symbol_map_cmd,
        capture: true,
        output: 'libpal.so.map',

        install: true,
        install_dir: pkglibdir / 'tyche',
    )

    custom_target('loader.map',
        input: libpal_sgx_host,
        command: gen_symbol_map_cmd,
        capture: true,
        output: 'loader.map',

        install: true,
        install_dir: pkglibdir / 'tyche',
    )

    #shared_library('sgx_gdb',
    #    'gdb_integration/sgx_gdb.c',

    #    # just `sgx_gdb.so`, without `lib`
    #    name_prefix: '',

    #    c_args: [
    #        # optimize even in a debug build
    #        '-O3',
    #    ],

    #    install: true,
    #    install_dir: pkglibdir / 'sgx/gdb_integration',
    #)

    install_data(
        'gdb_integration/gramine_sgx.gdb',
        'gdb_integration/gramine_sgx_gdb.py',
        install_dir: pkglibdir / 'sgx/gdb_integration',
    )
endif
