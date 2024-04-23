extra_sources = []
extra_cargs = []
extra_ldargs = []
fuzzing_engine = []


extra_cargs += '-g'
if fuzzer_build
  extra_cargs += '-fsanitize=fuzzer,address'
  extra_cargs += '-fsanitize-coverage=edge,indirect-calls,trace-cmp'
  extra_cargs += '-DCUSTOM_MUTATOR'
  extra_cargs += '-fprofile-instr-generate'
  extra_cargs += '-fcoverage-mapping'

  extra_ldargs += '-fsanitize=fuzzer,address'
  extra_ldargs += '-fprofile-instr-generate'
  extra_ldargs += '-fcoverage-mapping'
endif

deps = [glib_dep, libslirp_dep, platform_deps]

exes = [['fuzz-ip-header', ['slirp_fuzz_ip_header.c', 'helper.c']],
        ['fuzz-udp', ['slirp_fuzz_udp.c', 'helper.c']]]

if fuzzer_build
  foreach exe : exes
    executable(
      exe[0], exe[1],
      dependencies : deps,
      c_args: extra_cargs,
      link_args: extra_ldargs,
    )
  endforeach
endif

if fuzz_reproduce
  executable(['reproducer', ['reproducer.c']],
    dependencies: deps,
    c_args: extra_cargs,
    link_args: extra_ldargs,
  )
endif
