extra_sources = []
fuzzing_engine = []

if want_libfuzzer
  fuzzing_engine = meson.get_compiler('cpp').find_library('Fuzzer')
elif want_ossfuzz
  fuzzing_engine = meson.get_compiler('cpp').find_library('FuzzingEngine')
endif

deps = [glib_dep, libslirp_dep, platform_deps]
if fuzzer_build
  deps += fuzzing_engine
else
  code = '''
void main() {}
'''
  if cc.links(code, name : 'fuzzer driver check')
    extra_sources += 'fuzz-main.c'
  endif
endif

executable(
  'fuzz-input', [extra_sources, 'fuzz-input.c'],
  dependencies : deps,
)
