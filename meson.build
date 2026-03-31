# SPDX-License-Identifier: AGPL-3.0-or-later

#
# know working version are ubuntu 22.04 (0.61.2), 24.04 (1.3.2)
# and debian 13 (1.7.0)
#
project('gtp-guard', 'c',
	version : files('VERSION'),
	meson_version: '>= 0.61.2',
	license: 'AGPL-3.0-or-later',
	default_options : [
	  'buildtype=debugoptimized',
	  'werror=false',
	  'warning_level=2',
	  'c_std=gnu99'
	]
)

add_project_arguments('-D_GNU_SOURCE', language: 'c')
add_project_arguments('-Wstrict-prototypes', language: 'c')
add_project_arguments('-Wno-extra', language: 'c')
add_project_arguments('-ggdb', language: 'c')

# config.h header
build_date = run_command('date', '+%Y/%m/%d', check: true).stdout().strip()
conf_data = configuration_data()
conf_data.set('VERSION', meson.project_version())
conf_data.set('BUILD_DATE', build_date)
configure_file(input : 'lib/config.h.in',
               output : 'config.h',
               configuration : conf_data)

# get programs to compile ebpf
clang = find_program('clang', required: true)
llc = find_program('llc', required: true)

# libraries this project is using
libelf_dep = dependency('libelf')
libpcap_dep = dependency('libpcap')

# check for system's libbpf
# if not found or version too old, fetch and compile libbpf from git
libbpf_dep = dependency('libbpf', version : '>=1.5.0', fallback: ['libbpf', 'libbpf_dep'])
libbpf_inc = libbpf_dep.get_variable('includedir') + '/bpf'
add_project_arguments('-I' + libbpf_inc, language: 'c')

# if using our own compiled libbpf, also use provided include/uapi/linux
# instead of /usr/include/linux
libbpf_uapi_inc = libbpf_dep.get_variable('includeuapidir', default_value: '')
if libbpf_uapi_inc != ''
  add_project_arguments('-I' + libbpf_uapi_inc, language: 'c')
endif

# need libxdp only for xsks
libxdp_dep = dependency('libxdp', version : '>=1.5.0', fallback: ['libxdp', 'libxdp_dep'])

# get Clang's default include paths, to compile bpf
clang_includes = []
search_start = false
foreach line : run_command(clang, '-v', '-E', '-', check: false, capture: true).stderr().split('\n')
	if search_start
		if line.strip() == 'End of search list.'
			break
		endif
		if line.strip().startswith('/')
			clang_includes += ['-idirafter', line.strip()]
		endif
	elif line.strip() == '#include <...> search starts here:'
		search_start = true
	endif
endforeach


src = []
inc = []

subdir('lib')
subdir('src')

gtp_guard_exe = executable(
  'gtp-guard', src,
  include_directories: inc,
  dependencies: [libbpf_dep, libxdp_dep, libelf_dep, libpcap_dep],
  link_args: [ '-lresolv' ],
  install_dir: get_option('sbindir'),
  install: true,
)

subdir('tools/selftests')
