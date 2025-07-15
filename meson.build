# SPDX-License-Identifier: AGPL-3.0-or-later

#
# know working version are ubuntu 24.04 (1.3.2) and debian 13 (1.7.0)
#
project('gtp-guard', 'c',
	version : files('VERSION'),
	meson_version: '>= 1.3.2',
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

# get programs to compile ebpf
clang = find_program('clang', required: true)
llc = find_program('llc', required: true)
arch = 'x86'

# libraries this project is using
libcrypt_dep = dependency('libcrypt')
libelf_dep = dependency('libelf')

# check for system's libbpf 
# if not found or version too old, fetch and compile libbpf from git
libbpf_dep = dependency('libbpf', version : '>=1.5.0', fallback: ['libbpf', 'libbpf_dep'])
libbpf_inc = libbpf_dep.get_variable('includedir') + '/bpf'
add_project_arguments('-I' + libbpf_inc, language: 'c')

src = []
inc = []

subdir('lib')
subdir('src')

gtp_guard_exe = executable(
  'gtp-guard', src,
  include_directories: inc,
  dependencies: [libbpf_dep, libcrypt_dep, libelf_dep],
  link_args: [ '-lresolv' ],
  install: true,
)

subdir('tools/selftests')
