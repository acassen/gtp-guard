
# Meson build system

Here are some tips and useful commands for gtp-guard build system


### Getting started

```
apt-get install meson clang llvm
git clone git@github.com:acassen/gtp-guard.git
cd gtp-guard
make
```

The first `make` command will configure the project with default
values. There's nothing much configurable, anyway.

Generated objects and artifacts all goes to `build` directory, which
can be changed with the `BUILDDIR` environment variable.


### Cleaning

Dependencies are usually well handled, sometimes is it necessary to
clean build directory. Here the soft version:

```
make clean
```

And the hard version:

```
rm -rf build
```


### Verbose build

To have a more verbose build, for instance to see invoked compiler and
other commands, the `V=1` variable must be set in the environment:

```
make V=1
```



### Use clang instead of gcc

`gcc` is usually the default `cc` command, but `clang` can be used to
compile the user application (eBPF are always compiled with clang).  A
'fresh' build directory must be used:

```
rm -rf build
CC=clang make
```

It is possible to have different build directory, one for `gcc` and another for `clang`:

```
# gcc
make

#clang
BUILDDIR=build-clang CC=clang make
```



### Self-tests

To run self-tests:

```
make test
```

To run a single test:

```
make test TEST=cdrfwd_test
```

Binaries are generated on `build/tools/selftests/`, if there is a
need to launch them manually.

More powerful actions can be achieved by using meson directly, see
https://mesonbuild.com/Unit-tests.html

```
meson test -C build --list
```

Starting from meson 1.7.0, self-tests programs are only compiled when tests are launched.
Before then, self-tests programs are compiled, but not run nor installed.
