# Contributing

## Setting up

[mise](https://mise.jdx.dev) installs the tools at the versions `mise.lock`
records and names the commands used day to day:

```sh
mise install
mise tasks
```

The compiler and the three libraries are not mise's to install. On Linux they
come with the development container, which `mise run linux -- <command>`
enters; on macOS, where the command line and the unit tests build,
`brew install protobuf-c libnghttp2 pkgconf` provides the libraries. A build
outside the container needs Clang 19 or later (C23 and `#embed`), CMake 3.25,
libbpf 1.3, `llvm-strip`, protobuf-c 1.3 and nghttp2 1.60.

## Before opening a pull request

```sh
mise run ci           # what every pull request is checked with: lint and unit tests
mise run test:linux   # adds the integration tests; needs Docker
```

`mise run lint` covers formatting (`mise run fmt` fixes it), the protobuf
schema and the generated code under `gen/` (`mise run gen` regenerates it),
the shell scripts, the workflows and the commit subjects.

A change to packaging, the service definitions or the installer is checked by
the package tests, which need Docker: `mise run dist`, `mise run package`,
then `mise run test:package`.

A change to the screen of `filetrace top` is judged by looking at it.
`mise run shots:top` draws every screen from the simulated agent
(`tests/sim`) and prints the directory, under the system's temporary one,
where it saved them as text, HTML and PNG. It builds on
`tools/dev/tuishot.py`, which runs any terminal program on a pseudo-terminal,
presses the keys it is given and saves the screen. Both need only `python3`
(3.9 or later, no packages); the PNG files are rendered by Chrome or Chromium
and are left out where neither is installed.

## Commits and branches

Work happens on a branch named `<type>/<short-description>`. A contribution
reaches `master` through a pull request, which is rebased onto it: every
commit of the branch lands as it is. A commit holds one change, and its subject reads

```
<type>: <subject>
```

with a type of `feat`, `fix`, `perf`, `refactor`, `docs`, `test` or `chore`,
and a subject in the imperative, in lowercase, of at most 72 characters in
all. A change that breaks compatibility carries `!` after the type.

The subjects are what users read: the notes of a release are the `feat`,
`perf` and `fix` subjects since the release before, and the changes marked
with `!`. `mise run changelog` shows what the next release would say.

## Continuous integration

Every pull request and every push to `master` builds and tests on Linux for
x86-64 and arm64 and on macOS, runs the unit tests under the sanitizers,
builds the static release binaries and the packages from them, and installs
those packages in containers. The check named `CI` passes when all of that
did.
The integration tests also run nightly on the oldest supported kernels, and so
does `mise run test:returns`, which checks on x86-64 kernels without and with
the uretprobe fix that the agent attaches return probes only where they kill
no process under seccomp.
