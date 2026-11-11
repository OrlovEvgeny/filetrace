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
`brew install protobuf-c libnghttp2 pkgconf` provides the libraries. The
README lists the versions needed.

## Before opening a pull request

```sh
mise run ci           # what every pull request is checked with: lint and unit tests
mise run test:linux   # adds the integration tests; needs Docker
```

`mise run lint` covers formatting (`mise run fmt` fixes it), the protobuf
schema and the generated code under `gen/` (`mise run gen` regenerates it),
the shell scripts, the workflows and the commit subjects.

A change to packaging, the service definitions or the installer is checked by
the package tests, described under Tests in the README.

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
The integration tests also run nightly on the oldest supported kernels.
