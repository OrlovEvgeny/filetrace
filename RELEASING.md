# Releasing

## Versions

A version reads `year.month.patch.build`, and a release is tagged with it and
its channel: `v26.11.1.80-stable`.

| Part | Meaning |
|---|---|
| `26.11` | The line, named after the month (UTC) it was cut from `master`. It lives on the branch `26.11`. |
| `1` | The patch: 1 for the release that opens the line, one more for each release of the line after it. |
| `80` | The build: the commits since the release this one follows. |
| `-stable`, `-lts` | The channel of the line. An lts line is one that keeps receiving patches. |
| `-prestable` | A candidate. It is published as a pre-release, reaches no package repository, and the release that follows counts its build as if the candidate were not there. |

The tags are the only record of a version. A build without a tag on its
commit reports the release before it and the distance: `26.11.1.80+5.gabc1234`.
`mise run version` prints what the current tree builds as.

One line opens per month. A second release in the same month is a patch of
that line.

## Cutting a release

```sh
mise run release -- new                      # a new line from master
mise run release -- new --lts                # the same, as an lts line
mise run release -- patch --ref 26.11        # the next patch of a line
mise run release -- new --prestable          # a candidate
mise run release -- new --dry-run            # everything short of publishing
```

Each prints the version it will produce and starts the `Release` workflow,
which can also be started from the Actions tab. The workflow

1. computes the version and refuses a commit that is not on `master` (for a
   new line) or on the branch of the line (for a patch);
2. runs every check of continuous integration on that commit, with the
   binaries and packages built as that version;
3. waits for approval of the `release` environment;
4. signs the rpm and apk packages, writes `SHA256SUMS`, attests the files,
   tags the commit, and publishes the GitHub release with notes generated
   from the commit subjects;
5. opens the branch of a new line;
6. rebuilds the apt, yum and apk repositories from every published release
   and deploys them, with the installer, to GitHub Pages;
7. updates the formula in the Homebrew tap, for the newest release only;
8. opens a pull request that adds the notes to `CHANGELOG.md`.

A candidate stops after step 4.

## Patching a line

Bring the fixes to the branch of the line, then release with
`patch --ref <line>`. While the line has received
nothing of its own, moving its branch forward to `master` and releasing a
patch is how a second release in a month is made.

## When a release stops halfway

Every job can be run again from the workflow run: an existing tag is accepted
if it names the same commit, a draft release is filled and published, and the
site is rebuilt from what is published. `Download site` rebuilds and deploys
the repositories on its own.

A published release cannot be changed. A bad one is followed by a patch.

## Setting the repository up

`tools/release/github-setup.sh` applies the settings below and is safe to run
again:

- GitHub Pages deployed by Actions, immutable releases, private vulnerability
  reports;
- the `release` environment, with the repository owner as its reviewer;
- rules: `master` and the line branches keep a linear history and can be
  neither rewritten nor deleted; release tags can be neither moved nor
  deleted;
- rebase as the only way to merge, and permission for workflows to open pull
  requests.

Three secrets of the `release` environment hold the keys:

| Secret | Holds | Without it |
|---|---|---|
| `FILETRACE_GPG_KEY` | OpenPGP private key for the apt and yum repositories and the rpm packages | the package repositories are not updated |
| `FILETRACE_APK_KEY` | RSA private key for the apk repository and packages | the same |
| `HOMEBREW_TAP_KEY` | SSH deploy key with write access to the tap | the formula is not updated |

`tools/release/keys.sh <directory>` creates the first two;
`tools/release/github-setup.sh --keys <directory>` stores them and creates
the third. Keep a copy of the directory somewhere safe and offline: the keys
have no passphrase, and losing them means every user has to trust new ones.

To replace a key, create a new one, store it, and run `Download site`: the
repositories are signed again and serve the new public key. Users of apt and
yum then fetch `gpg.key` again, and users of apk `filetrace.rsa.pub`.
