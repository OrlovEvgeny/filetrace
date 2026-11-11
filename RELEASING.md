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
6. rebuilds the download site from every published release and uploads it:
   the files of each release, the apt, yum and apk repositories, and the
   installer;
7. writes the formula `filetrace@<line>` in the Homebrew tap
   `OrlovEvgeny/homebrew-filetrace`, and `filetrace` too when the release is
   the newest one;
8. opens a pull request that adds the notes to `CHANGELOG.md`.

A candidate is published and its files reach the download site. It opens no
branch, enters no repository and no formula, and adds nothing to the
changelog.

## Patching a line

Bring the fixes to the branch of the line, then release with
`patch --ref <line>`. While the line has received
nothing of its own, moving its branch forward to `master` and releasing a
patch is how a second release in a month is made.

## When a release stops halfway

Every job can be run again from the workflow run: an existing tag is accepted
if it names the same commit, a draft release is filled and published, a
public one is left as it is, and the site is rebuilt from what is published.
`Download site` rebuilds and uploads the site on its own.

A published release cannot be changed. A bad one is followed by a patch.

## The download site

`https://filetrace.eorlov.org` serves both the downloads and the
documentation. A Cloudflare Worker, `packaging/site/worker.js`, answers every
request to the domain: the paths below come from the R2 bucket, and everything
else from the documentation site on Mintlify (`filetrace.mintlify.site`).

| Path | Holds |
|---|---|
| `install.sh` | the installer of the newest release |
| `dist/<tag>/` | the files of a release, the same as its GitHub assets |
| `apt/`, `rpm/`, `apk/` | the package repositories, with the `stable` and `lts` channels |
| `channels/<channel>`, `versions/<version>` | what the installer reads to find a release |
| `gpg.key`, `apk/filetrace.rsa.pub` | the public halves of the signing keys |

The site is built from the GitHub releases every time, so the bucket holds
nothing that cannot be made again: `Download site` fills an empty one.

`tools/release/deploy.sh` uploads the release files, the packages and the
indexes named after their checksum first, to be cached for good, and the
indexes that name them after, to be checked on every request. A file under
`dist/` that differs from the bucket's stops the upload. Nothing is deleted,
so a client that holds an older index still finds every file it lists.

## Setting the repository up

`tools/release/github-setup.sh` applies the settings below and is safe to run
again:

- immutable releases and private vulnerability reports;
- the `release` environment, with the repository owner as its reviewer;
- rules: `master` and the line branches keep a linear history and can be
  neither rewritten nor deleted; release tags can be neither moved nor
  deleted;
- rebase as the only way to merge, and permission for workflows to open pull
  requests.

The bucket is set up once in the Cloudflare dashboard: create it, connect
`filetrace.eorlov.org` to it as a custom domain, and create an R2 API token
with Object Read & Write permission on that bucket alone. The custom domain
only gives the name a DNS record; the Worker's route on
`filetrace.eorlov.org/*` takes every request first and reads the bucket
through its binding. `R2_BUCKET_NAME=<bucket> mise run site:worker`
deploys the Worker with the settings in `packaging/site/wrangler.toml.in`,
after `npx wrangler login` with an account that may edit Workers and the
`eorlov.org` zone.

These secrets, of the repository or of its `release` environment, hold the
keys and the way into the bucket:

| Secret | Holds | Without it |
|---|---|---|
| `FILETRACE_GPG_KEY` | OpenPGP private key for the apt and yum repositories and the rpm packages | the packages are unsigned, and neither the site nor the formulae are updated |
| `FILETRACE_APK_KEY` | RSA private key for the apk repository and packages | the same |
| `R2_ACCOUNT_ID`, `R2_BUCKET_NAME` | the Cloudflare account and the bucket of the download site | neither the site nor the formulae are updated |
| `R2_ACCESS_KEY_ID`, `R2_SECRET_ACCESS_KEY` | the R2 API token | the same |
| `HOMEBREW_TAP_KEY` | SSH deploy key with write access to `OrlovEvgeny/homebrew-filetrace` | the formulae are not updated |

`tools/release/keys.sh <directory>` creates the two signing keys;
`tools/release/github-setup.sh --keys <directory>` stores them and creates
the deploy key. Keep a copy of the directory somewhere safe and offline: the
keys have no passphrase, and losing them means every user has to trust new
ones.

To replace a key, create a new one, store it, and run `Download site`: the
repositories are signed again and serve the new public key. Users of apt and
yum then fetch `gpg.key` again, and users of apk `filetrace.rsa.pub`.
