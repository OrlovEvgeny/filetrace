# Security

## Reporting a vulnerability

Report it privately through
[a security advisory](https://github.com/OrlovEvgeny/filetrace/security/advisories/new),
not in a public issue. Expect an answer within a week.

## Supported versions

Fixes go into the newest release line and into the lts lines. `RELEASING.md`
explains how to tell them apart.

## Verifying a download

Every release lists the SHA-256 checksum of its files in `SHA256SUMS` and
carries a build attestation that ties each file to the workflow run and the
commit it came from:

```sh
gh attestation verify <file> --repo OrlovEvgeny/filetrace
```

The apt and yum repositories and the rpm packages are signed with the OpenPGP
key at <https://filetrace.eorlov.org/gpg.key>, the apk repository
and packages with <https://filetrace.eorlov.org/apk/filetrace.rsa.pub>.
