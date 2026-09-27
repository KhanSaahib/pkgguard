# Security Policy

pkgguard exists to be run against untrusted, possibly malicious packages, so
bugs that make pkgguard *itself* unsafe to run are taken seriously.

## Supported versions

Security fixes are made on the latest release. Please upgrade before reporting.

## What counts as a vulnerability

Please report these privately:

- An archive that makes pkgguard write, overwrite or link anything outside
  its temporary extraction directory.
- Any way to make pkgguard execute code from the package it is scanning.
- Crafted input that crashes pkgguard or makes it hang or exhaust memory or
  disk (for example catastrophic regex backtracking or a decompression bomb
  that gets past the size limits), since this can be used to bypass a CI gate.

**Detection bypasses are not vulnerabilities.** pkgguard is a heuristic
scanner, and a malicious pattern it misses is a false negative. Please open a
regular **Detection issue** for those so the fix can be discussed in public.

## How to report

Use GitHub's private vulnerability reporting:
**[Report a vulnerability](https://github.com/KhanSaahib/pkgguard/security/advisories/new)**.

Please include the pkgguard version, Python version and OS, and a minimal
proof of concept (an archive or file, or a script that generates one).

You can expect an acknowledgement within a week. Once a fix is ready, it will
be released with a GitHub Security Advisory crediting you, unless you'd
prefer not to be named.
