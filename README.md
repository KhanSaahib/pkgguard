# pkgguard

[![CI](https://github.com/KhanSaahib/pkgguard/actions/workflows/ci.yml/badge.svg)](https://github.com/KhanSaahib/pkgguard/actions/workflows/ci.yml)
![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)
![Dependencies: none](https://img.shields.io/badge/dependencies-none-brightgreen)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

**Catch malicious npm and PyPI packages by what they *do*, not just what they're called.**

pkgguard is an offline, dependency-free CLI that statically scans the actual
contents of an npm or PyPI package (lifecycle scripts, source files,
`setup.py`) for install-time malicious behavior *before* you run
`npm install` or `pip install`. It never executes package code.

```console
$ pkgguard scan totally-legit-lib-1.0.0.tgz
verdict: CRITICAL
summary: critical=3, medium=2

[CRITICAL] LIFECYCLE_REMOTE_EXEC - package.json:1
    'postinstall' script downloads and pipes remote content directly into a shell/decoder
[CRITICAL] WORM_SIBLING_WRITE - index.js:10
    Writes into another package's node_modules tree (self-propagation pattern seen in npm worm outbreaks)
[CRITICAL] SECRET_EXFIL_CHAIN - index.js:3
    Reads a credential/secret and also performs outbound network calls in the same file (possible exfiltration chain)
...
```

## Why

2025 saw a wave of self-propagating npm supply-chain worms (for example the
"Shai-Hulud" campaign) and repeated PyPI/npm incidents where a compromised
maintainer account or a typosquatted package shipped a `postinstall` or
`setup.py` payload. The payload harvested cloud credentials, SSH keys and CI
tokens, then republished itself into other packages the victim maintained.

Most defenses at this layer stop at the manifest: *is this name or version on
a known-bad list?* That's necessary but not sufficient. It does nothing for a
brand-new malicious package, or for a legitimate package whose maintainer
account was just compromised and pushed a fresh malicious version that nobody
has blocklisted yet.

pkgguard looks *inside* the package for the behaviors that matter, and it
does so with nothing but the Python standard library, so you can audit a
package you don't trust without first installing anything else you don't
trust.

## What it detects

| Rule ID | Severity | What it flags |
|---|---|---|
| `LIFECYCLE_REMOTE_EXEC` | critical | `preinstall`/`postinstall`/etc. script that pipes a download (`curl … \| sh`), a base64 blob, or an encoded PowerShell command into a shell |
| `SECRET_EXFIL_CHAIN` | critical | A file that reads a well-known secret (`NPM_TOKEN`, `GITHUB_TOKEN`, `AWS_*`, `~/.ssh/id_rsa`, `~/.npmrc`, browser `Login Data`, …) **and** makes an outbound network call |
| `WORM_SIBLING_WRITE` | critical | Code that writes into another package's `node_modules` tree |
| `WORM_SELF_PUBLISH` | critical | Code that shells out to `npm publish` |
| `LIFECYCLE_INLINE_EVAL` | high | Lifecycle script running inline code via `node -e` / `--eval` |
| `SETUP_CUSTOM_INSTALL_CMD` | high | `setup.py` overriding the setuptools `install` command via `cmdclass` |
| `SHELL_EXEC_SHELL_TRUE` | high | Python `os.system(...)` or `subprocess.*(..., shell=True)` |
| `OBFUSCATION_EVAL` | medium | `eval()`, `new Function()`, Python `exec()` |
| `OBFUSCATION_DECODE` | medium | `atob()`, `Buffer.from(…, 'base64')`, `base64.b64decode()` decode chains |
| `SECRET_ACCESS` | low | References a secret without any network call in the same file |
| `SHELL_EXEC` | low | JS child-process execution |
| `LARGE_FILE_NOT_SCANNED` | info | A source file above the 10 MiB scan limit, reported so it gets a manual look |

Every directory in the package is scanned except VCS metadata and bytecode
caches. That includes `dist/`, `build/`, `lib/` and `test/`: they ship inside
published packages, and a lifecycle script can execute code from any of them.
JavaScript/TypeScript files (`.js .mjs .cjs .ts .mts .cts .jsx .tsx`) and
Python files (`.py .pyw`, plus `setup.py`) are analyzed.

## Install

pkgguard has no runtime dependencies and supports Python 3.10+.

```bash
pip install "git+https://github.com/KhanSaahib/pkgguard@v0.1.0"
```

Or run it straight from a checkout with nothing installed, which is handy on
locked-down or air-gapped hosts:

```bash
git clone https://github.com/KhanSaahib/pkgguard
PYTHONPATH=pkgguard/src python -m pkgguard scan ./some-package-1.2.3.tgz
```

## Usage

```bash
# scan a downloaded npm tarball, PyPI sdist, or wheel
pkgguard scan ./some-package-1.2.3.tgz
pkgguard scan ./some_package-1.2.3.tar.gz
pkgguard scan ./some_package-1.2.3-py3-none-any.whl

# scan an already-extracted package directory
pkgguard scan ./node_modules/some-package

# machine-readable output and a stricter gate, e.g. for CI
pkgguard scan --json --fail-on high ./some-package-1.2.3.tgz
```

| Exit code | Meaning |
|---|---|
| `0` | No finding at or above `--fail-on` (default `critical`) |
| `1` | At least one finding at or above `--fail-on` |
| `2` | Usage error, unsupported target, or an archive pkgguard refused to extract |

### Getting a package without running it

Scan *before* install: once a package is installed, its install-time code has
already run.

- **npm:** `npm pack <name>@<version>` downloads the registry tarball without
  running any of its scripts.
- **PyPI wheels:** `pip download --no-deps --only-binary=:all: <name>==<version>`.
- **PyPI sdists:** download the `.tar.gz` directly from the package's
  "Download files" page (or the URLs in `https://pypi.org/pypi/<name>/<version>/json`).
  Avoid `pip download` for sdists: to read their metadata, pip may invoke the
  package's build backend, which means running its `setup.py`.

### In CI

Gate a new or updated dependency before it's installed:

```yaml
- name: Vet dependency with pkgguard
  run: |
    python -m pip install "git+https://github.com/KhanSaahib/pkgguard@v0.1.0"
    npm pack left-pad@1.3.0
    pkgguard scan --fail-on high left-pad-1.3.0.tgz
```

## How it works

- **Signals are combined, not scored in isolation.** Reading an environment
  variable is normal. Making a network call is normal. Doing both in the same
  file, with the variable being `NPM_TOKEN`, is how credential stealers work.
  pkgguard escalates to `critical` only on those combinations, following the
  capability-plus-indicator idea used by DataDog's GuardDog (see
  [NOTICE.md](NOTICE.md)).
- **Archive handling is defensive by construction.** Archives are untrusted
  input, so pkgguard never calls `extractall()`. It validates every member
  first and rejects path traversal (`../`, absolute and drive paths), links
  whose target leaves the extraction root, device files and FIFOs, and
  archives over 20,000 members or 512 MiB uncompressed. It then writes only
  regular files and directories itself. Links are never materialized, so one
  member can't set up a write outside the root for another. This works the
  same on every supported Python version, independent of `tarfile`'s
  extraction-filter defaults.
- **Stdlib only, at runtime and in tests.** No YARA, no third-party regex
  engine, nothing to `pip install` before you can audit a package you don't
  trust yet.

## Limitations

pkgguard is static, heuristic analysis. It looks for suspicious *patterns*,
not proof of malice.

- A sufficiently novel obfuscation technique, or a payload that is only
  fetched at runtime, can evade it.
- Legitimate tools trip the lower-severity rules. Test runners and build tools
  commonly use `exec()`/`eval()` and child processes, so scanning packages
  like `pytest` or `pip` reports `high`/`medium` findings. That's why the
  default gate is `--fail-on critical`. Raise the bar only for packages where
  those behaviors would be unexpected.
- Detection is per file. A payload split across files (secret read in one,
  network call in another) is reported at lower severity.
- Files above 10 MiB are reported but not pattern-scanned.

Treat findings as investigation leads for a human reviewer or a CI gate, not
as an automatic verdict.

## Development

```bash
git clone https://github.com/KhanSaahib/pkgguard
cd pkgguard
python -m unittest discover -s tests -v
```

The test suite is stdlib `unittest` (pytest also works). It covers every
detection rule against benign and synthetic-malicious fixtures, evasion
attempts (payloads in `dist/` and `test/`, ESM and `node:` imports), and the
archive extractor against path-traversal, symlink, hardlink, device-file and
decompression-bomb inputs.

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add a rule or report a false
positive.

## Security

If you find a way to make pkgguard itself unsafe to run, such as an archive
that escapes extraction or input that crashes or hangs the scanner, please
report it privately as described in [SECURITY.md](SECURITY.md). Detection
bypasses (a malicious pattern pkgguard misses) are welcome as regular issues.

## License

[MIT](LICENSE). Design credits are in [NOTICE.md](NOTICE.md).
