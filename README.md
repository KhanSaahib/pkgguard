# pkgguard

A dependency-free, offline CLI that statically scans the **actual contents**
of an npm or PyPI package - lifecycle scripts, source files, `setup.py` - for
install-time malicious behavior, before you `npm install` or `pip install`
it.

## Why this exists

2025 saw a wave of self-propagating npm supply-chain worms (e.g. the
"Shai-Hulud" campaign) and repeated PyPI/npm incidents where a compromised
maintainer account or a typosquatted package shipped a `postinstall`/`setup.py`
payload that harvested cloud credentials, SSH keys, and CI tokens, then
republished itself into other packages the victim had installed.

Most defenses at this layer stop at the manifest: "is this package name or
version on a known-bad list?" or "is this name a Levenshtein-distance
typosquat of a popular package?" That's necessary but not sufficient - it
does nothing for a brand-new malicious package, or a legitimate package whose
maintainer account was just compromised and pushed a fresh malicious version
under a name nobody has blocklisted yet.

pkgguard instead looks *inside* the package for the behaviors that matter:

- **Lifecycle script abuse** - `preinstall`/`postinstall`/etc. scripts in
  `package.json` that pipe a remote download straight into a shell, or run
  inline `node -e` payloads.
- **Secret-exfiltration chains** - code that reads a well-known secret
  (`AWS_SECRET_ACCESS_KEY`, `NPM_TOKEN`, `GITHUB_TOKEN`, `~/.ssh/id_rsa`,
  `~/.npmrc`, ...) *and* makes an outbound network call in the same file.
  Either signal alone is common in legitimate code; the combination is not.
- **Obfuscation** - `eval`/`Function()`/`exec` combined with base64/`atob`
  decode chains, a staple of hiding a malicious payload from a casual review.
- **Worm self-propagation** - code that writes into a *sibling* package's
  `node_modules` directory, or shells out to `npm publish` on its own behalf
  - the exact mechanism the 2025 npm worm outbreaks used to spread.
- **PyPI install-time execution** - `setup.py` code that runs at `pip install`
  time (top-level `exec`/`os.system`/`subprocess(..., shell=True)`, custom
  `cmdclass` overrides of the `install` command).

This complements, rather than replaces, manifest-level tools such as this
project's sibling `depguard` (known-bad name/version + typosquat detection in
`blue-forge`) - that catches packages already known to be bad by name;
pkgguard catches malicious *behavior* regardless of the name on the tin.

## Usage

```bash
pip install -e .

# scan an already-extracted package directory
pkgguard scan ./node_modules/some-package

# scan a downloaded npm tarball or PyPI sdist/wheel directly
pkgguard scan ./some-package-1.2.3.tgz
pkgguard scan ./some_package-1.2.3.tar.gz
pkgguard scan ./some_package-1.2.3-py3-none-any.whl

# machine-readable output, e.g. for a CI gate
pkgguard scan --json --fail-on high ./some-package.tgz
```

Exit code is non-zero once a finding at or above `--fail-on` (default
`critical`) is present, so it can be dropped into a pre-install CI step.

## Design notes

- **Archive handling is defensive by construction.** Because the whole point
  is inspecting untrusted, potentially malicious archives, `pkgguard.extract`
  validates every tar/zip member path before extraction and rejects anything
  that would escape the destination directory (path traversal / "Zip Slip")
  or any symlink pointing outside it, instead of calling
  `extractall()` directly on attacker-controlled input.
- **Signals are combined, not scored in isolation.** A single "makes a
  network call" or "reads an env var" match is low-severity noise on its own
  (plenty of legitimate packages do both); pkgguard escalates to `CRITICAL`
  only when a secret-read and a network call appear together in the same
  file, following the same "capability + indicator" correlation idea used by
  DataDog's GuardDog (see `NOTICE.md`).
- **Stdlib only, both at runtime and in tests** - no YARA, no third-party
  regex engines, nothing to `pip install` before you can even audit a
  package you don't trust yet.

## Layout

```
src/pkgguard/
  rules.py     - the heuristic rule catalog (lifecycle scripts, JS, Python)
  scanner.py   - walks a package tree and applies the rules
  extract.py   - path-traversal-safe tar/zip extraction
  report.py    - human-readable rendering
  cli.py       - `pkgguard scan ...` entry point
tests/
  fixtures/    - benign and synthetic-malicious npm/PyPI sample packages
  test_*.py    - unittest suite (stdlib only, no pytest dependency)
```

## Testing

```bash
python -m unittest discover -s tests -v
```

14 tests cover: clean packages produce no findings, each malicious fixture
trips the rule it's designed to demonstrate, the CLI's exit codes and JSON
output, and that the tar/zip extractor rejects a path-traversal payload.

## Scope and limitations

This is static, heuristic analysis - it looks for suspicious *patterns*, not
proof of malice, and does not execute any package code. It will not catch a
sufficiently novel obfuscation technique, and legitimate packages that
genuinely need to read a token and call the network (e.g. a publish helper)
will trip the same heuristic - treat findings as investigation leads for a
human reviewer or a CI gate, not an automatic verdict.
