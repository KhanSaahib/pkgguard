# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - Initial public release

### Added

- `pkgguard scan` for package directories, npm tarballs (`.tgz`), PyPI sdists
  (`.tar.gz`) and wheels (`.whl`/`.zip`).
- Detection rules: `LIFECYCLE_REMOTE_EXEC`, `LIFECYCLE_INLINE_EVAL`,
  `SECRET_EXFIL_CHAIN`, `SECRET_ACCESS`, `WORM_SIBLING_WRITE`,
  `WORM_SELF_PUBLISH`, `SETUP_CUSTOM_INSTALL_CMD`, `SHELL_EXEC_SHELL_TRUE`,
  `SHELL_EXEC`, `OBFUSCATION_EVAL`, `OBFUSCATION_DECODE`, and the
  informational `LARGE_FILE_NOT_SCANNED`.
- Text and JSON reports, a `--fail-on` severity gate, `--version`, and
  documented exit codes (`0` pass, `1` findings, `2` error).
- CI on Linux, macOS and Windows for Python 3.10 to 3.14.

### Security

Hardening made before the first public release:

- Archive extraction no longer uses `extractall()`. Symlink and hardlink
  *targets* are now validated (previously only the link's own path was
  checked, which let a link point outside the extraction root on Python
  3.10 to 3.13). Links are never materialized, device files and FIFOs are
  rejected, and archives are capped at 20,000 members and 512 MiB
  uncompressed.
- Unsafe archives now exit with code `2` and a clear message instead of a
  traceback.

### Changed

- `dist/`, `build/`, `test/` and `tests/` are now scanned. Previously they
  were skipped, which let a payload hide in the directory most npm packages
  ship their code from.
- Files over the size limit (raised from 2 MB to 10 MiB) are reported as
  `LARGE_FILE_NOT_SCANNED` instead of being skipped silently.
- `.mts`, `.cts`, `.jsx`, `.tsx` and `.pyw` files are scanned.
- Network detection covers `node:`-prefixed requires, ESM `import` statements
  and dynamic `import()`, `http2`/`net`/`tls`/`dgram`, WebSockets, and Python's
  `urlopen`, `http.client`, `httpx`, `urllib3` and `aiohttp`.
- Removed an exemption that let code write into `node_modules/pkgguard`
  without triggering `WORM_SIBLING_WRITE`.

### Fixed

- The text report never printed `summary: no findings` for clean packages.
- An unsupported scan target exited with code `1`, indistinguishable from
  "findings present". It now exits with `2`.
- A `package.json` whose `scripts` field isn't an object no longer crashes
  the scan.
- CLI tests no longer run the interpreter with an empty environment, which
  broke them on Windows.

[Unreleased]: https://github.com/KhanSaahib/pkgguard/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/KhanSaahib/pkgguard/releases/tag/v0.1.0
