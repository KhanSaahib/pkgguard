# Contributing to pkgguard

Thanks for helping make package installs a little less scary. Bug reports,
false-positive/false-negative reports, new detection rules and documentation
fixes are all welcome.

## Ground rules

pkgguard has a few hard constraints that every change needs to respect:

1. **Standard library only**, at runtime and in tests. People use pkgguard to
   audit packages they don't trust yet, so it can't ask them to install other
   packages first.
2. **Never execute scanned code.** No `import`, `exec`, `subprocess` or
   sandbox-and-run of anything from the package under inspection.
3. **Archives are hostile input.** Anything touching `extract.py` must keep
   rejecting traversal, escaping links, special files and oversized archives.
   Add a test for any new archive edge case.
4. **Precision over recall at high severities.** `critical` should mean
   "a human needs to look at this before installing". Noisy heuristics
   belong at `low`/`medium`, or should combine signals the way
   `SECRET_EXFIL_CHAIN` does.

## Development setup

```bash
git clone https://github.com/KhanSaahib/pkgguard
cd pkgguard
python -m unittest discover -s tests -v
```

No virtualenv or install step is required to run the tests. To try the CLI
from a checkout, run `PYTHONPATH=src python -m pkgguard scan <path>`.

## Adding or changing a detection rule

1. Add the pattern and emitting code to `src/pkgguard/rules.py`. Rule IDs are
   `UPPER_SNAKE_CASE` and should be stable once released, because users
   filter on them.
2. Pick the severity using the ground rules above.
3. Add tests in `tests/test_scanner.py` with **both** a positive case (the
   rule fires) and a negative case (similar benign code stays clean).
4. Add the rule to the table in `README.md` and an entry under `Unreleased`
   in `CHANGELOG.md`.

### Writing malicious test fixtures

Fixtures must demonstrate a pattern without being a working payload:

- Use reserved, non-resolvable domains such as `example-attacker.test`.
- Don't include real malware samples, real credentials or real C2 addresses.
- Prefer generating one-off samples inside the test (see
  `TestEvasionResistance`) over committing new fixture files.

## Reporting a false positive or false negative

Open a **Detection issue** and include the package name and version (or a
minimal code snippet), the rule ID involved, and what you expected. For false
negatives, a minimal inert reproduction is ideal.

Found a way to make pkgguard itself unsafe to run? Please don't open a public
issue; follow [SECURITY.md](SECURITY.md) instead.

## Pull requests

- Keep each PR focused on one change, and include tests.
- Make sure `python -m unittest discover -s tests` passes on Python 3.10+.
  CI runs the suite on Linux, macOS and Windows.
- Describe user-visible changes in `CHANGELOG.md`.

By contributing, you agree that your contributions are licensed under the
project's [MIT License](LICENSE). Please also follow the
[Code of Conduct](CODE_OF_CONDUCT.md).
