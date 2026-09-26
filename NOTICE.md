# Notice / Attributions

pkgguard is original code written for this repository. No source code was
copied from any third-party project. The following projects informed the
*design ideas* behind pkgguard's detection approach; they are credited here
for transparency even though nothing was copied from them.

## Inspiration sources

### DataDog GuardDog
- Repository: https://github.com/DataDog/guarddog
- License: Apache License 2.0
- Idea drawn from it (not code): correlating a *capability* (e.g. network
  access, filesystem access) with a *threat indicator* (e.g. reading a
  secret) in the same file before escalating severity, rather than flagging
  either signal in isolation. GuardDog implements this via YARA rules over
  PyPI/npm/Go/Rust/RubyGems/GitHub Actions/VSCode-extension packages;
  pkgguard implements the same correlation idea from scratch using stdlib
  regex, scoped to npm and PyPI.

### OpenSSF Package Analysis
- Repository: https://github.com/ossf/package-analysis
- License: Apache License 2.0
- Idea drawn from it (not code): the general framing of analyzing a
  package's *install-time behavior* (not just its published metadata) as a
  first-class supply-chain security signal.

## Naming inspiration

The `depguard` / `iamguard` / `iacguard` / `k8sguard` / `dockerguard` naming
and "offline, dependency-free static scanner" design convention follows the
existing sibling tools in https://github.com/KhanSaahib/blue-forge (own
prior work, MIT licensed).
