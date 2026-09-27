# Test fixtures

The `malicious_*` packages here are **inert, synthetic samples** that exist only
to exercise pkgguard's detection rules. They point at the reserved
`example-attacker.test` domain, which can never resolve, and contain no real
payloads.

Even so, don't `npm install` or `pip install` them: they are written to look
exactly like the install-time behavior pkgguard is meant to catch, and some
antivirus tools may flag them for the same reason.
