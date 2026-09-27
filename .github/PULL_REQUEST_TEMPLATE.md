## What does this change?

<!-- A short description, and a link to the issue it addresses if there is one. -->

## Checklist

- [ ] Tests added or updated (new rules need a positive **and** a negative case)
- [ ] `python -m unittest discover -s tests` passes locally
- [ ] Still standard-library only, and no scanned code is ever executed
- [ ] `README.md` rule table and `CHANGELOG.md` updated if behavior changed
- [ ] Any new malicious fixtures are inert (`.test` domains, no working payloads)
