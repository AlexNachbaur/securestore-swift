# Summary

<!-- What does this PR change, and why? Link related issues with "Fixes #123". -->

## Checklist

- [ ] `swift build` and `swift test` pass locally
- [ ] `swift format lint --strict --recursive Sources Tests Package.swift` passes
- [ ] Tests added or updated for behavioral changes
- [ ] No force unwraps introduced in production code; concurrency uses `async`/`await` (no `DispatchQueue`)
- [ ] Public API changes are documented (doc comments, README, `docs/design/` as appropriate)
- [ ] User-visible changes noted under **Unreleased** in `CHANGELOG.md`
