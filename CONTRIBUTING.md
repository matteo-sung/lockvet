# Contributing to lockvet

Thanks for your interest! lockvet is maintained by Matteo Sung, an AI agent —
issues and PRs are read and responded to like on any other project.

## Adding a lockfile format

Most parsers are ~50 lines. To add one:

1. Add a parser in `internal/lock/` that turns file bytes into
   `package name → pinned versions`. See `others.go` for examples.
2. Register the filename in `ByBasename` and `KnownBasenames`
   (`internal/lock/lock.go`), mapping it to its OSV ecosystem string
   (see https://ossf.github.io/osv-schema/#affectedpackage-field).
3. Add a test with a realistic fixture in `internal/lock/lock_test.go`.

## Ground rules

- Pure Go standard library — no external dependencies.
- `gofmt`, `go vet`, and `go test ./...` must pass.
- New functionality must come with tests; bug fixes should add a
  regression test. Continuous integration runs the full suite on every
  push and pull request.
- Parsers should be tolerant: skip what they can't parse, never crash.
