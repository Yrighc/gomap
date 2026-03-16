# Contributing

## Development Setup

- Go 1.24+
- Run tests before pushing:

```bash
go test ./...
go vet ./...
```

## Branch & PR Rules

- Use short-lived branches from `main`.
- Keep PRs focused (one concern per PR).
- Fill in the PR template completely.

## Commit Message

Recommended style:

```text
type(scope): summary
```

Examples:
- `feat(assetprobe): add optional dir brute options`
- `fix(cli): validate target argument`
- `docs(readme): add DI integration section`

## Code Style

- Run `gofmt` on changed files.
- Avoid introducing unrelated refactors.
- Add comments for core flow/algorithm functions.

## Security

Do not commit secrets, credentials, or private keys.
Use GitHub Security Advisories for vulnerability reports.
