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

This repository enforces conventional commit style via:
- Local hook: `husky` + `commitlint` (`.husky/commit-msg`)
- PR check: semantic PR title validation (`.github/workflows/commitlint.yml`)

### Setup Hooks Locally

```bash
npm install
```

Then commit messages will be validated automatically.

### PR Title Convention

Use semantic style for PR titles as well, e.g.:
- `feat: add release-please workflow`
- `fix: handle empty target in cli`

### Automated Changelog & Versioning

`release-please` is enabled (`.github/workflows/release-please.yml`).
After commits land on `main`/`master`, it automatically opens/updates a release PR,
generates `CHANGELOG.md`, and manages version tags.

## Code Style

- Run `gofmt` on changed files.
- Avoid introducing unrelated refactors.
- Add comments for core flow/algorithm functions.

## Security

Do not commit secrets, credentials, or private keys.
Use GitHub Security Advisories for vulnerability reports.
