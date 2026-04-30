# Task 1 Secprobe Baseline Failure Evidence

This records the required pre-implementation failing baseline for Task 1 from `2026-04-30-secprobe-engine-metadata-phase1.md`.

- Implementation commit: `bcbec4d8c5f2cfc93b632e7b2cf470f172a0e75e`
- Pre-implementation parent commit: `3f2dee095bbc28366a5eaf66d07883b6e9490de3`
- Method: temporary detached `git worktree`

## Exact command

```bash
go test ./pkg/secprobe/metadata ./pkg/secprobe -run 'TestLoadSpecsIncludesRedisAndSSHAliases|TestLookupProtocolSpecPrefersYAMLMetadata' -v
```

## Observed result at the parent commit

Exit status: `1`

Short failure excerpt:

```text
# ./pkg/secprobe/metadata
stat /tmp/.../repo/pkg/secprobe/metadata: directory not found
FAIL	./pkg/secprobe/metadata [setup failed]
testing: warning: no tests to run
PASS
ok  	github.com/yrighc/gomap/pkg/secprobe	0.606s [no tests to run]
FAIL
```

This parent commit predates the Task 1 metadata package and loader files, so the required baseline command failed before implementation as expected.
