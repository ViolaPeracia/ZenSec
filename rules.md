# Project Rules & Coding Standards

## General Guidelines
* **Language:** Go 1.25+ (matches `go.mod` and the CI toolchain).
* **Formatting:** run `gofmt -w .` before committing. CI fails if any file differs.
* **Linting:** `golangci-lint run ./...` must be clean. Configuration lives in `.golangci.yml`.
* **Vulnerabilities:** `govulncheck ./...` must be clean. CI runs it on every PR.

## Code Structure
* `cmd/zensec/`: CLI entry point. Argument handling, prompts and output only.
* `internal/crypto/`: All cryptographic logic. Must not depend on any UI package.
* `internal/crypto/header.go`: Container format. Changing the layout requires bumping `FormatVersion` and keeping the previous version readable.
* `internal/crypto/testdata/`: Golden fixtures produced by the original version 1 code. Do not regenerate them; they exist to prove backward compatibility.

## Pull Requests & Contributions
* All PRs must include unit tests, especially for `internal/crypto`.
* `internal/crypto` must stay above the 85% coverage gate enforced in CI. The uncovered remainder is failure paths that need fault injection to reach; the target is 100%, and lowering the gate is not an acceptable way to make CI green.
* `cmd/zensec` currently sits around 70% and is not gated. Raise that before adding a global coverage gate.
* CI must be green: formatting, `go vet`, lint, `govulncheck`, build and `-race` tests.
* PR descriptions should state the problem and the approach.

## Cryptographic Changes
Changes under `internal/crypto` require explicit human review. Before proposing one, work through the checklist in [docs/threat-model.md](docs/threat-model.md). At minimum:

* Bump `FormatVersion` and keep the previous version readable if the container layout changes.
* Range-check anything read from a header before using it.
* Keep per-file nonce entropy at 64 bits or more and keep per-chunk nonces provably unique.
* Keep output atomic: the destination must be untouched on every error path.
* Include a test that fails before the change and passes after it.
