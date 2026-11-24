# go in a box (`@box/go`)

The `@box/go` pack lets the agent run the `go` that your `PATH` finds: an official tarball,
Homebrew, or setup-go. Add `@box/go` to `packs` in your profile.

## Where go keeps its files

go keeps GOPATH, its module cache, and its build cache in its own folder in the profile's storage,
`~/.strands/box/storage/<profile>/default/tool/go/cache`, because the box cannot write `~/go` or
`~/Library/Caches/go-build`. The agent cannot write that folder, so it cannot change a module that
a later build compiles. Every project of the profile shares it.

## What go can reach

`proxy.golang.org` and `sum.golang.org`, for module downloads. Every program in the box can reach
these hosts, not only go.

## Private modules

go in the box never reads your own `GOPRIVATE`, from your shell or from `go env -w`. Without it,
go asks `proxy.golang.org` and `sum.golang.org` for each private module path, so the names of
your private modules reach Google. Set it in your profile:

```toml
[tool.go.env]
GOPRIVATE = "github.com/your-org/*"
```

go then skips both hosts for those paths and downloads them straight from their git host. It
starts git for that: the `git` your `PATH` finds. `@box/go` extends `@box/git`, so go gets
`@box/git`'s grants and variables and git's folder on its `PATH`. git is not a tool of its own, so
the agent gets no `git` tool unless your profile lists `@box/git` too. git reads no git config, so it has no credential helper and no `~/.netrc`.
Give it a token with a route in your profile. For GitHub, put a token that can read the
repositories in `GIT_GITHUB` as `x-access-token:<token>`:

```toml
[egress.github_git]
destinations = ["github.com"]
secret.ref = "env://GIT_GITHUB"
secret.placement = "basic_auth"
secret.inject = "always"
```

The box adds the token to every request to github.com, from any program in the box.

If your company serves private modules from its own module proxy, set `GOPROXY` and
`GONOSUMDB` instead of `GOPRIVATE`, and add the proxy host with a route, as
[Routes and other hosts](../../../docs/cli/profiles-reference.md#routes-and-other-hosts) says.
`GOPRIVATE` would make go skip your proxy too.

```toml
[tool.go.env]
GOPROXY = "https://goproxy.example.com"
GONOSUMDB = "github.com/your-org/*"
```

## Limitations

- go uses only the toolchain your `PATH` finds. It never downloads another one
  (`GOTOOLCHAIN=local`).
- cgo is off (`CGO_ENABLED=0`), so a package that needs a C compiler does not build.
- go reads no host env file (`GOENV=off`), so `go env -w` has no effect.
- On macOS, go must be 1.27 or later. An older go fails module downloads with
  `x509: OSStatus -26276`. A program that go builds, such as a test binary or `go run`, has the
  same failure unless the project's `go.mod` says `go 1.27` or later. Linux has no such floor.
- A program that go runs, such as a test binary or `go run`, can change go's folder in storage, and
  every project of the profile then builds with what it changed. To start over, delete
  `~/.strands/box/storage/<profile>/default/tool/go`.
- The agent cannot run a program that `go install` puts in GOPATH, because GOPATH is in go's own
  storage.
