# Releasing

Go needs no publish step: a version exists once its `v*` tag is pushed, and
the Go module proxy fetches it on first request. The `Release` workflow runs
the tests on a pushed tag and asks proxy.golang.org for the version so it is
cached and shows on pkg.go.dev straight away. Tags are pushed by hand, usually
after merging a `regen/<tag>` pull request.
