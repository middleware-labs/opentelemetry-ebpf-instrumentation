# Syncing the fork with upstream

How to merge `upstream/main` into the fork, from the merge of 2026-11-13 (245 upstream commits,
37 conflicting files). Read [README.md](README.md) first: its rules decide most conflicts.

## Steps

1. Work on a branch: `git switch -c network-performance-monitoring-sync` (or reuse it).
2. `git fetch upstream`, then `git merge --no-ff --no-commit upstream/main`.
3. Resolve the conflicts by kind, as below. Do not commit until everything validates.
4. Regenerate the eBPF files and validate (see [Validate](#validate)).
5. Stage the resolution with `git add`. Leave out local files that are not part of the merge.

Before resolving, list what upstream changed in the stats code:
`git log --oneline $(git merge-base HEAD upstream/main)..upstream/main -- bpf/statsolly pkg/internal/statsolly pkg/statsolly`.
Upstream may have fixed something the fork also fixed: prefer upstream's fix and drop ours.

## Resolving conflicts by kind

| Files | How |
|---|---|
| Upstream eBPF files (`tp_tcp.c`, `k_tcp.c`, maps the reader does not own) | Take upstream's: `git checkout --theirs <file>`. Move anything the reader still needs into the fork's own files |
| `bpf/statsolly/types.h`, `stats.c` | Keep upstream's lines and add ours after them. Renumber our `enum stat_type` values after upstream's new ones (Go uses the generated names, never the numbers) |
| `stats_tracer.go` | Union: upstream's new programs and hooks, and ours. Merge the `go:generate -type` lists |
| `stats/tracer_ringbuf.go` and its test | Take upstream's. Only the event flow uses it |
| Lists of features, metrics, attributes, exporter fields, v2 feature names | Union, upstream's entries first |
| Exporters (`metrics_stats.go`, `prom_stats.go`) and tests where both sides edited the same functions | Start from our version (`git show HEAD:<file>`) and apply upstream's diff (`git diff $(git merge-base HEAD upstream/main) upstream/main -- <file>`) by hand |
| `schemas/obi/groups/stats/metrics.yaml` | Start from ours and append upstream's new metric blocks |
| `site/docs/` | Take upstream's, then regenerate: `make generate-schema-docs` |
| `devdocs/telemetry-schema.md` pending notes | Take upstream's list and add back only the items the fork added |
| `devdocs/config/version-2.0/*` | Union of the feature lists |

Search for leftovers when done: `grep -rn '^<<<<<<<\|^>>>>>>>' --exclude-dir=.git .`

## Pitfalls seen so far

- **Enum missing from BTF.** An enum that only an inlined function returns is not in BTF, and
  bpf2go fails with `looking up type <enum>: not found`. Add
  `const enum <name> *unused_N __attribute__((unused));` in `stats.c`.
- **Duplicate static helpers.** `stats.c` includes every `.c` file into one compile unit. A helper
  that upstream defines in `tp_tcp.c` (such as `sk_err_to_reason`) cannot also be defined in our
  headers: rename ours (`row_fail_reason` in `tcp_failure.h`).
- **Upstream types narrower than ours.** `Stat.TCPIo.Bytes` is `uint64` in the fork (row totals),
  `uint32` upstream: the event decoder needs `uint64(b)`, and its test expects `uint64`.
- **Interfaces the fork extends.** The fork's `ebpFetcher` (`pkg/statsolly/agent/agent.go`) has
  more methods than upstream's. New upstream fakes, such as `noopFetcher` in `agent_test.go`, need
  them too.
- **Tests that mean "all TCP stats".** Fixtures written as `export.FeatureStats` do not include the
  row-only features: use `export.FeatureStats | export.FeatureStatsTCPRowOnly`.
- **Upstream shutdown handling.** Upstream's `buildPipeline(ctx, readerCtx)` stops the ring buffer
  reader with `readerCtx` so the pipeline can drain. The DNS tracer and the socket traffic reader
  must use `readerCtx` too, or shutdown waits for them.
- **`sock_role` lifetime.** Since upstream #4055 it is deleted at `tcp_destroy_sock`, not at
  `TCP_CLOSE`. Reader code that relied on the old order must be checked when this changes again.
- **Local clang-format version.** The pre-commit hook formats staged C files with the local
  `clang-format` (19 on the dev laptop), while CI uses the generator image's (22): they format some
  lines differently (`int(*name)[val]` against `int (*name)[val]`). Commit merges with
  `CLANG_FORMAT=true git commit ...` so the hook leaves upstream files alone, and format the
  fork's own C files with `make docker-clang-format CLANG_FORMAT_FILES="..."`.
- **Removed upstream APIs.** Upstream removed `PrometheusConfig.Registry`: tests use
  `testutil.NewPrometheusServer(t)`.

## Validate

Run these one at a time. On a laptop, limit the CPU: running eBPF generation, Go builds and tests
in parallel has crashed the machine. Use `GOMAXPROCS=4 GOFLAGS=-p=2 nice -n 15` for Go commands
and `--cpus=4` for containers.

1. Regenerate the eBPF files. This is `make docker-generate` with a CPU limit; the image tag is
   `GEN_IMG` in the `Makefile`:

   ```sh
   _git_dir=$(git rev-parse --absolute-git-dir)
   _git_common_dir=$(git rev-parse --path-format=absolute --git-common-dir)
   docker run --rm --cpus=4 -u "$(id -u):$(id -g)" -v "$PWD:/src:z" \
     -v "$_git_common_dir:/src/.gitrepo:ro,z" -e GIT_DIR="/src/.gitrepo${_git_dir#$_git_common_dir}" \
     -e BPF_TARGETS="amd64,arm64" -w /src <GEN_IMG> make generate
   ```

2. Build and vet: `go build ./...`, then `go vet` on the changed packages, and
   `go vet -tags integration ./internal/test/integration/`.
3. Unit tests: `go test -count=1 ./pkg/internal/statsolly/... ./pkg/statsolly/... ./pkg/export/... ./pkg/obi/... ./internal/config/... ./cmd/check-config-v2-parity/... ./pkg/config/...`
4. eBPF verifier, in a privileged container when there is no root:

   ```sh
   CGO_ENABLED=0 go test -c -tags bpf_verifier_tests -o /tmp/verifier.test ./pkg/internal/ebpf/verifier/
   docker run --rm --privileged --cpus=4 -v /sys/kernel:/sys/kernel -v /tmp:/t:ro \
     --entrypoint /t/verifier.test <GEN_IMG> \
     -test.run 'TestBPFVerifierWithConstants/statsolly' -test.v -test.parallel 1
   ```

   Use `-test.parallel 1`: parallel subtests crash in cilium/ebpf's BTF decoder.

5. C format: `clang-format --dry-run --Werror` on the changed `bpf/` files.
6. Go lint on the changed packages:
   `go tool -modfile=internal/tools/go.mod golangci-lint run --concurrency 2 <packages>`.
7. Config and schema: `make check-config-schema`, `make check-config-v2-artifacts`,
   `make lint-schema`, `make generate-schema-docs`, `make check-schema-files`.
8. Integration (Docker): the stats suite (`docker-compose-go-stat-metrics.yml`).

Then move mw-agent's `.obi-src` to the new commit, following mw-agent's `docs/obi-update.md`.
