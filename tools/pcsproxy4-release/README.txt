Prepared remote release build; no execution is authorized by these files.

The runtime source is the already validated06ab4eae tree, all221 files and six
module lock hashes. Go1.25.6/CGO0/linuxamd64v1 and build flags are unchanged.
Relative to the existing CI candidate7da47f5b, the only link identity changes
are appVersion, appType and the fixed preparation-UTC appDate. No tests, pure
contracts, benchmark, generated CLI main, network fixture or deployment runs.
The two earlier workflows have disjoint path filters and are not re-triggered.

The existing approved CLI helper is imported only for git source archive,
module guard, command recording and JSON output. Build dependencies are fetched
only for app via readonly go list; all three modules verify before offline
builds. A same-input second build must have the same final SHA. All original
source files and locks are rechecked afterward. The fixed codeload source tar
is bounded and its entire core/extras/app tree must equal the same221 hashes;
its actual archive SHA is emitted into the exact sources.json artifact.
The final result binds binary SHA, same-input repeat SHA, sources.json SHA,
source/archive/module/command provenance and toolchain. Buildinfo fields are
reported as actually present; absence of ldflags from go version -m is not
treated as source proof or failure. No candidate binary is relabeled in place.

Public Ubuntu runner, exact pinned official actions, contents:read, no secrets,
15min job, one owned1CPU768MiBSwap0 service,780s hard budget. Private per-attempt
Go caches; HOME is not overwritten. memory.max events are retained as pressure
of this build-only job, never runtime-cost evidence; any high/OOM/kill, missing
resource identity, command failure or timeout fails. Run5 memory HOLD and the
separate run6 contract result remain unchanged.

Root must approve/freeze plan before one dedicated branch push. After artifact
verification, the host may COPY this binary and exact sources.json into the
previous pinned runtime base without a local Go build. Root separately owns
consumer installation, immutable single-HY image switch, health and30min
natural observation. This workflow does not authorize those actions.
