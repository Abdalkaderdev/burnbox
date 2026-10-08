# Design

## Goals

1. Tell a developer, before they run anything, what an unfamiliar repository will execute on install, on open and on commit.
2. When they do want to run it, run it somewhere that cannot reach their files or the network, and record what it tried.
3. Keep it one static binary with two dependencies and no daemon.

Non-goals: malware classification, signature databases, catching code that is designed to stay dormant in a sandbox.

## Layout

```
cmd/burnbox          CLI: argument parsing, cloning, output selection
internal/scan        static rules, one pass over the tree
internal/sandbox     image build, docker run, trace parsing
internal/report      verdict, terminal, JSON and HTML output
skills/burnbox       agent skill
action.yml           composite GitHub Action
```

## Static scan

`scan.Scan` walks the tree once with `filepath.WalkDir`, skipping `.git` and `node_modules` (and reporting a committed `node_modules`). Symlinks are never followed. Files over 2 MB are skipped. Each file is dispatched on its name and extension.

JavaScript files are parsed with `tdewolff/parse/v2/js`. That parser has no source positions, so line numbers come from two tricks: string literal byte slices point into the input buffer, so their offset is `cap(buf) - cap(literal)`, and a cursor moves forward through the file as the AST is walked in source order. Findings anchor on the next occurrence of the callee name after the cursor. If parsing fails (JSX, Flow), the file falls back to the line-based rules used for TypeScript.

A finding's severity says how much attention it deserves, not how likely it is to be malicious:

- high: code that runs automatically on install or open, code built at run time and executed, references to credential stores, typosquats
- medium: things that run on purpose but deserve a look, constructs that hide intent (split URLs, blobs, raw IPs)
- low: context (what `make` runs, no lockfile)

Each rule reports at most five findings per file and one per line.

## Sandbox

The image is embedded in the binary (`go:embed`) and tagged with a hash of its files, so a changed Dockerfile or decoy produces a new tag and a rebuild.

Container flags: `--network none`, `--dns 127.0.0.1`, `--cap-drop ALL`, `--security-opt no-new-privileges`, `--read-only`, `--user 1000:1000`, memory and swap equal, CPU and PID limits, tmpfs for `/tmp`, `/work` and `HOME`. The repository is bind-mounted read-only at `/src`, copied to `/work`, and results go to a host temp directory mounted at `/out`.

The entrypoint:

1. copies the decoy home and the repository into tmpfs
2. starts the DNS stub on `127.0.0.1:53` (allowed for uid 1000 by `net.ipv4.ip_unprivileged_port_start=53`, a namespaced sysctl)
3. runs the command under `timeout` and `strace -ff`, one trace file per process

ptrace of one's own children needs no capability and is permitted by Docker's default seccomp profile on current kernels, so `--cap-drop ALL` still works.

Trace parsing builds a process tree from `clone`/`fork` return values and the first successful `execve` in each process, so every file open or connect is attributed to a command line. Decoy matches are by absolute path under `HOME`, or by a relative path ending in a decoy's home-relative path. Connections to the DNS stub are ignored; the stub's own log is the source for DNS events. Lookups of package registries are low severity because npm and pip make them on every install.

## Verdict

```
DANGEROUS  any high sandbox event (a decoy credential was read)
REVIEW     any high static finding, any medium sandbox event, or a timeout
CLEAN      otherwise
```

Static findings alone never produce DANGEROUS. A pattern in source is a reason to look, not proof.

## Testing

- `internal/scan/testdata` holds inert fixtures: each one contains the pattern a rule looks for and does nothing harmful if run. The fixture test asserts the exact set of findings per fixture, so new false positives fail it too.
- `testdata/clean` is a control that must produce no medium or high findings.
- `TestFalsePositiveRepos` scans a folder of cloned popular repositories (set `BURNBOX_FP_DIR`) and fails if strong-signal rules (typosquat, split URL, char-code strings, encoded blobs, folder-open tasks, escaping symlinks) fire.
- Sandbox tests (set `BURNBOX_SANDBOX_TESTS=1`) use benign probes only: reading the decoy key to `/dev/null`, resolving `probe.burnbox.test`, a TCP connect to 1.1.1.1 that must fail with `ENETUNREACH`, a check that only `lo` exists, a real `npm install` that must show the fixture's postinstall, and a timeout.
