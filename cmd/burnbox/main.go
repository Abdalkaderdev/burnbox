package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/Abdalkaderdev/burnbox/internal/report"
	"github.com/Abdalkaderdev/burnbox/internal/sandbox"
	"github.com/Abdalkaderdev/burnbox/internal/scan"
)

var version = "dev"

const usage = `burnbox inspects an untrusted repository before you install or open it.

usage: burnbox <git-url | path> [flags]

  --run "cmd"       run cmd in the locked-down sandbox (e.g. "npm install && npm test")
  --json            print the report as JSON
  --report file     write a single-file HTML report
  --timeout dur     sandbox time limit (default 5m)
  --memory size     sandbox memory limit (default 2g)
  --cpus n          sandbox CPU limit (default 2)
  --no-color        plain terminal output
  --version         print version

exit codes: 0 CLEAN, 1 REVIEW, 2 DANGEROUS, 3 error
`

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(argv []string) int {
	fs := flag.NewFlagSet("burnbox", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	runCmd := fs.String("run", "", "")
	asJSON := fs.Bool("json", false, "")
	htmlOut := fs.String("report", "", "")
	timeout := fs.Duration("timeout", 5*time.Minute, "")
	memory := fs.String("memory", "2g", "")
	cpus := fs.String("cpus", "2", "")
	noColor := fs.Bool("no-color", false, "")
	showVersion := fs.Bool("version", false, "")

	var targets []string
	for {
		if err := fs.Parse(argv); err != nil {
			return 3
		}
		if fs.NArg() == 0 {
			break
		}
		targets = append(targets, fs.Arg(0))
		argv = fs.Args()[1:]
	}
	if *showVersion {
		fmt.Println("burnbox", version)
		return 0
	}
	if len(targets) != 1 {
		fs.Usage()
		return 3
	}
	target := targets[0]

	dir, commit, cleanup, err := resolve(target)
	if err != nil {
		fmt.Fprintln(os.Stderr, "burnbox:", err)
		return 3
	}
	defer cleanup()

	rep := &report.Report{Tool: "burnbox", Version: version, Target: target, Commit: commit, CreatedAt: time.Now().UTC()}
	start := time.Now()
	rep.Static, err = scan.Scan(dir)
	rep.StaticMS = time.Since(start).Milliseconds()
	if err != nil {
		fmt.Fprintln(os.Stderr, "burnbox: scan:", err)
		return 3
	}
	if *runCmd != "" {
		if !*asJSON {
			fmt.Fprintf(os.Stderr, "running %q in the sandbox (first run builds the image)...\n", *runCmd)
		}
		rep.Sandbox, err = sandbox.Run(context.Background(), sandbox.Options{
			Repo: dir, Command: *runCmd, Timeout: *timeout, Memory: *memory, CPUs: *cpus,
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, "burnbox: sandbox:", err)
			return 3
		}
	}
	rep.Decide()

	if *htmlOut != "" {
		f, err := os.Create(*htmlOut)
		if err == nil {
			err = rep.WriteHTML(f)
			if cerr := f.Close(); err == nil {
				err = cerr
			}
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "burnbox: report:", err)
			return 3
		}
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		if err := enc.Encode(rep); err != nil {
			return 3
		}
	} else {
		color := !*noColor && os.Getenv("NO_COLOR") == "" && (os.Getenv("FORCE_COLOR") != "" || term.IsTerminal(int(os.Stdout.Fd())))
		rep.WriteText(os.Stdout, color)
		if *htmlOut != "" {
			fmt.Println("\nHTML report:", *htmlOut)
		}
	}
	return rep.ExitCode()
}

func isGitURL(s string) bool {
	if _, err := os.Stat(s); err == nil {
		return false
	}
	for _, p := range []string{"https://", "http://", "ssh://", "git://", "git@"} {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

func resolve(target string) (dir, commit string, cleanup func(), err error) {
	cleanup = func() {}
	if !isGitURL(target) {
		info, err := os.Stat(target)
		if err != nil {
			return "", "", cleanup, err
		}
		if !info.IsDir() {
			return "", "", cleanup, fmt.Errorf("%s is not a directory", target)
		}
		return target, "", cleanup, nil
	}
	tmp, err := os.MkdirTemp("", "burnbox-clone-")
	if err != nil {
		return "", "", cleanup, err
	}
	cleanup = func() { os.RemoveAll(tmp) }
	dir = filepath.Join(tmp, "repo")
	cmd := exec.Command("git", "-c", "core.hooksPath="+os.DevNull, "-c", "protocol.ext.allow=never", "-c", "core.symlinks=false",
		"clone", "--quiet", "--depth", "1", "--no-recurse-submodules", "--", target, dir)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_LFS_SKIP_SMUDGE=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", "", cleanup, fmt.Errorf("git clone: %v\n%s", err, out)
	}
	if out, err := exec.Command("git", "-C", dir, "rev-parse", "HEAD").Output(); err == nil {
		commit = strings.TrimSpace(string(out))
	}
	return dir, commit, cleanup, nil
}
