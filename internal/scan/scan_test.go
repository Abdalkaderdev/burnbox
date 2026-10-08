package scan

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type want struct {
	rule string
	sev  Severity
	file string
	line int
}

func TestFixtures(t *testing.T) {
	cases := map[string][]want{
		"lifecycle": {
			{"lifecycle-script", High, "package.json", 6},
			{"lifecycle-script", Medium, "package.json", 7},
		},
		"pyhooks": {
			{"python-build-hook", High, "setup.py", 11},
			{"python-build-hook", Medium, "setup.py", 1},
		},
		"pyproject": {{"python-build-hook", High, "pyproject.toml", 4}},
		"makefile":  {{"makefile-default", Low, "Makefile", 1}},
		"vscode": {
			{"vscode-folder-open-task", High, ".vscode/tasks.json", 9},
			{"vscode-settings", Medium, ".vscode/settings.json", 3},
			{"vscode-settings", Medium, ".vscode/settings.json", 4},
		},
		"devcontainer": {
			{"devcontainer-command", High, ".devcontainer/devcontainer.json", 5},
			{"devcontainer-command", Medium, ".devcontainer/devcontainer.json", 6},
		},
		"hooks": {{"git-hook", Medium, ".husky/pre-commit", 1}},
		"js": {
			{"dynamic-code", Medium, "eval.js", 1},
			{"dynamic-code", High, "func.js", 2},
			{"child-process", High, "child.js", 3},
			{"child-process", Medium, "child-const.js", 2},
			{"encoded-blob", Medium, "blob.js", 1},
			{"split-url", Medium, "url.js", 1},
			{"split-url", Medium, "url.js", 2},
			{"string-obfuscation", Medium, "charcodes.js", 1},
			{"raw-ip-url", Medium, "ip.js", 1},
			{"credential-path", High, "credpath.js", 3},
		},
		"ts": {
			{"dynamic-code", Medium, "index.ts", 3},
			{"child-process", High, "index.ts", 5},
		},
		"python": {
			{"dynamic-code", High, "main.py", 5},
			{"dynamic-code", Medium, "main.py", 6},
			{"child-process", High, "main.py", 8},
			{"credential-path", High, "main.py", 9},
		},
		"deps": {
			{"typosquat", High, "package.json", 6},
			{"typosquat", High, "requirements.txt", 1},
			{"lockfile-mismatch", Medium, "package.json", 7},
			{"dependency-source", Medium, "package.json", 8},
			{"dependency-install-script", Medium, "package-lock.json", 9},
		},
	}
	for dir, wants := range cases {
		t.Run(dir, func(t *testing.T) {
			res, err := Scan(filepath.Join("testdata", dir))
			if err != nil {
				t.Fatal(err)
			}
			got := map[want]bool{}
			for _, f := range res.Findings {
				got[want{f.Rule, f.Severity, f.File, f.Line}] = true
			}
			for _, w := range wants {
				if !got[w] {
					t.Errorf("missing %+v\ngot:\n%s", w, dump(res))
				}
			}
			if len(res.Findings) != len(wants) {
				t.Errorf("expected %d findings, got %d:\n%s", len(wants), len(res.Findings), dump(res))
			}
		})
	}
}

func TestCleanControl(t *testing.T) {
	res, err := Scan(filepath.Join("testdata", "clean"))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range res.Findings {
		if f.Severity != Low {
			t.Errorf("unexpected finding in clean fixture: %+v", f)
		}
	}
}

func TestFalsePositiveRepos(t *testing.T) {
	dir := os.Getenv("BURNBOX_FP_DIR")
	if dir == "" {
		t.Skip("set BURNBOX_FP_DIR to a folder of cloned popular repositories")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		res, err := Scan(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		high := 0
		for _, f := range res.Findings {
			if strongSignal[f.Rule] || f.Rule == "devcontainer-command" && f.Severity == High {
				t.Errorf("%s: strong-signal rule fired on a legitimate repo: %+v", e.Name(), f)
			}
			if f.Severity == High {
				high++
				t.Logf("%s: %s %s:%d %s", e.Name(), f.Rule, f.File, f.Line, f.Snippet)
			}
		}
		t.Logf("%s: %d files, %d findings, %d high", e.Name(), res.Files, len(res.Findings), high)
	}
}

var strongSignal = set("typosquat split-url string-obfuscation encoded-blob vscode-folder-open-task symlink-escape")

func TestMakefileRisky(t *testing.T) {
	s := &scanner{counts: map[string]int{}}
	s.makefile("Makefile", []byte("CC=gcc\n\nsetup:\n\techo hello | sh\n"))
	if len(s.res.Findings) != 1 || s.res.Findings[0].Severity != Medium || s.res.Findings[0].Line != 3 {
		t.Fatalf("got %+v", s.res.Findings)
	}
}

func TestOneEdit(t *testing.T) {
	for _, c := range []struct {
		a, b string
		ok   bool
	}{
		{"expresss", "express", true}, {"reqeusts", "requests", true}, {"lodahs", "lodash", true},
		{"axois", "axios", true}, {"chalk", "chalk", false}, {"react", "preact", true}, {"vite", "vitest", false},
	} {
		if oneEdit(c.a, c.b) != c.ok {
			t.Errorf("oneEdit(%q,%q) != %v", c.a, c.b, c.ok)
		}
	}
	if typosquat("preact", popularNPM) != "" {
		t.Error("short or allowlisted names must not be flagged when they are popular themselves")
	}
}

func TestStripJSONC(t *testing.T) {
	got := string(stripJSONC([]byte("{\"a\": \"//not a comment\", /* x */ \"b\": [1,],}")))
	if !strings.Contains(got, "//not a comment") || strings.Contains(got, "x */") || strings.Contains(got, ",]") {
		t.Fatalf("got %q", got)
	}
}

func dump(r Result) string {
	var b strings.Builder
	for _, f := range r.Findings {
		fmt.Fprintf(&b, "  %s %s %s:%d %s\n", f.Severity, f.Rule, f.File, f.Line, f.Snippet)
	}
	return b.String()
}
