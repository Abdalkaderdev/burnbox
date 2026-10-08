package scan

import (
	"bytes"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

type Severity string

const (
	High   Severity = "high"
	Medium Severity = "medium"
	Low    Severity = "low"
)

func (s Severity) Rank() int {
	switch s {
	case High:
		return 3
	case Medium:
		return 2
	}
	return 1
}

type Finding struct {
	Rule        string   `json:"rule"`
	Severity    Severity `json:"severity"`
	File        string   `json:"file"`
	Line        int      `json:"line,omitempty"`
	Snippet     string   `json:"snippet,omitempty"`
	Explanation string   `json:"explanation"`
}

type Result struct {
	Files    int       `json:"files_scanned"`
	Findings []Finding `json:"findings"`
}

const maxFileSize = 2 << 20
const maxPerRule = 5

type scanner struct {
	root   string
	res    Result
	counts map[string]int
}

func (s *scanner) add(f Finding) {
	key := f.Rule + "\x00" + f.File
	lineKey := fmt.Sprintf("%s:%d", key, f.Line)
	if s.counts[key] >= maxPerRule || s.counts[lineKey] > 0 {
		return
	}
	s.counts[key]++
	s.counts[lineKey]++
	f.File = filepath.ToSlash(f.File)
	f.Snippet = clip(f.Snippet)
	s.res.Findings = append(s.res.Findings, f)
}

func Scan(root string) (Result, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return Result{}, err
	}
	s := &scanner{root: root, counts: map[string]int{}, res: Result{Findings: []Finding{}}}
	s.gitHooks()
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		if d.IsDir() {
			switch d.Name() {
			case ".git":
				return filepath.SkipDir
			case "node_modules":
				sev := Medium
				if rel != "node_modules" {
					sev = Low
				}
				s.add(Finding{Rule: "committed-node-modules", Severity: sev, File: rel,
					Explanation: "The repository ships its own node_modules. Code in it was not scanned and will be used instead of registry packages."})
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			s.symlink(path, rel)
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		if info, err := d.Info(); err != nil || info.Size() > maxFileSize {
			return nil
		}
		s.file(path, rel)
		return nil
	})
	sort.SliceStable(s.res.Findings, func(i, j int) bool {
		a, b := s.res.Findings[i], s.res.Findings[j]
		if a.Severity != b.Severity {
			return a.Severity.Rank() > b.Severity.Rank()
		}
		if a.File != b.File {
			return a.File < b.File
		}
		return a.Line < b.Line
	})
	return s.res, err
}

func (s *scanner) symlink(path, rel string) {
	target, err := os.Readlink(path)
	if err != nil {
		return
	}
	abs := target
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(filepath.Dir(path), target)
	}
	if r, err := filepath.Rel(s.root, abs); err != nil || strings.HasPrefix(r, "..") {
		s.add(Finding{Rule: "symlink-escape", Severity: Medium, File: rel, Snippet: target,
			Explanation: "Symlink points outside the repository. Tools that follow it read files from your machine."})
	}
}

func (s *scanner) file(path, rel string) {
	name := filepath.Base(rel)
	dir := filepath.ToSlash(filepath.Dir(rel))
	ext := strings.ToLower(filepath.Ext(name))
	read := func() []byte {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		s.res.Files++
		return b
	}
	switch {
	case name == "package.json":
		s.packageJSON(rel, read())
	case name == "setup.py":
		s.setupPy(rel, read())
	case name == "pyproject.toml":
		s.pyproject(rel, read())
	case strings.HasPrefix(name, "requirements") && ext == ".txt":
		s.requirements(rel, read())
	case dir == "." && (name == "Makefile" || name == "makefile" || name == "GNUmakefile"):
		s.makefile(rel, read())
	case dir == ".vscode" && name == "tasks.json":
		s.vscodeTasks(rel, read())
	case dir == ".vscode" && name == "settings.json":
		s.vscodeSettings(rel, read())
	case name == "devcontainer.json" || name == ".devcontainer.json":
		s.devcontainer(rel, read())
	case dir == ".husky" || dir == ".githooks" || name == "lefthook.yml" || name == ".pre-commit-config.yaml":
		if !strings.HasPrefix(name, ".") || name == ".pre-commit-config.yaml" {
			s.hookFile(rel, read())
		}
	case ext == ".js" || ext == ".cjs" || ext == ".mjs":
		b := read()
		if !s.javascript(rel, b) {
			s.codeRegex(rel, b, "js")
		}
		s.textRules(rel, b)
	case ext == ".ts" || ext == ".tsx" || ext == ".mts" || ext == ".cts" || ext == ".jsx":
		b := read()
		s.codeRegex(rel, b, "js")
		s.textRules(rel, b)
	case ext == ".py":
		b := read()
		s.codeRegex(rel, b, "py")
		s.textRules(rel, b)
	case ext == ".sh" || ext == ".ps1" || ext == ".bat" || ext == ".cmd":
		s.textRules(rel, read())
	}
}

func clip(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 160 {
		return s[:157] + "..."
	}
	return s
}

func lineAt(b []byte, off int) (int, string) {
	if off < 0 || off > len(b) {
		return 0, ""
	}
	line := bytes.Count(b[:off], []byte("\n")) + 1
	start := bytes.LastIndexByte(b[:off], '\n') + 1
	end := bytes.IndexByte(b[off:], '\n')
	if end < 0 {
		end = len(b)
	} else {
		end += off
	}
	text := string(b[start:end])
	if len(text) > 160 {
		col := off - start
		lo := max(0, col-40)
		text = text[lo:min(len(text), lo+157)] + "..."
	}
	return line, strings.TrimRight(text, "\r")
}

func lineOf(b []byte, needle string) (int, string) {
	i := bytes.Index(b, []byte(needle))
	if i < 0 {
		return 0, ""
	}
	return lineAt(b, i)
}

var (
	reB64  = regexp.MustCompile(`[A-Za-z0-9+/]{200,}={0,2}`)
	reHex  = regexp.MustCompile(`\b[0-9a-fA-F]{200,}\b`)
	reIP   = regexp.MustCompile(`\b(?:https?|wss?|tcp|ftp)://((?:\d{1,3}\.){3}\d{1,3})\b`)
	reCred = []struct {
		re   *regexp.Regexp
		sev  Severity
		what string
	}{
		{regexp.MustCompile(`\.ssh[/\\"'` + "`" + `]|\bid_(?:rsa|ed25519|ecdsa|dsa)\b`), High, "SSH private keys"},
		{regexp.MustCompile(`\.aws[/\\"'` + "`" + `]`), High, "AWS credentials"},
		{regexp.MustCompile(`\.config[/\\]gcloud|\.azure[/\\"']`), High, "cloud CLI credentials"},
		{regexp.MustCompile(`\.kube[/\\]config|\.docker[/\\]config\.json`), High, "Kubernetes or Docker registry credentials"},
		{regexp.MustCompile(`\.git-credentials|\.netrc\b|\.gnupg\b|\.pypirc\b`), High, "stored git, GPG or package-registry credentials"},
		{regexp.MustCompile(`Login Data|Local State|\bwallet\.dat\b|\.ethereum[/\\]keystore`), High, "browser profile or wallet data"},
		{regexp.MustCompile(`\.bash_history|\.zsh_history`), High, "shell history"},
		{regexp.MustCompile(`\.npmrc\b`), Medium, "npm auth tokens"},
	}
)

func (s *scanner) textRules(rel string, b []byte) {
	for _, m := range reB64.FindAllIndex(b, -1) {
		blob := b[m[0]:m[1]]
		if !bytes.ContainsAny(blob, "0123456789") {
			continue
		}
		tok := b[max(0, m[0]-200):m[0]]
		if i := bytes.LastIndexAny(tok, " \t\n'\"`("); i >= 0 {
			tok = tok[i+1:]
		}
		if bytes.Contains(tok, []byte("data:")) || bytes.Contains(tok, []byte("://")) {
			continue
		}
		if bytes.Equal(bytes.ToLower(blob), blob) || bytes.Equal(bytes.ToUpper(blob), blob) {
			continue
		}
		line, snip := lineAt(b, m[0])
		s.add(Finding{Rule: "encoded-blob", Severity: Medium, File: rel, Line: line, Snippet: snip,
			Explanation: "Long base64-looking string literal. Payloads are often hidden this way and decoded at run time."})
	}
	for _, m := range reHex.FindAllIndex(b, -1) {
		line, snip := lineAt(b, m[0])
		s.add(Finding{Rule: "encoded-blob", Severity: Medium, File: rel, Line: line, Snippet: snip,
			Explanation: "Long hex string literal. Payloads are often hidden this way and decoded at run time."})
	}
	for _, m := range reIP.FindAllSubmatchIndex(b, -1) {
		if privateIP(string(b[m[2]:m[3]])) {
			continue
		}
		line, snip := lineAt(b, m[0])
		s.add(Finding{Rule: "raw-ip-url", Severity: Medium, File: rel, Line: line, Snippet: snip,
			Explanation: "URL that points at a raw public IP address instead of a hostname. Common for payload servers."})
	}
	for _, c := range reCred {
		for _, m := range c.re.FindAllIndex(b, -1) {
			line, snip := lineAt(b, m[0])
			if strings.HasPrefix(strings.TrimSpace(snip), "//") || strings.HasPrefix(strings.TrimSpace(snip), "#") {
				continue
			}
			s.add(Finding{Rule: "credential-path", Severity: c.sev, File: rel, Line: line, Snippet: snip,
				Explanation: "Code references a home-directory location that holds " + c.what + ". Take-home projects have no reason to touch it."})
		}
	}
}

func privateIP(s string) bool {
	ip := net.ParseIP(s)
	return ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.Equal(net.IPv4bcast)
}
