package scan

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var lifecycle = map[string]Severity{
	"preinstall":  High,
	"install":     High,
	"postinstall": High,
	"preprepare":  Medium,
	"prepare":     Medium,
	"postprepare": Medium,
}

type pkgJSON struct {
	Scripts         map[string]string `json:"scripts"`
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
	OptionalDeps    map[string]string `json:"optionalDependencies"`
}

func (s *scanner) packageJSON(rel string, b []byte) {
	var p pkgJSON
	if json.Unmarshal(b, &p) != nil {
		return
	}
	root := filepath.Dir(rel) == "."
	for _, name := range sortedKeys(p.Scripts) {
		sev, ok := lifecycle[name]
		if !ok {
			continue
		}
		if !root {
			sev = Medium
		}
		line, _ := lineOf(b, `"`+name+`"`)
		s.add(Finding{Rule: "lifecycle-script", Severity: sev, File: rel, Line: line,
			Snippet:     name + ": " + p.Scripts[name],
			Explanation: "npm runs the \"" + name + "\" script automatically during npm install. Read what it executes before installing."})
	}
	deps := map[string]string{}
	for _, m := range []map[string]string{p.Dependencies, p.DevDependencies, p.OptionalDeps} {
		for k, v := range m {
			deps[k] = v
		}
	}
	lock := s.lockfile(filepath.Dir(rel))
	for _, name := range sortedKeys(deps) {
		spec := deps[name]
		line, snip := lineOf(b, `"`+name+`"`)
		if near := typosquat(name, popularNPM); near != "" {
			s.add(Finding{Rule: "typosquat", Severity: High, File: rel, Line: line, Snippet: snip,
				Explanation: "Dependency \"" + name + "\" is one edit away from the popular package \"" + near + "\". Typosquats are a common way to slip in malicious code."})
		}
		if remoteSpec(spec) {
			s.add(Finding{Rule: "dependency-source", Severity: Medium, File: rel, Line: line, Snippet: snip,
				Explanation: "Dependency is fetched from a URL or git repository, bypassing the registry and its malware takedowns."})
		}
		if lock.kind != "" && !lock.has(name) && !strings.HasPrefix(spec, "file:") && !strings.HasPrefix(spec, "link:") && !strings.HasPrefix(spec, "workspace:") {
			s.add(Finding{Rule: "lockfile-mismatch", Severity: Medium, File: rel, Line: line, Snippet: snip,
				Explanation: "Dependency is declared but missing from " + lock.kind + ". Install will resolve whatever version is newest at that moment."})
		}
	}
	for _, name := range lock.installScripts {
		line, snip := lineOf(lock.raw, `"node_modules/`+name+`"`)
		s.add(Finding{Rule: "dependency-install-script", Severity: Medium, File: lock.path, Line: line, Snippet: snip,
			Explanation: "Locked dependency \"" + name + "\" declares an install script that runs during npm install."})
	}
	if root && len(deps) > 0 && lock.kind == "" {
		s.add(Finding{Rule: "no-lockfile", Severity: Low, File: rel,
			Explanation: "No lockfile next to package.json. Every install resolves fresh versions."})
	}
}

func remoteSpec(spec string) bool {
	for _, p := range []string{"http:", "https:", "git:", "git+", "github:", "gitlab:", "bitbucket:", "gist:"} {
		if strings.HasPrefix(spec, p) {
			return true
		}
	}
	return reGitHubShort.MatchString(spec)
}

var reGitHubShort = regexp.MustCompile(`^[\w.-]+/[\w.-]+(#.*)?$`)

type lockInfo struct {
	kind, path     string
	raw            []byte
	names          map[string]bool
	installScripts []string
}

func (l lockInfo) has(name string) bool {
	if l.names != nil {
		return l.names[name]
	}
	return bytes.Contains(l.raw, []byte(name+"@")) || bytes.Contains(l.raw, []byte("/"+name+"@")) || bytes.Contains(l.raw, []byte(" "+name+":"))
}

func (s *scanner) lockfile(dir string) lockInfo {
	for _, name := range []string{"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock"} {
		rel := filepath.Join(dir, name)
		b, err := os.ReadFile(filepath.Join(s.root, rel))
		if err != nil {
			continue
		}
		l := lockInfo{kind: name, path: rel, raw: b}
		if strings.HasSuffix(name, ".json") {
			var lock struct {
				Packages map[string]struct {
					HasInstallScript bool `json:"hasInstallScript"`
				} `json:"packages"`
				Dependencies map[string]json.RawMessage `json:"dependencies"`
			}
			if json.Unmarshal(b, &lock) != nil {
				continue
			}
			l.names = map[string]bool{}
			for k := range lock.Dependencies {
				l.names[k] = true
			}
			for k, v := range lock.Packages {
				i := strings.LastIndex(k, "node_modules/")
				if i < 0 {
					continue
				}
				n := k[i+len("node_modules/"):]
				l.names[n] = true
				if v.HasInstallScript {
					l.installScripts = append(l.installScripts, n)
				}
			}
			sort.Strings(l.installScripts)
		}
		return l
	}
	return lockInfo{}
}

var reReq = regexp.MustCompile(`(?m)^\s*([A-Za-z0-9][A-Za-z0-9._-]*)`)

func (s *scanner) requirements(rel string, b []byte) {
	for _, m := range reReq.FindAllSubmatchIndex(b, -1) {
		name := strings.ToLower(strings.ReplaceAll(string(b[m[2]:m[3]]), "_", "-"))
		if near := typosquat(name, popularPyPI); near != "" {
			line, snip := lineAt(b, m[2])
			s.add(Finding{Rule: "typosquat", Severity: High, File: rel, Line: line, Snippet: snip,
				Explanation: "Requirement \"" + name + "\" is one edit away from the popular package \"" + near + "\"."})
		}
	}
}

func (s *scanner) setupPy(rel string, b []byte) {
	s.add(Finding{Rule: "python-build-hook", Severity: Medium, File: rel, Line: 1, Snippet: firstCodeLine(b),
		Explanation: "setup.py is executed as a program by pip install and python setup.py."})
	if line, snip := lineOf(b, "cmdclass"); line > 0 {
		s.add(Finding{Rule: "python-build-hook", Severity: High, File: rel, Line: line, Snippet: snip,
			Explanation: "setup.py overrides setuptools commands (cmdclass), so custom code runs during install or build."})
	}
}

func (s *scanner) pyproject(rel string, b []byte) {
	if line, snip := lineOf(b, "backend-path"); line > 0 {
		s.add(Finding{Rule: "python-build-hook", Severity: High, File: rel, Line: line, Snippet: snip,
			Explanation: "pyproject.toml uses an in-tree build backend. pip runs this repository's own code to build it."})
	}
}

var reRisky = regexp.MustCompile(`\b(curl|wget|nc|ncat|base64|eval|bash -c|sh -c|powershell|iex|Invoke-Expression)\b|\|\s*(ba)?sh\b`)

func (s *scanner) makefile(rel string, b []byte) {
	lines := strings.Split(string(b), "\n")
	target, head, start := "", "", -1
	for i, l := range lines {
		if l == "" || l[0] == '\t' || l[0] == '#' || l[0] == '.' || strings.Contains(l, "=") && !strings.Contains(strings.SplitN(l, "=", 2)[0], ":") {
			continue
		}
		if c := strings.Index(l, ":"); c > 0 {
			target, head, start = strings.TrimSpace(l[:c]), strings.TrimSpace(l), i
			break
		}
	}
	if start < 0 {
		return
	}
	recipe := []string{}
	for _, l := range lines[start+1:] {
		if !strings.HasPrefix(l, "\t") {
			break
		}
		recipe = append(recipe, strings.TrimSpace(l))
	}
	sev, why := Low, "Running plain `make` executes the first target, \""+target+"\"."
	if reRisky.MatchString(strings.Join(recipe, "\n")) {
		sev, why = Medium, why+" Its recipe downloads, decodes or pipes into a shell."
	}
	s.add(Finding{Rule: "makefile-default", Severity: sev, File: rel, Line: start + 1,
		Snippet: strings.Join(append([]string{head}, recipe...), "; "), Explanation: why})
}

func (s *scanner) vscodeTasks(rel string, b []byte) {
	var t struct {
		Tasks []struct {
			Label   string          `json:"label"`
			Command json.RawMessage `json:"command"`
			Args    json.RawMessage `json:"args"`
			RunOn   struct {
				RunOn string `json:"runOn"`
			} `json:"runOptions"`
		} `json:"tasks"`
	}
	if json.Unmarshal(stripJSONC(b), &t) != nil {
		return
	}
	for _, task := range t.Tasks {
		if task.RunOn.RunOn != "folderOpen" {
			continue
		}
		line, _ := lineOf(b, "folderOpen")
		cmd := strings.Trim(string(task.Command)+" "+string(task.Args), " ")
		s.add(Finding{Rule: "vscode-folder-open-task", Severity: High, File: rel, Line: line,
			Snippet:     task.Label + ": " + cmd,
			Explanation: "VS Code runs this task as soon as the folder is opened, if automatic tasks are allowed or the workspace is trusted. Do not open the folder in an IDE before reading it."})
	}
}

var riskySettings = []string{
	"task.allowAutomaticTasks", "terminal.integrated.", "python.defaultInterpreterPath", "python.pythonPath",
	"python.venvPath", "git.path", "eslint.nodePath", "eslint.runtime", "npm.packageManager",
	"typescript.tsdk", "go.alternateTools", "rust-analyzer.server.path", "php.validate.executablePath",
	"code-runner.executorMap", "jest.jestCommandLine",
}

func (s *scanner) vscodeSettings(rel string, b []byte) {
	var m map[string]json.RawMessage
	if json.Unmarshal(stripJSONC(b), &m) != nil {
		return
	}
	for _, k := range sortedKeys(m) {
		for _, r := range riskySettings {
			if k == r || strings.HasSuffix(r, ".") && strings.HasPrefix(k, r) {
				line, snip := lineOf(b, `"`+k+`"`)
				s.add(Finding{Rule: "vscode-settings", Severity: Medium, File: rel, Line: line, Snippet: snip,
					Explanation: "Workspace setting \"" + k + "\" changes which program the editor or an extension runs, or allows tasks to start on their own."})
				break
			}
		}
	}
}

func (s *scanner) devcontainer(rel string, b []byte) {
	var m map[string]json.RawMessage
	if json.Unmarshal(stripJSONC(b), &m) != nil {
		return
	}
	for _, k := range []string{"initializeCommand", "onCreateCommand", "updateContentCommand", "postCreateCommand", "postStartCommand", "postAttachCommand"} {
		v, ok := m[k]
		if !ok {
			continue
		}
		sev, where := Medium, "inside the dev container"
		if k == "initializeCommand" {
			sev, where = High, "on your host machine, before the container starts"
		}
		line, _ := lineOf(b, `"`+k+`"`)
		s.add(Finding{Rule: "devcontainer-command", Severity: sev, File: rel, Line: line,
			Snippet:     k + ": " + string(v),
			Explanation: "\"Reopen in Container\" runs " + k + " " + where + "."})
	}
}

func (s *scanner) hookFile(rel string, b []byte) {
	s.add(Finding{Rule: "git-hook", Severity: Medium, File: rel, Line: 1, Snippet: firstCodeLine(b),
		Explanation: "Git hook or hook-manager config. It runs on commit, push or checkout once installed (husky installs it from the prepare script)."})
}

func (s *scanner) gitHooks() {
	dir := filepath.Join(s.root, ".git", "hooks")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() || strings.HasSuffix(e.Name(), ".sample") {
			continue
		}
		b, _ := os.ReadFile(filepath.Join(dir, e.Name()))
		s.add(Finding{Rule: "git-hook", Severity: High, File: filepath.Join(".git", "hooks", e.Name()), Line: 1, Snippet: firstCodeLine(b),
			Explanation: "Active git hook in this checkout. It runs on your machine on the next git operation."})
	}
}

func firstCodeLine(b []byte) string {
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "#") {
			return l
		}
	}
	return ""
}

func stripJSONC(b []byte) []byte {
	out := make([]byte, 0, len(b))
	inStr := false
	for i := 0; i < len(b); i++ {
		c := b[i]
		switch {
		case inStr:
			out = append(out, c)
			if c == '\\' && i+1 < len(b) {
				i++
				out = append(out, b[i])
			} else if c == '"' {
				inStr = false
			}
		case c == '"':
			inStr = true
			out = append(out, c)
		case c == '/' && i+1 < len(b) && b[i+1] == '/':
			for i < len(b) && b[i] != '\n' {
				i++
			}
			out = append(out, '\n')
		case c == '/' && i+1 < len(b) && b[i+1] == '*':
			end := bytes.Index(b[i+2:], []byte("*/"))
			if end < 0 {
				return out
			}
			out = append(out, bytes.Repeat([]byte("\n"), bytes.Count(b[i:i+2+end], []byte("\n")))...)
			i += end + 3
		default:
			out = append(out, c)
		}
	}
	return reTrailingComma.ReplaceAll(out, []byte("$1"))
}

var reTrailingComma = regexp.MustCompile(`,(\s*[}\]])`)

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
