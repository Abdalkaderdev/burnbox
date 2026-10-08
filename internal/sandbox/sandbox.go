package sandbox

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

//go:embed all:image
var imageFS embed.FS

const home = "/home/burnbox"

type Options struct {
	Repo    string
	Command string
	Timeout time.Duration
	Memory  string
	CPUs    string
}

type Event struct {
	Kind     string `json:"kind"`
	Severity string `json:"severity"`
	Summary  string `json:"summary"`
	Detail   string `json:"detail,omitempty"`
}

type Result struct {
	Command    string   `json:"command"`
	Image      string   `json:"image"`
	ExitCode   int      `json:"exit_code"`
	TimedOut   bool     `json:"timed_out"`
	DurationMS int64    `json:"duration_ms"`
	OutputTail string   `json:"output_tail"`
	Processes  []string `json:"processes"`
	Events     []Event  `json:"events"`
}

var decoys = map[string]string{
	".ssh/id_ed25519":     "decoy SSH key",
	".ssh/id_ed25519.pub": "decoy SSH public key",
	".ssh":                "decoy SSH directory",
	".env":                "decoy .env file",
	".aws/credentials":    "decoy AWS credentials",
	".aws":                "decoy AWS directory",
	".config/gcloud/application_default_credentials.json": "decoy Google Cloud credentials",
	".config/gcloud": "decoy Google Cloud directory",
}

var expectedHosts = set("registry.npmjs.org registry.yarnpkg.com registry.npmmirror.com pypi.org files.pythonhosted.org github.com codeload.github.com objects.githubusercontent.com nodejs.org")

var networkTools = set("curl wget nc ncat netcat socat ssh scp sftp ftp telnet")

func set(s string) map[string]bool {
	m := map[string]bool{}
	for _, w := range strings.Fields(s) {
		m[w] = true
	}
	return m
}

func imageTag() string {
	h := sha256.New()
	fs.WalkDir(imageFS, "image", func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			b, _ := imageFS.ReadFile(p)
			h.Write([]byte(p))
			h.Write(b)
		}
		return nil
	})
	return "burnbox-sandbox:" + hex.EncodeToString(h.Sum(nil))[:12]
}

func ensureImage(ctx context.Context, tag string) error {
	if _, err := exec.LookPath("docker"); err != nil {
		return errors.New("docker not found in PATH; install Docker or run without --run for a static scan only")
	}
	if exec.CommandContext(ctx, "docker", "image", "inspect", tag).Run() == nil {
		return nil
	}
	dir, err := os.MkdirTemp("", "burnbox-image-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	err = fs.WalkDir(imageFS, "image", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		dst := filepath.Join(dir, filepath.FromSlash(strings.TrimPrefix(p, "image")))
		if d.IsDir() {
			return os.MkdirAll(dst, 0o755)
		}
		b, err := imageFS.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(dst, b, 0o644)
	})
	if err != nil {
		return err
	}
	out, err := exec.CommandContext(ctx, "docker", "build", "-q", "-t", tag, dir).CombinedOutput()
	if err != nil {
		return fmt.Errorf("building sandbox image: %v\n%s", err, out)
	}
	return nil
}

func Run(ctx context.Context, o Options) (*Result, error) {
	if o.Timeout <= 0 {
		o.Timeout = 5 * time.Minute
	}
	if o.Memory == "" {
		o.Memory = "2g"
	}
	if o.CPUs == "" {
		o.CPUs = "2"
	}
	repo, err := filepath.Abs(o.Repo)
	if err != nil {
		return nil, err
	}
	tag := imageTag()
	if err := ensureImage(ctx, tag); err != nil {
		return nil, err
	}
	out, err := os.MkdirTemp("", "burnbox-out-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(out)
	if err := os.Chmod(out, 0o777); err != nil {
		return nil, err
	}
	var rnd [6]byte
	rand.Read(rnd[:])
	name := "burnbox-" + hex.EncodeToString(rnd[:])
	secs := strconv.Itoa(int(o.Timeout.Seconds()))
	args := []string{"run", "--rm", "--name", name,
		"--network", "none", "--dns", "127.0.0.1",
		"--cap-drop", "ALL", "--security-opt", "no-new-privileges",
		"--read-only", "--user", "1000:1000",
		"--sysctl", "net.ipv4.ip_unprivileged_port_start=53",
		"--memory", o.Memory, "--memory-swap", o.Memory, "--cpus", o.CPUs, "--pids-limit", "512",
		"--tmpfs", "/tmp:rw,exec,nosuid,size=512m,uid=1000,gid=1000",
		"--tmpfs", "/work:rw,exec,nosuid,size=4g,uid=1000,gid=1000",
		"--tmpfs", home + ":rw,nosuid,size=256m,uid=1000,gid=1000",
		"-v", repo + ":/src:ro", "-v", out + ":/out",
		"-e", "HOME=" + home, "-e", "BURNBOX_CMD=" + o.Command, "-e", "BURNBOX_TIMEOUT=" + secs,
		tag}
	runCtx, cancel := context.WithTimeout(ctx, o.Timeout+90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(runCtx, "docker", args...)
	cmd.Cancel = func() error {
		exec.Command("docker", "kill", name).Run()
		return cmd.Process.Kill()
	}
	start := time.Now()
	dockerOut, err := cmd.CombinedOutput()
	res := &Result{Command: o.Command, Image: tag, DurationMS: time.Since(start).Milliseconds()}
	exitRaw, readErr := os.ReadFile(filepath.Join(out, "exit"))
	if readErr != nil {
		if err == nil {
			err = errors.New("sandbox produced no result")
		}
		return nil, fmt.Errorf("sandbox run failed: %v\n%s", err, dockerOut)
	}
	res.ExitCode, _ = strconv.Atoi(strings.TrimSpace(string(exitRaw)))
	res.TimedOut = res.ExitCode == 124 || res.ExitCode == 137
	if b, err := os.ReadFile(filepath.Join(out, "cmd.log")); err == nil {
		if len(b) > 4000 {
			b = b[len(b)-4000:]
		}
		res.OutputTail = string(b)
	}
	if err := analyze(out, res); err != nil {
		return nil, err
	}
	return res, nil
}

var (
	reQuoted  = regexp.MustCompile(`"((?:[^"\\]|\\.)*)"`)
	reOpen    = regexp.MustCompile(`^open(?:at)?\((?:AT_FDCWD, )?"((?:[^"\\]|\\.)*)", [^)]*\) = (-?\d+)`)
	reConnect = regexp.MustCompile(`^connect\(\d+, \{sa_family=AF_INET6?, sin6?_port=htons\((\d+)\), (?:sin_addr=inet_addr\("([^"]+)"\)|.*?inet_pton\(AF_INET6, "([^"]+)")[^=]*= (.*)$`)
	reClone   = regexp.MustCompile(`^(?:clone3?|v?fork)\(.*\) = (\d+)$`)
)

type proc struct {
	parent int
	argv   string
}

func analyze(dir string, res *Result) error {
	files, _ := filepath.Glob(filepath.Join(dir, "trace.*"))
	type line struct {
		pid  int
		text string
	}
	procs := map[int]*proc{}
	var lines []line
	var pids []int
	for _, f := range files {
		pid, err := strconv.Atoi(strings.TrimPrefix(filepath.Ext(f), "."))
		if err != nil {
			continue
		}
		pids = append(pids, pid)
		if procs[pid] == nil {
			procs[pid] = &proc{}
		}
		fh, err := os.Open(f)
		if err != nil {
			return err
		}
		sc := bufio.NewScanner(fh)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			t := sc.Text()
			if m := reClone.FindStringSubmatch(t); m != nil {
				child, _ := strconv.Atoi(m[1])
				if procs[child] == nil {
					procs[child] = &proc{}
				}
				procs[child].parent = pid
			}
			if strings.HasPrefix(t, "execve(") && strings.HasSuffix(t, "= 0") && procs[pid].argv == "" {
				var argv []string
				for i, q := range reQuoted.FindAllStringSubmatch(t, -1) {
					if i > 0 {
						argv = append(argv, unescape(q[1]))
					}
				}
				procs[pid].argv = strings.Join(argv, " ")
			}
			lines = append(lines, line{pid, t})
		}
		fh.Close()
	}
	sort.Ints(pids)
	argvOf := func(pid int) string {
		for i := 0; i < 64 && procs[pid] != nil; i++ {
			if procs[pid].argv != "" {
				return procs[pid].argv
			}
			pid = procs[pid].parent
		}
		return ""
	}
	seenProc := map[string]bool{}
	for _, pid := range pids {
		a := procs[pid].argv
		if a == "" || seenProc[a] {
			continue
		}
		seenProc[a] = true
		if len(res.Processes) < 200 {
			res.Processes = append(res.Processes, a)
		}
		if bin := path.Base(strings.Fields(a)[0]); networkTools[bin] {
			res.add(Event{Kind: "process", Severity: "medium", Summary: "spawned network tool " + bin, Detail: a})
		}
	}
	for _, l := range lines {
		if m := reOpen.FindStringSubmatch(l.text); m != nil {
			if label, rel := decoyFor(unescape(m[1])); label != "" {
				res.add(Event{Kind: "decoy", Severity: "high", Summary: "accessed " + label,
					Detail: "~/" + rel + " opened by: " + argvOf(l.pid)})
			}
			continue
		}
		if m := reConnect.FindStringSubmatch(l.text); m != nil {
			addr := m[2] + m[3]
			if (addr == "127.0.0.1" || addr == "::1") && m[1] == "53" {
				continue
			}
			res.add(Event{Kind: "connect", Severity: "medium",
				Summary: "attempted connection to " + addr + ":" + m[1] + " (blocked)",
				Detail:  "result: " + m[4] + "; process: " + argvOf(l.pid)})
		}
	}
	if b, err := os.ReadFile(filepath.Join(dir, "dns.log")); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			f := strings.Fields(l)
			if len(f) < 2 {
				continue
			}
			name := strings.ToLower(strings.TrimSuffix(f[1], "."))
			sev := "medium"
			if expectedHosts[name] {
				sev = "low"
			}
			res.add(Event{Kind: "dns", Severity: sev, Summary: "attempted DNS lookup of " + name, Detail: "answered NXDOMAIN by the sandbox resolver"})
		}
	}
	rank := map[string]int{"high": 0, "medium": 1, "low": 2}
	sort.SliceStable(res.Events, func(i, j int) bool { return rank[res.Events[i].Severity] < rank[res.Events[j].Severity] })
	return nil
}

func (r *Result) add(e Event) {
	for _, x := range r.Events {
		if x.Summary == e.Summary {
			return
		}
	}
	r.Events = append(r.Events, e)
}

func decoyFor(p string) (string, string) {
	rel, ok := strings.CutPrefix(p, home+"/")
	if !ok {
		for k := range decoys {
			if strings.Contains(k, "/") && !strings.HasPrefix(p, "/") && strings.HasSuffix(p, k) {
				rel = k
				break
			}
		}
	}
	rel = strings.TrimSuffix(rel, "/")
	if label := decoys[rel]; label != "" {
		return label, rel
	}
	return "", ""
}

func unescape(s string) string {
	if u, err := strconv.Unquote(`"` + s + `"`); err == nil {
		return u
	}
	return s
}
