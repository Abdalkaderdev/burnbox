package sandbox

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func needDocker(t *testing.T) {
	if os.Getenv("BURNBOX_SANDBOX_TESTS") == "" {
		t.Skip("set BURNBOX_SANDBOX_TESTS=1 to run sandbox tests (needs Docker)")
	}
}

func run(t *testing.T, repo, command string, timeout time.Duration) *Result {
	t.Helper()
	res, err := Run(context.Background(), Options{Repo: repo, Command: command, Timeout: timeout})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%s: exit %d in %dms", command, res.ExitCode, res.DurationMS)
	return res
}

func hasEvent(r *Result, summary string) bool {
	for _, e := range r.Events {
		if e.Summary == summary {
			return true
		}
	}
	return false
}

func TestProbes(t *testing.T) {
	needDocker(t)
	r := run(t, "testdata/probe", "cat ~/.ssh/id_ed25519 > /dev/null; getent hosts probe.burnbox.test; true", time.Minute)
	for _, want := range []string{"accessed decoy SSH key", "attempted DNS lookup of probe.burnbox.test"} {
		if !hasEvent(r, want) {
			t.Errorf("missing event %q in %+v", want, r.Events)
		}
	}
	for _, e := range r.Events {
		if e.Summary == "accessed decoy SSH key" && !strings.Contains(e.Detail, "cat") {
			t.Errorf("decoy access not attributed to cat: %q", e.Detail)
		}
	}
}

func TestNoNetwork(t *testing.T) {
	needDocker(t)
	r := run(t, "testdata/probe", `ls /sys/class/net; node -e "require('net').connect(443, '1.1.1.1').on('connect', () => { console.log('CONNECTED'); process.exit(0) }).on('error', e => console.log('ERR', e.code))"; getent hosts example.com || echo LOOKUP-FAILED`, time.Minute)
	out := r.OutputTail
	if strings.Contains(out, "CONNECTED") || !strings.Contains(out, "ERR ENETUNREACH") || !strings.Contains(out, "LOOKUP-FAILED") {
		t.Fatalf("container reached the network:\n%s", out)
	}
	if fields := strings.Fields(strings.SplitN(out, "ERR", 2)[0]); len(fields) != 1 || fields[0] != "lo" {
		t.Errorf("expected only the loopback interface, got %v", fields)
	}
	if !hasEvent(r, "attempted connection to 1.1.1.1:443 (blocked)") || !hasEvent(r, "attempted DNS lookup of example.com") {
		t.Errorf("network attempts not reported: %+v", r.Events)
	}
}

func TestLifecycleScriptObserved(t *testing.T) {
	needDocker(t)
	r := run(t, "../scan/testdata/lifecycle", "npm install --no-audit --no-fund", 3*time.Minute)
	found := false
	for _, p := range r.Processes {
		found = found || strings.Contains(p, "scripts/setup.js")
	}
	if !found || r.ExitCode != 0 {
		t.Errorf("postinstall not observed (exit %d): %v\n%s", r.ExitCode, r.Processes, r.OutputTail)
	}
	for _, e := range r.Events {
		if e.Kind == "decoy" {
			t.Errorf("unexpected decoy access: %+v", e)
		}
	}
}

func TestTimeout(t *testing.T) {
	needDocker(t)
	r := run(t, "testdata/probe", "sleep 60", 3*time.Second)
	if !r.TimedOut {
		t.Errorf("expected timeout, got exit %d", r.ExitCode)
	}
}

func TestDecoyFor(t *testing.T) {
	for p, want := range map[string]string{
		"/home/burnbox/.ssh/id_ed25519": "decoy SSH key",
		"/home/burnbox/.ssh/":           "decoy SSH directory",
		".aws/credentials":              "decoy AWS credentials",
		"/work/.env":                    "",
		"/home/burnbox/.npm/_cacache":   "",
	} {
		if got, _ := decoyFor(p); got != want {
			t.Errorf("decoyFor(%q) = %q, want %q", p, got, want)
		}
	}
}
