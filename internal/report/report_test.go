package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Abdalkaderdev/burnbox/internal/sandbox"
	"github.com/Abdalkaderdev/burnbox/internal/scan"
)

func TestDecide(t *testing.T) {
	high := scan.Finding{Rule: "lifecycle-script", Severity: scan.High, File: "package.json", Line: 6, Explanation: "x"}
	cases := []struct {
		name     string
		findings []scan.Finding
		sb       *sandbox.Result
		want     string
		code     int
	}{
		{"empty", nil, nil, Clean, 0},
		{"static high", []scan.Finding{high}, nil, Review, 1},
		{"medium only", []scan.Finding{{Severity: scan.Medium}}, &sandbox.Result{}, Clean, 0},
		{"dns", nil, &sandbox.Result{Events: []sandbox.Event{{Severity: "medium", Summary: "attempted DNS lookup of probe.burnbox.test"}}}, Review, 1},
		{"registry dns", nil, &sandbox.Result{Events: []sandbox.Event{{Severity: "low", Summary: "attempted DNS lookup of registry.npmjs.org"}}}, Clean, 0},
		{"decoy", []scan.Finding{high}, &sandbox.Result{Events: []sandbox.Event{{Severity: "high", Summary: "accessed decoy SSH key"}}}, Dangerous, 2},
		{"timeout", nil, &sandbox.Result{TimedOut: true}, Review, 1},
	}
	for _, c := range cases {
		r := &Report{Static: scan.Result{Findings: c.findings}, Sandbox: c.sb}
		r.Decide()
		if r.Verdict != c.want || r.ExitCode() != c.code {
			t.Errorf("%s: got %s/%d, want %s/%d (%v)", c.name, r.Verdict, r.ExitCode(), c.want, c.code, r.Reasons)
		}
	}
}

func TestOutputs(t *testing.T) {
	r := &Report{Version: "test", Target: "<repo>", Static: scan.Result{Files: 3, Findings: []scan.Finding{
		{Rule: "dynamic-code", Severity: scan.High, File: "a.js", Line: 2, Snippet: `eval("<b>")`, Explanation: "runs code"},
	}}, Sandbox: &sandbox.Result{Command: "npm install", Events: []sandbox.Event{{Kind: "decoy", Severity: "high", Summary: "accessed decoy SSH key"}}, Processes: []string{"sh -c npm install"}}}
	r.Decide()
	var h bytes.Buffer
	if err := r.WriteHTML(&h); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"DANGEROUS", "a.js:2", "accessed decoy SSH key", "&lt;repo&gt;", "eval(&#34;&lt;b&gt;&#34;)"} {
		if !strings.Contains(h.String(), want) {
			t.Errorf("html missing %q", want)
		}
	}
	if strings.ContainsAny(h.String(), "\u2014\u2013") {
		t.Error("html contains an em or en dash")
	}
	var txt bytes.Buffer
	r.WriteText(&txt, false)
	if !strings.Contains(txt.String(), "verdict  DANGEROUS") || strings.Contains(txt.String(), "\x1b[") {
		t.Errorf("unexpected text output:\n%s", txt.String())
	}
}
