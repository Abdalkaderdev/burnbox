package report

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/Abdalkaderdev/burnbox/internal/sandbox"
	"github.com/Abdalkaderdev/burnbox/internal/scan"
)

const (
	Clean     = "CLEAN"
	Review    = "REVIEW"
	Dangerous = "DANGEROUS"
)

type Report struct {
	Tool      string          `json:"tool"`
	Version   string          `json:"version"`
	Target    string          `json:"target"`
	Commit    string          `json:"commit,omitempty"`
	CreatedAt time.Time       `json:"created_at"`
	Verdict   string          `json:"verdict"`
	Reasons   []string        `json:"reasons"`
	StaticMS  int64           `json:"static_ms"`
	Static    scan.Result     `json:"static"`
	Sandbox   *sandbox.Result `json:"sandbox,omitempty"`
}

func (r *Report) Decide() {
	r.Verdict, r.Reasons = Clean, nil
	high := r.Count(scan.High)
	if high > 0 {
		r.Verdict = Review
		r.Reasons = append(r.Reasons, plural(high, "high-severity static finding"))
	}
	if r.Sandbox == nil {
		return
	}
	for _, e := range r.Sandbox.Events {
		switch e.Severity {
		case "high":
			r.Verdict = Dangerous
			r.Reasons = append(r.Reasons, "sandbox: "+e.Summary)
		case "medium":
			if r.Verdict == Clean {
				r.Verdict = Review
			}
			r.Reasons = append(r.Reasons, "sandbox: "+e.Summary)
		}
	}
	if r.Sandbox.TimedOut {
		if r.Verdict == Clean {
			r.Verdict = Review
		}
		r.Reasons = append(r.Reasons, "sandbox: command hit the time limit, so later behaviour was not observed")
	}
}

func (r *Report) Count(s scan.Severity) int {
	n := 0
	for _, f := range r.Static.Findings {
		if f.Severity == s {
			n++
		}
	}
	return n
}

func (r *Report) ExitCode() int {
	switch r.Verdict {
	case Dangerous:
		return 2
	case Review:
		return 1
	}
	return 0
}

func plural(n int, s string) string {
	if n == 1 {
		return "1 " + s
	}
	return fmt.Sprintf("%d %ss", n, s)
}

type palette struct{ red, orange, green, dim, bold, reset string }

func colors(on bool) palette {
	if !on {
		return palette{}
	}
	return palette{"\x1b[38;5;196m", "\x1b[38;5;202m", "\x1b[38;5;42m", "\x1b[2m", "\x1b[1m", "\x1b[0m"}
}

func (p palette) sev(s string) string {
	switch s {
	case "high":
		return p.red + p.bold + "HIGH" + p.reset
	case "medium":
		return p.orange + "MED " + p.reset
	}
	return p.dim + "LOW " + p.reset
}

func (r *Report) WriteText(w io.Writer, color bool) {
	p := colors(color)
	fmt.Fprintf(w, "%sburnbox%s %s%s%s  %s\n\n", p.bold, p.reset, p.dim, r.Version, p.reset, r.Target)
	fmt.Fprintf(w, "%sstatic scan%s  %d files in %dms  %s%d high%s  %s%d medium%s  %d low\n",
		p.bold, p.reset, r.Static.Files, r.StaticMS, p.red, r.Count(scan.High), p.reset, p.orange, r.Count(scan.Medium), p.reset, r.Count(scan.Low))
	for _, f := range r.Static.Findings {
		loc := f.File
		if f.Line > 0 {
			loc = fmt.Sprintf("%s:%d", f.File, f.Line)
		}
		fmt.Fprintf(w, "\n  %s  %s  %s%s%s\n", p.sev(string(f.Severity)), loc, p.dim, f.Rule, p.reset)
		if f.Snippet != "" {
			fmt.Fprintf(w, "        %s│%s %s\n", p.dim, p.reset, f.Snippet)
		}
		fmt.Fprintf(w, "        %s%s%s\n", p.dim, f.Explanation, p.reset)
	}
	if s := r.Sandbox; s != nil {
		status := fmt.Sprintf("exit %d", s.ExitCode)
		if s.TimedOut {
			status = "timed out"
		}
		fmt.Fprintf(w, "\n%ssandbox%s  %s  %s in %.1fs  %sno network, decoy HOME, all capabilities dropped%s\n",
			p.bold, p.reset, s.Command, status, float64(s.DurationMS)/1000, p.dim, p.reset)
		if len(s.Events) == 0 {
			fmt.Fprintf(w, "\n  %snothing touched the decoys or the network%s\n", p.green, p.reset)
		}
		for _, e := range s.Events {
			fmt.Fprintf(w, "\n  %s  %s\n", p.sev(e.Severity), e.Summary)
			if e.Detail != "" {
				fmt.Fprintf(w, "        %s%s%s\n", p.dim, e.Detail, p.reset)
			}
		}
		if len(s.Processes) > 0 {
			fmt.Fprintf(w, "\n  %sprocesses (%d)%s\n", p.dim, len(s.Processes), p.reset)
			for i, proc := range s.Processes {
				if i == 12 {
					fmt.Fprintf(w, "        %s... %d more in --json / --report%s\n", p.dim, len(s.Processes)-12, p.reset)
					break
				}
				fmt.Fprintf(w, "        %s\n", clip(proc, 110))
			}
		}
	}
	vc := p.green
	switch r.Verdict {
	case Dangerous:
		vc = p.red
	case Review:
		vc = p.orange
	}
	fmt.Fprintf(w, "\n%sverdict%s  %s%s%s%s\n", p.bold, p.reset, vc, p.bold, r.Verdict, p.reset)
	for _, reason := range r.Reasons {
		fmt.Fprintf(w, "  - %s\n", reason)
	}
	if r.Sandbox == nil {
		fmt.Fprintf(w, "  %sstatic scan only; add --run \"npm install\" to watch it run in the sandbox%s\n", p.dim, p.reset)
	}
}

func clip(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > n {
		return s[:n-3] + "..."
	}
	return s
}
