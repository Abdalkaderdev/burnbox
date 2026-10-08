package scan

import (
	"bytes"
	"regexp"
	"strings"

	"github.com/tdewolff/parse/v2"
	"github.com/tdewolff/parse/v2/js"
)

var cpMethods = set("exec execSync spawn spawnSync execFile execFileSync fork")

func isCPModule(b []byte) bool {
	m := strings.Trim(string(b), "'\"`")
	return m == "child_process" || m == "node:child_process"
}

type jsVisitor struct {
	s       *scanner
	file    string
	src     []byte
	last    int
	cpVars  map[string]bool
	cpFuncs map[string]bool
	seen    map[*js.BinaryExpr]bool
}

func (s *scanner) javascript(rel string, b []byte) bool {
	buf := make([]byte, len(b), len(b)+1)
	copy(buf, b)
	ast, err := js.Parse(parse.NewInputBytes(buf), js.Options{})
	if err != nil {
		return false
	}
	v := &jsVisitor{s: s, file: rel, src: buf, cpVars: map[string]bool{}, cpFuncs: map[string]bool{}, seen: map[*js.BinaryExpr]bool{}}
	js.Walk(v, ast)
	return true
}

func (v *jsVisitor) mark(data []byte) {
	off := cap(v.src) - cap(data)
	if off >= v.last && off+len(data) <= len(v.src) && bytes.Equal(v.src[off:off+len(data)], data) {
		v.last = off
	}
}

func (v *jsVisitor) report(rule string, sev Severity, anchor, why string) {
	off := v.last
	i := bytes.Index(v.src[v.last:], []byte(anchor+"("))
	if i < 0 {
		i = bytes.Index(v.src[v.last:], []byte(anchor))
	}
	if i >= 0 {
		off = v.last + i
		v.last = off
	}
	line, snip := lineAt(v.src, off)
	v.s.add(Finding{Rule: rule, Severity: sev, File: v.file, Line: line, Snippet: snip, Explanation: why})
}

func (v *jsVisitor) Exit(js.INode) {}

func (v *jsVisitor) Enter(n js.INode) js.IVisitor {
	switch n := n.(type) {
	case *js.LiteralExpr:
		v.mark(n.Data)
	case *js.ImportStmt:
		if isCPModule(n.Module) {
			if n.Default != nil {
				v.cpVars[string(n.Default)] = true
			}
			for _, a := range n.List {
				orig, local := string(a.Name), string(a.Binding)
				if orig == "" {
					orig = local
				}
				if orig == "*" {
					v.cpVars[local] = true
				} else if cpMethods[orig] {
					v.cpFuncs[local] = true
				}
			}
		}
	case *js.BindingElement:
		if !isRequireCP(n.Default) {
			break
		}
		switch b := n.Binding.(type) {
		case *js.Var:
			v.cpVars[string(b.Data)] = true
		case *js.BindingObject:
			for _, item := range b.List {
				local, ok := item.Value.Binding.(*js.Var)
				if !ok {
					continue
				}
				orig := string(local.Data)
				if item.Key != nil && item.Key.Literal.Data != nil {
					orig = string(item.Key.Literal.Data)
				}
				if cpMethods[orig] {
					v.cpFuncs[string(local.Data)] = true
				}
			}
		}
	case *js.NewExpr:
		if !isVar(n.X, "Function") {
			break
		}
		if n.Args == nil || allConst(n.Args.List) {
			v.report("dynamic-code", Medium, "Function", "new Function compiles constant strings into code. Harmless on its own but unusual in application code.")
		} else {
			v.report("dynamic-code", High, "Function", "new Function compiles a string built at run time into code, which hides what actually runs.")
		}
	case *js.CallExpr:
		v.call(n)
	case *js.BinaryExpr:
		v.concat(n)
	}
	return v
}

func (v *jsVisitor) call(n *js.CallExpr) {
	var first js.IExpr
	if len(n.Args.List) > 0 {
		first = n.Args.List[0].Value
	}
	obj, method := member(n.X)
	switch {
	case isVar(n.X, "eval") || method == "eval" && (isVar(obj, "window") || isVar(obj, "globalThis") || isVar(obj, "global") || isVar(obj, "self")):
		if isConst(first) {
			v.report("dynamic-code", Medium, "eval", "eval runs a string as code. This call uses a constant string, which is harmless on its own but unusual in application code.")
		} else {
			v.report("dynamic-code", High, "eval", "eval runs a string that is computed at run time. Decoded or downloaded payloads are usually executed this way.")
		}
	case isVar(n.X, "Function"):
		v.report("dynamic-code", High, "Function", "Function(...) compiles a string into code at run time.")
	case v.isCPCall(n.X, obj, method):
		name := method
		if name == "" {
			name = string(n.X.(*js.Var).Data)
		}
		if isConst(first) {
			v.report("child-process", Medium, name, "Spawns a fixed shell command via child_process.")
		} else {
			v.report("child-process", High, name, "Spawns a process via child_process with a command built at run time, so the scan cannot see what runs.")
		}
	case method == "join":
		if arr, ok := obj.(*js.ArrayExpr); ok {
			var parts []string
			for _, el := range arr.List {
				s, ok := strLit(el.Value)
				if !ok {
					return
				}
				parts = append(parts, s)
			}
			v.splitURL(parts, "join")
		}
	case method == "fromCharCode" && isVar(obj, "String") && len(n.Args.List) >= 6:
		v.report("string-obfuscation", Medium, "fromCharCode", "Builds a string from character codes, a common way to hide URLs and commands from readers and scanners.")
	}
}

func (v *jsVisitor) isCPCall(x, obj js.IExpr, method string) bool {
	if xv, ok := x.(*js.Var); ok {
		return v.cpFuncs[string(xv.Data)]
	}
	if !cpMethods[method] {
		return false
	}
	if ov, ok := obj.(*js.Var); ok {
		return v.cpVars[string(ov.Data)]
	}
	return isRequireCP(obj)
}

func (v *jsVisitor) concat(n *js.BinaryExpr) {
	if v.seen[n] || n.Op != js.AddToken {
		return
	}
	var parts []string
	var walk func(e js.IExpr)
	walk = func(e js.IExpr) {
		if b, ok := e.(*js.BinaryExpr); ok && b.Op == js.AddToken {
			v.seen[b] = true
			walk(b.X)
			walk(b.Y)
			return
		}
		if s, ok := strLit(e); ok {
			parts = append(parts, s)
		}
	}
	walk(n)
	v.splitURL(parts, "+")
}

var reScheme = regexp.MustCompile(`(?i)\b(?:https?|wss?|ftp)://`)

func (v *jsVisitor) splitURL(parts []string, anchor string) {
	if len(parts) < 2 {
		return
	}
	joined := strings.Join(parts, "")
	if !reScheme.MatchString(joined) {
		return
	}
	for _, p := range parts {
		if reScheme.MatchString(p) {
			return
		}
	}
	v.report("split-url", Medium, anchor, "A URL scheme is split across string fragments and glued back together at run time, which hides the address from search and review.")
}

func member(x js.IExpr) (js.IExpr, string) {
	d, ok := x.(*js.DotExpr)
	if !ok {
		return nil, ""
	}
	switch y := d.Y.(type) {
	case js.LiteralExpr:
		return d.X, string(y.Data)
	case *js.Var:
		return d.X, string(y.Data)
	}
	return d.X, ""
}

func isVar(x js.IExpr, name string) bool {
	v, ok := x.(*js.Var)
	return ok && string(v.Data) == name
}

func isRequireCP(x js.IExpr) bool {
	c, ok := x.(*js.CallExpr)
	if !ok || !isVar(c.X, "require") || len(c.Args.List) == 0 {
		return false
	}
	l, ok := c.Args.List[0].Value.(*js.LiteralExpr)
	return ok && isCPModule(l.Data)
}

func strLit(x js.IExpr) (string, bool) {
	switch e := x.(type) {
	case *js.LiteralExpr:
		if e.TokenType == js.StringToken {
			return string(e.Data[1 : len(e.Data)-1]), true
		}
	case *js.TemplateExpr:
		if e.Tag == nil && len(e.List) == 0 {
			return string(bytes.Trim(e.Tail, "`")), true
		}
	}
	return "", false
}

func allConst(args []js.Arg) bool {
	for _, a := range args {
		if !isConst(a.Value) {
			return false
		}
	}
	return true
}

func isConst(x js.IExpr) bool {
	if x == nil {
		return true
	}
	if _, ok := strLit(x); ok {
		return true
	}
	if b, ok := x.(*js.BinaryExpr); ok {
		return isConst(b.X) && isConst(b.Y)
	}
	l, ok := x.(*js.LiteralExpr)
	return ok && l.TokenType != js.RegExpToken
}

var (
	reEval     = regexp.MustCompile(`(?:^|[^.\w$])(eval|exec)\s*\(\s*(.)`)
	reNewFunc  = regexp.MustCompile(`\bnew\s+Function\s*\(`)
	reCPImport = regexp.MustCompile(`(?:import\s+\*\s+as\s+|(?:const|let|var)\s+)(\w+)\s*(?:from\s*|=\s*require\s*\(\s*)['"](?:node:)?child_process['"]`)
	reCPCall   = regexp.MustCompile(`(?:^|[^\w$])(?:(\w+)\.)?(exec|execSync|spawn|spawnSync|execFile|execFileSync|fork)\(\s*(.)`)
	rePyShell  = regexp.MustCompile(`\b(os\.system|os\.popen|subprocess\.(?:run|call|Popen|check_output|check_call|getoutput))\s*\(\s*(.)`)
	rePyDecode = regexp.MustCompile(`\b(exec|eval)\s*\(.*\b(b64decode|b32decode|a85decode|fromhex|decompress|marshal\.loads|codecs\.decode)\b`)
)

func (s *scanner) codeRegex(rel string, b []byte, lang string) {
	hasCP := bytes.Contains(b, []byte("child_process"))
	cpVars := map[string]bool{}
	for _, m := range reCPImport.FindAllSubmatch(b, -1) {
		cpVars[string(m[1])] = true
	}
	off := 0
	for _, raw := range bytes.SplitAfter(b, []byte("\n")) {
		line := string(raw)
		base := off
		at := func(i int) (int, string) { return lineAt(b, base+i) }
		trim := strings.TrimSpace(line)
		off += len(raw)
		if strings.HasPrefix(trim, "//") || strings.HasPrefix(trim, "#") || strings.HasPrefix(trim, "*") {
			continue
		}
		if lang == "py" {
			if m := rePyDecode.FindStringIndex(line); m != nil {
				n, sn := at(m[0])
				s.add(Finding{Rule: "dynamic-code", Severity: High, File: rel, Line: n, Snippet: sn,
					Explanation: "Decodes data and executes it in one step. This is how hidden payloads are usually unpacked."})
				continue
			}
		}
		for _, m := range reEval.FindAllStringSubmatchIndex(line, -1) {
			fn := line[m[2]:m[3]]
			if fn == "exec" && lang != "py" {
				continue
			}
			sev, why := High, fn+" runs a string that is computed at run time."
			if literalArg(line[m[4]:]) {
				sev, why = Medium, fn+" runs a constant string as code. Harmless on its own but unusual in application code."
			}
			n, sn := at(m[2])
			s.add(Finding{Rule: "dynamic-code", Severity: sev, File: rel, Line: n, Snippet: sn, Explanation: why})
		}
		if lang == "js" {
			if m := reNewFunc.FindStringIndex(line); m != nil {
				sev, why := High, "new Function compiles a string built at run time into code."
				if literalArg(strings.TrimSpace(line[m[1]:])) {
					sev, why = Medium, "new Function compiles a constant string into code. Unusual in application code."
				}
				n, sn := at(m[0])
				s.add(Finding{Rule: "dynamic-code", Severity: sev, File: rel, Line: n, Snippet: sn, Explanation: why})
			}
			if hasCP {
				for _, m := range reCPCall.FindAllStringSubmatchIndex(line, -1) {
					if m[2] >= 0 && !cpVars[line[m[2]:m[3]]] {
						continue
					}
					sev, why := High, "Spawns a process via child_process with a command built at run time."
					if literalArg(line[m[6]:]) {
						sev, why = Medium, "Spawns a fixed shell command via child_process."
					}
					n, sn := at(m[4])
					s.add(Finding{Rule: "child-process", Severity: sev, File: rel, Line: n, Snippet: sn, Explanation: why})
				}
			}
		}
		if lang == "py" {
			for _, m := range rePyShell.FindAllStringSubmatchIndex(line, -1) {
				sev, why := Medium, "Runs an external command built at run time."
				if line[m[4]] == '[' || literalArg(line[m[4]:]) {
					sev, why = Low, "Runs a fixed external command."
				} else if strings.Contains(line, "shell=True") || line[m[2]:m[3]] == "os.system" || line[m[2]:m[3]] == "os.popen" {
					sev, why = High, "Runs a shell command built at run time."
				}
				n, sn := at(m[2])
				s.add(Finding{Rule: "child-process", Severity: sev, File: rel, Line: n, Snippet: sn, Explanation: why})
			}
		}
	}
}

func literalArg(rest string) bool {
	if rest == "" || !strings.ContainsRune("'\"`", rune(rest[0])) {
		return false
	}
	q := rest[0]
	for i := 1; i < len(rest); i++ {
		switch rest[i] {
		case '\\':
			i++
		case '$':
			if q == '`' && i+1 < len(rest) && rest[i+1] == '{' {
				return false
			}
		case q:
			tail := strings.TrimSpace(rest[i+1:])
			return tail == "" || tail[0] == ',' || tail[0] == ')'
		}
	}
	return false
}
