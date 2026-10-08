package report

import (
	_ "embed"
	"fmt"
	"html/template"
	"io"
	"strings"
)

//go:embed report.html
var htmlSrc string

var tmpl = template.Must(template.New("report").Funcs(template.FuncMap{
	"lower": strings.ToLower,
	"secs":  func(ms int64) string { return fmt.Sprintf("%.1fs", float64(ms)/1000) },
}).Parse(htmlSrc))

func (r *Report) WriteHTML(w io.Writer) error {
	return tmpl.Execute(w, r)
}
