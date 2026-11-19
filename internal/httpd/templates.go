package httpd

import (
	"embed"
	"html/template"
	"io/fs"
	"strings"
)

//go:embed templates/*.html
var templateFS embed.FS

// loadTemplates builds one template per page: the layout cloned with the
// page's "content" block, so pages stay independent of each other.
func loadTemplates() (map[string]*template.Template, error) {
	layoutBytes, err := templateFS.ReadFile("templates/layout.html")
	if err != nil {
		return nil, err
	}
	entries, err := fs.ReadDir(templateFS, "templates")
	if err != nil {
		return nil, err
	}
	out := make(map[string]*template.Template, len(entries))
	for _, e := range entries {
		if e.IsDir() || e.Name() == "layout.html" {
			continue
		}
		pageBytes, err := templateFS.ReadFile("templates/" + e.Name())
		if err != nil {
			return nil, err
		}
		t, err := template.New("layout").Parse(string(layoutBytes))
		if err != nil {
			return nil, err
		}
		if _, err := t.Parse(string(pageBytes)); err != nil {
			return nil, err
		}
		out[strings.TrimSuffix(e.Name(), ".html")] = t
	}
	return out, nil
}
