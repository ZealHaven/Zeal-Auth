package handler

import (
	"embed"
	"html/template"
	"net/http"
	"path/filepath"
	"sync"
)

//go:embed templates/*.html
var templateFS embed.FS

var (
	tmplOnce sync.Once
	tmpl     *template.Template
)

func getTemplates() *template.Template {
	tmplOnce.Do(func() {
		tmpl = template.Must(template.ParseFS(templateFS, "templates/*.html"))
	})
	return tmpl
}

func renderTemplate(w http.ResponseWriter, name string, data any) {
	t := getTemplates()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(w, name, data); err != nil {
		http.Error(w, "template error: "+err.Error(), http.StatusInternalServerError)
	}
}

func templateExists(name string) bool {
	t := getTemplates()
	for _, t := range t.Templates() {
		if t.Name() == filepath.Base(name) {
			return true
		}
	}
	return false
}
