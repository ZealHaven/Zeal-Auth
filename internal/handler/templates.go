package handler

import (
	"html/template"
	"net/http"
	"path/filepath"
	"runtime"
	"sync"
)

var (
	tmplOnce sync.Once
	tmpl     *template.Template
)

func templatesDir() string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(filename), "..", "..", "templates")
}

func getTemplates() *template.Template {
	tmplOnce.Do(func() {
		pattern := filepath.Join(templatesDir(), "*.html")
		tmpl = template.Must(template.ParseGlob(pattern))
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
