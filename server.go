package main

import (
	"html/template"
	"log"
	"net/http"
	"path/filepath"
	"runtime"
	"strings"
)

func resultsHandler(w http.ResponseWriter, r *http.Request) {
	performancePerDomainLock.Lock()
	p := performancePerDomain
	performancePerDomainLock.Unlock()

	// Get source path
	_, path, _, _ := runtime.Caller(0)
	root := filepath.Dir(path)

	if r.URL.Path[len(r.URL.Path)-1] == '/' {
		var tpl = template.Must(template.ParseFiles(filepath.Join(root, "templates", "index.html")))
		tpl.Execute(w, p)
	} else {
		domain := r.URL.Path[strings.LastIndexByte(r.URL.Path, '/')+1:]
		var tpl = template.Must(template.ParseFiles(filepath.Join(root, "templates", "domain.html")))
		if result, ok := performancePerDomain[domain]; ok {
			err := tpl.Execute(w, map[string]interface{}{
				"domain": domain,
				"result": result,
			})
			if err != nil {
				log.Println("failed to send response:", err)
			}
		} else {
			w.WriteHeader(http.StatusNotFound)
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte("domain not found"))
		}
	}
}
