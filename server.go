package main

import (
	"html/template"
	"net/http"
	"strings"
)

func resultsHandler(w http.ResponseWriter, r *http.Request) {
	performancePerDomainLock.Lock()
	p := performancePerDomain
	performancePerDomainLock.Unlock()

	if r.URL.Path[len(r.URL.Path)-1] == '/' {
		var tpl = template.Must(template.ParseFiles("templates/index.html"))
		tpl.Execute(w, p)
	} else {
		domain := r.URL.Path[strings.LastIndexByte(r.URL.Path, '/')+1:]
		var tpl = template.Must(template.ParseFiles("templates/domain.html"))
		if result, ok := performancePerDomain[domain]; ok {
			tpl.Execute(w, map[string]interface{}{
				"domain": domain,
				"result": result,
			})
		} else {
			w.WriteHeader(http.StatusNotFound)
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte("domain not found"))
		}
	}
}
