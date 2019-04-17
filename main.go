package main

import (
	"log"
	"net/http"
	"time"
)

func main() {
	go func() {
		for {
			update("maildir", "example.com")
			time.Sleep(time.Minute)
		}
	}()

	http.HandleFunc("/", resultsHandler)
	addr := ":8028"
	log.Printf("Serving on %s", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}
