package main

import (
	"fmt"
	"net/http"
)

func main() {

	mux := http.NewServeMux()

	mux.Handle("/", http.FileServer(http.Dir(".")))

	mux.Handle("/assets", http.FileServer(http.Dir("./assets")))

	mux.Handle("/healthz")

	server := &http.Server{
		Addr:    "localhost:8080",
		Handler: mux,
	}

	if err := server.ListenAndServe(); err != nil {
		fmt.Printf("error listening and serving - %v", err)
	}

}
