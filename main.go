package main

import (
	"fmt"
	"net/http"
)

func main() {

	mux := http.NewServeMux()

	var root http.Dir = "."
	fileServerHandler := http.FileServer(root)
	mux.Handle("/", fileServerHandler)

	server := http.Server{
		Addr:    "localhost:8080",
		Handler: mux,
	}

	if err := server.ListenAndServe(); err != nil {
		fmt.Printf("error listening and serving - %v", err)
	}

}
