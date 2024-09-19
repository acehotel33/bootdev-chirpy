package main

import (
	"fmt"
	"net/http"
)

func main() {

	myMux := http.NewServeMux()

	server := http.Server{
		Addr:    "localhost:8080",
		Handler: myMux,
	}

	if err := server.ListenAndServe(); err != nil {
		fmt.Printf("error listening and serving - %v", err)
	}

}
