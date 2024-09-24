package main

import (
	"fmt"
	"net/http"
)

type apiConfig struct {
	fileserverHits int
}

var appHandler http.Handler = http.FileServer(http.Dir("."))
var assetsHandler http.Handler = http.FileServer(http.Dir("./assets"))
var adminHandler http.Handler = http.FileServer(http.Dir("./admin"))

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits++
		// fmt.Printf("Hits incremented. Current count: %d\n", cfg.fileserverHits)
		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) serverHitsHandler(w http.ResponseWriter, r *http.Request) {
	// fmt.Printf("Serving metrics. Current count: %d\n", cfg.fileserverHits)
	fmt.Fprintf(w, "Hits: %d", cfg.fileserverHits)
}

func (cfg *apiConfig) resetHitsHandler(w http.ResponseWriter, r *http.Request) {
	cfg.fileserverHits = 0
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Hits counter reset to %d", cfg.fileserverHits)
}

func healthzFunc(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func main() {
	apiCfg := apiConfig{
		fileserverHits: 0,
	}

	mux := http.NewServeMux()

	mux.Handle("/app/", http.StripPrefix("/app", apiCfg.middlewareMetricsInc(appHandler)))
	mux.Handle("/admin/", http.StripPrefix("/admin", adminHandler))
	mux.Handle("/assets/", http.StripPrefix("/assets", assetsHandler))
	mux.HandleFunc("GET /api/healthz", healthzFunc)
	mux.HandleFunc("GET /api/metrics", apiCfg.serverHitsHandler)
	mux.HandleFunc("/api/reset", apiCfg.resetHitsHandler)

	server := &http.Server{
		Addr:    "localhost:8080",
		Handler: mux,
	}

	if err := server.ListenAndServe(); err != nil {
		fmt.Printf("error listening and serving - %v", err)
	}

}
