package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

type apiConfig struct {
	fileserverHits int
}

var ProfaneWords = []string{"kerfuffle", "sharbert", "fornax"}

var appHandler http.Handler = http.FileServer(http.Dir("."))
var assetsHandler http.Handler = http.FileServer(http.Dir("."))

// var adminHandler http.Handler = http.FileServer(http.Dir("./admin"))

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits++
		// fmt.Printf("Hits incremented. Current count: %d\n", cfg.fileserverHits)
		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) adminHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "<html>\n</html>\n<body>\n<h1>Welcome, Chirpy Admin</h1>\n<p>Chirpy has been visited %d times!</p>\n</body>\n</html>", cfg.fileserverHits)
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

func validateChirp(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	type chirpStruct struct {
		Body string `json:"body"`
	}

	chirp := chirpStruct{}
	if err := json.NewDecoder(r.Body).Decode(&chirp); err != nil {
		respondWithError(w, 500, "Could not decode request body")
	}

	chCount := len(chirp.Body)
	if chCount > 140 {
		respondWithError(w, 400, fmt.Sprintf("Chirp is too long (exceeds limit by %d characters)", chCount-140))
	} else {
		words := strings.Fields(chirp.Body)
		for i, word := range words {
			for _, pWord := range ProfaneWords {
				if strings.ToLower(word) == pWord {
					words[i] = "****"
				}
			}
		}
		joinedWords := strings.Join(words, " ")

		if err := respondWithJSON(w, 200, map[string]string{"cleaned_body": joinedWords}); err != nil {
			respondWithError(w, 500, "Could not clean the chirp")
		}
	}

}

func respondWithJSON(w http.ResponseWriter, statusCode int, payload interface{}) error {
	respJSON, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(statusCode)
	w.Write(respJSON)

	return nil
}

func respondWithError(w http.ResponseWriter, statusCode int, msg string) error {
	return respondWithJSON(w, statusCode, map[string]string{"error": msg})
}

func main() {
	apiCfg := apiConfig{
		fileserverHits: 0,
	}

	mux := http.NewServeMux()

	mux.Handle("/app/", http.StripPrefix("/app", apiCfg.middlewareMetricsInc(appHandler)))
	mux.Handle("/admin/", http.HandlerFunc(apiCfg.adminHandler))
	mux.Handle("/assets/", assetsHandler)
	mux.HandleFunc("GET /api/healthz", healthzFunc)
	mux.HandleFunc("GET /api/metrics", apiCfg.serverHitsHandler)
	mux.Handle("POST /admin/reset", http.HandlerFunc(apiCfg.resetHitsHandler))
	mux.Handle("POST /api/validate_chirp", http.HandlerFunc(validateChirp))

	server := &http.Server{
		Addr:    "localhost:8080",
		Handler: mux,
	}

	if err := server.ListenAndServe(); err != nil {
		fmt.Printf("error listening and serving - %v", err)
	}

}
