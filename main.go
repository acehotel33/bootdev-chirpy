package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/acehotel33/bootdev-chirpy/internal/database"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type apiConfig struct {
	fileserverHits int
	dbQueries      *database.Queries
	platform       string
}

type User struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Email     string    `json:"email"`
}

type ChirpStruct struct {
	Body   string    `json:"body"`
	UserID uuid.UUID `json:"user_id"`
}

var ProfaneWords = []string{"kerfuffle", "sharbert", "fornax"}

var appHandler http.Handler = http.FileServer(http.Dir("."))
var assetsHandler http.Handler = http.FileServer(http.Dir("."))

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits++
		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) adminHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "<html>\n</html>\n<body>\n<h1>Welcome, Chirpy Admin</h1>\n<p>Chirpy has been visited %d times!</p>\n</body>\n</html>", cfg.fileserverHits)
}

func (cfg *apiConfig) serverHitsHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hits: %d", cfg.fileserverHits)
}

func (cfg *apiConfig) resetHitsHandler(w http.ResponseWriter, r *http.Request) {
	cfg.fileserverHits = 0
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Hits counter reset to %d", cfg.fileserverHits)
}

func (cfg *apiConfig) resetUsersHandler(w http.ResponseWriter, r *http.Request) {
	if cfg.platform != "dev" {
		respondWithError(w, 403, "Forbidden request")
	} else {
		cfg.dbQueries.ResetUsers(r.Context())
		respondWithJSON(w, 200, "Users DB has been reset")
	}
}

func (cfg *apiConfig) resetChirpsHandler(w http.ResponseWriter, r *http.Request) {
	if cfg.platform != "dev" {
		respondWithError(w, 403, "Forbidden request")
	} else {
		cfg.dbQueries.ResetChirps(r.Context())
		respondWithJSON(w, 200, "Chirps DB has been reset")
	}
}

func (cfg *apiConfig) createUsers(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	type emailStruct struct {
		Email string `json:"email"`
	}

	newEmail := emailStruct{}
	if err := json.NewDecoder(r.Body).Decode(&newEmail); err != nil {
		respondWithError(w, 500, fmt.Sprintf("could not decode request body: %s", err))
	}

	user, err := cfg.dbQueries.CreateUser(r.Context(), newEmail.Email)
	if err != nil {
		respondWithError(w, 500, fmt.Sprintf("could not create user: %s", err))
	}

	User := User{
		ID:        user.ID,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
		Email:     user.Email,
	}

	if err := respondWithJSON(w, 201, User); err != nil {
		respondWithError(w, 500, fmt.Sprintf("could not respond with user: %s", err))
	}

}

func (cfg *apiConfig) createChirpHandler(w http.ResponseWriter, r *http.Request) {
	type chirpJSON struct {
		Body   string `json:"body"`
		UserID string `json:"user_id"`
	}

	req, err := io.ReadAll(r.Body)
	if err != nil {
		respondWithError(w, 500, fmt.Sprintf("could not read request body: %s", err))
	} else {
		defer r.Body.Close()

		chirpData := chirpJSON{}
		if err := json.Unmarshal(req, &chirpData); err != nil {
			respondWithError(w, 500, fmt.Sprintf("failed to parse JSON: %s", err))
		} else {
			body, err := validateChirp(chirpData.Body)
			if err != nil {
				respondWithError(w, 401, err.Error())
			} else {
				userID, err := uuid.Parse(chirpData.UserID)
				if err != nil {
					respondWithError(w, 401, fmt.Sprintf("invalid user_id: %v", err))
				} else {
					chirpData = chirpJSON{
						Body:   body,
						UserID: userID.String(),
					}

					chirpParams := database.CreateChirpParams{
						Body:   chirpData.Body,
						UserID: uuid.NullUUID{UUID: userID, Valid: true},
					}

					_, err := cfg.dbQueries.CreateChirp(r.Context(), chirpParams)
					if err != nil {
						respondWithError(w, 500, fmt.Sprintf("could not create chirp: %s", err))
					} else {
						respondWithJSON(w, 201, chirpData)
					}
				}
			}
		}
	}
}

func healthzFunc(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func validateChirp(body string) (string, error) {
	chCount := len(body)
	if chCount > 140 {
		return "", fmt.Errorf("chirp is too long (exceeds limit by %d characters)", chCount-140)
	} else {
		return body, nil
	}
}

func profanityReplacer(text string) string {
	words := strings.Fields(text)
	for i, word := range words {
		for _, pWord := range ProfaneWords {
			if strings.ToLower(word) == pWord {
				words[i] = "****"
			}
		}
	}
	return strings.Join(words, " ")
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
	godotenv.Load()
	dbURL := os.Getenv("DB_URL")
	platform := os.Getenv("PLATFORM")

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		fmt.Printf("Could not initiate db: %s", err)
	}
	dbQueries := database.New(db)

	apiCfg := apiConfig{
		fileserverHits: 0,
		dbQueries:      dbQueries,
		platform:       platform,
	}

	mux := http.NewServeMux()

	mux.Handle("GET /app/", http.StripPrefix("/app", apiCfg.middlewareMetricsInc(appHandler)))

	mux.Handle("GET /admin/", http.StripPrefix("/admin", http.HandlerFunc(apiCfg.adminHandler)))
	mux.Handle("POST /admin/reset", http.StripPrefix("/admin", http.HandlerFunc(apiCfg.resetUsersHandler)))
	mux.Handle("POST /admin/resetUsers", http.StripPrefix("/admin", http.HandlerFunc(apiCfg.resetUsersHandler)))
	mux.Handle("POST /admin/resetChirps", http.StripPrefix("/admin", http.HandlerFunc(apiCfg.resetChirpsHandler)))
	mux.Handle("POST /admin/resetHits", http.StripPrefix("/admin", http.HandlerFunc(apiCfg.resetHitsHandler)))

	mux.HandleFunc("GET /api/healthz", healthzFunc)
	mux.HandleFunc("GET /api/metrics", apiCfg.serverHitsHandler)
	mux.Handle("POST /api/users", http.HandlerFunc(apiCfg.createUsers))
	mux.Handle("POST /api/chirps", http.HandlerFunc(apiCfg.createChirpHandler))

	mux.Handle("GET /assets/", assetsHandler)

	server := &http.Server{
		Addr:    "localhost:8080",
		Handler: mux,
	}

	if err := server.ListenAndServe(); err != nil {
		fmt.Printf("error listening and serving - %v", err)
	}

}
