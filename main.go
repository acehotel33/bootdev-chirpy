package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/acehotel33/bootdev-chirpy/internal/auth"
	"github.com/acehotel33/bootdev-chirpy/internal/database"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type apiConfig struct {
	fileserverHits int
	dbQueries      *database.Queries
	platform       string
	secret         string
}

type UserCreate struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Email     string    `json:"email"`
}

type UserLogin struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Email     string    `json:"email"`
	Token     string    `json:"token"`
}

type Chirp struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Body      string    `json:"body"`
	UserID    uuid.UUID `json:"user_id"`
}

var ProfaneWords = []string{"kerfuffle", "sharbert", "fornax"}

var (
	appHandler    http.Handler = http.FileServer(http.Dir("."))
	assetsHandler http.Handler = http.FileServer(http.Dir("."))
)

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
		return
	}
	cfg.dbQueries.ResetUsers(r.Context())
	respondWithJSON(w, 200, "Users DB has been reset")
}

func (cfg *apiConfig) resetChirpsHandler(w http.ResponseWriter, r *http.Request) {
	if cfg.platform != "dev" {
		respondWithError(w, 403, "Forbidden request")
		return
	}
	cfg.dbQueries.ResetChirps(r.Context())
	respondWithJSON(w, 200, "Chirps DB has been reset")
}

func (cfg *apiConfig) createUsersHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	log.Printf("entered createUsersHandler")

	type reqStruct struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	newReq := reqStruct{}
	if err := json.NewDecoder(r.Body).Decode(&newReq); err != nil {
		respondWithError(w, 500, fmt.Sprintf("could not decode request body: %s", err))
		return
	}
	hashedPassword, err := auth.HashPassword(newReq.Password)
	if err != nil {
		respondWithError(w, 501, fmt.Sprintf("could not hash password: %v", err.Error()))
		return
	}

	userParams := database.CreateUserParams{
		Email:          newReq.Email,
		HashedPassword: hashedPassword,
	}
	user, err := cfg.dbQueries.CreateUser(r.Context(), userParams)
	if err != nil {
		respondWithError(w, 500, fmt.Sprintf("could not create user: %s", err))
		return
	}

	User := UserCreate{
		ID:        user.ID,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
		Email:     user.Email,
	}

	if err := respondWithJSON(w, 201, User); err != nil {
		respondWithError(w, 500, fmt.Sprintf("could not respond with user: %s", err))
		return
	}
}

func (cfg *apiConfig) userLoginHandler(w http.ResponseWriter, r *http.Request) {
	type reqStruct struct {
		ExpiresInSeconds *int   `json:"expires_in_seconds,omitempty"`
		Email            string `json:"email"`
		Password         string `json:"password"`
	}

	req, err := io.ReadAll(r.Body)
	if err != nil {
		respondWithError(w, 501, fmt.Sprintf("could not read request body: %s", err.Error()))
		return
	}
	defer r.Body.Close()

	userLoginParams := &reqStruct{}
	if err := json.Unmarshal(req, userLoginParams); err != nil {
		respondWithError(w, 501, fmt.Sprintf("could not unmarshal request body: %s", err.Error()))
		return
	}

	retrievedUser, err := cfg.dbQueries.GetUserByEmail(r.Context(), userLoginParams.Email)
	if err != nil {
		respondWithError(w, 401, "Incorrect email or password")
		return
	}

	if err := auth.CheckPasswordHash(userLoginParams.Password, retrievedUser.HashedPassword); err != nil {
		respondWithError(w, 401, "Incorrect email or password")
		return
	}

	if userLoginParams.ExpiresInSeconds == nil || *userLoginParams.ExpiresInSeconds > 3600 {
		expiresInSeconds := 3600
		userLoginParams.ExpiresInSeconds = &expiresInSeconds
	}

	log.Printf("\nexpires in after: %v\n", *userLoginParams.ExpiresInSeconds)

	secretToken, err := auth.MakeJWT(retrievedUser.ID, cfg.secret, time.Second*time.Duration(*userLoginParams.ExpiresInSeconds))
	if err != nil {
		respondWithError(w, 401, "Unauthorized")
		return
	}

	retrievedUserClean := UserLogin{
		ID:        retrievedUser.ID,
		CreatedAt: retrievedUser.CreatedAt,
		UpdatedAt: retrievedUser.UpdatedAt,
		Email:     retrievedUser.Email,
		Token:     secretToken,
	}

	respondWithJSON(w, 200, retrievedUserClean)
}

func (cfg *apiConfig) createChirpHandler(w http.ResponseWriter, r *http.Request) {
	bearer, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, 401, "Unauthorized")
		return
	}

	tokenUserID, err := auth.ValidateJWT(bearer, cfg.secret)
	if err != nil {
		respondWithError(w, 401, "Unauthorized")
		return
	}

	req, err := io.ReadAll(r.Body)
	if err != nil {
		respondWithError(w, 500, fmt.Sprintf("could not read request body: %s", err))
		return
	}
	defer r.Body.Close()

	// Define and parse the chirp request
	type ChirpRequest struct {
		Body string `json:"body"`
	}

	chirpRequest := ChirpRequest{}
	if err := json.Unmarshal(req, &chirpRequest); err != nil {
		respondWithError(w, 500, fmt.Sprintf("failed to parse JSON: %s", err))
		return
	}

	// Validate the chirp body
	body, err := validateChirp(chirpRequest.Body)
	if err != nil {
		respondWithError(w, 401, err.Error())
		return
	}

	// Prepare chirp parameters and create chirp in the database
	chirpParams := database.CreateChirpParams{
		Body:   body,
		UserID: uuid.NullUUID{UUID: tokenUserID, Valid: true},
	}

	chirpDB, err := cfg.dbQueries.CreateChirp(r.Context(), chirpParams)
	if err != nil {
		respondWithError(w, 500, fmt.Sprintf("could not create chirp: %s", err))
		return
	}

	// Respond with the created chirp
	chirpAPI := Chirp{
		ID:        chirpDB.ID,
		CreatedAt: chirpDB.CreatedAt,
		UpdatedAt: chirpDB.UpdatedAt,
		Body:      chirpDB.Body,
		UserID:    chirpDB.UserID.UUID,
	}
	respondWithJSON(w, 201, chirpAPI)
}

func (cfg *apiConfig) getAllChirpsHandler(w http.ResponseWriter, r *http.Request) {
	chirpsSpliceDB, err := cfg.dbQueries.GetAllChirps(r.Context())
	if err != nil {
		respondWithError(w, 500, err.Error())
		return
	}
	chirpsSpliceAPI := []Chirp{}
	for _, chirp := range chirpsSpliceDB {
		chirpsSpliceAPI = append(chirpsSpliceAPI, Chirp{
			ID:        chirp.ID,
			CreatedAt: chirp.CreatedAt,
			UpdatedAt: chirp.UpdatedAt,
			Body:      chirp.Body,
			UserID:    chirp.UserID.UUID,
		})
	}
	respondWithJSON(w, 200, chirpsSpliceAPI)
}

func (cfg *apiConfig) getChirpHandler(w http.ResponseWriter, r *http.Request) {
	chirpID := r.PathValue("chirpID")
	chirpUUID, err := uuid.Parse(chirpID)
	if err != nil {
		respondWithError(w, 500, err.Error())
		return
	}
	chirpDB, err := cfg.dbQueries.GetChirp(r.Context(), chirpUUID)
	if err != nil {
		respondWithError(w, 500, err.Error())
		return
	}
	chirpAPI := Chirp{
		ID:        chirpDB.ID,
		CreatedAt: chirpDB.CreatedAt,
		UpdatedAt: chirpDB.UpdatedAt,
		Body:      chirpDB.Body,
		UserID:    chirpDB.UserID.UUID,
	}
	respondWithJSON(w, 200, chirpAPI)
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

func initiateServer(dbURL, platform, secret string) {
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		fmt.Printf("Could not initiate db: %s", err)
	}
	dbQueries := database.New(db)

	apiCfg := apiConfig{
		fileserverHits: 0,
		dbQueries:      dbQueries,
		platform:       platform,
		secret:         secret,
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

	mux.Handle("POST /api/users", http.HandlerFunc(apiCfg.createUsersHandler))
	mux.Handle("POST /api/login", http.HandlerFunc(apiCfg.userLoginHandler))
	mux.Handle("POST /api/chirps", http.HandlerFunc(apiCfg.createChirpHandler))

	mux.Handle("GET /api/chirps", http.HandlerFunc(apiCfg.getAllChirpsHandler))
	mux.Handle("GET /api/chirps/{chirpID}", http.HandlerFunc(apiCfg.getChirpHandler))

	mux.Handle("GET /assets/", assetsHandler)

	server := &http.Server{
		Addr:    "localhost:8080",
		Handler: mux,
	}

	if err := server.ListenAndServe(); err != nil {
		fmt.Printf("error listening and serving - %v", err)
	}
}

func main() {
	godotenv.Load()
	dbURL := os.Getenv("DB_URL")
	platform := os.Getenv("PLATFORM")
	secret := os.Getenv("SECRET")
	initiateServer(dbURL, platform, secret)
}
