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
	ID           uuid.UUID `json:"id"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	Email        string    `json:"email"`
	Token        string    `json:"token"`
	RefreshToken string    `json:"refresh_token"`
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

func (cfg *apiConfig) createUserHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

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

func (cfg *apiConfig) updateUserHandler(w http.ResponseWriter, r *http.Request) {
	accessToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, 401, "Unauthorized")
		return
	}
	userID, err := auth.ValidateJWT(accessToken, cfg.secret)
	if err != nil {
		respondWithError(w, 401, "Unauthorized")
		return
	}

	type reqStruct struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	req, err := io.ReadAll(r.Body)
	if err != nil {
		respondWithError(w, 501, "Could not read request body")
		return
	}
	defer r.Body.Close()

	reqBody := &reqStruct{}
	if err := json.Unmarshal(req, reqBody); err != nil {
		respondWithError(w, 501, "Could not read request body")
		return
	}

	email := reqBody.Email
	password := reqBody.Password
	hashedPassword, err := auth.HashPassword(password)
	if err != nil {
		respondWithError(w, 401, "Invalid password")
	}

	updatePasswordParams := database.UpdateUserPasswordParams{
		ID:             userID,
		Email:          email,
		HashedPassword: hashedPassword,
	}
	userDB, err := cfg.dbQueries.UpdateUserPassword(r.Context(), updatePasswordParams)
	if err != nil {
		respondWithError(w, 501, "Could not update password")
	}

	resp := UserCreate{
		ID:        userDB.ID,
		CreatedAt: userDB.CreatedAt,
		UpdatedAt: userDB.UpdatedAt,
		Email:     userDB.Email,
	}

	respondWithJSON(w, 200, resp)
}

func (cfg *apiConfig) userLoginHandler(w http.ResponseWriter, r *http.Request) {
	type reqStruct struct {
		Email    string `json:"email"`
		Password string `json:"password"`
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

	secretToken, err := auth.MakeJWT(retrievedUser.ID, cfg.secret)
	if err != nil {
		respondWithError(w, 401, "Unauthorized")
		return
	}

	refreshToken, err := auth.MakeRefreshToken()
	if err != nil {
		respondWithError(w, 401, "Could not generate refresh token")
		return
	}

	refreshTokenParameters := database.AssignRefreshTokenToUserParams{
		Token:  refreshToken,
		UserID: uuid.NullUUID{UUID: retrievedUser.ID, Valid: true},
	}

	_, err = cfg.dbQueries.AssignRefreshTokenToUser(r.Context(), refreshTokenParameters)
	if err != nil {
		respondWithError(w, 401, "Could not assign refresh token")
		return
	}

	retrievedUserClean := UserLogin{
		ID:           retrievedUser.ID,
		CreatedAt:    retrievedUser.CreatedAt,
		UpdatedAt:    retrievedUser.UpdatedAt,
		Email:        retrievedUser.Email,
		Token:        secretToken,
		RefreshToken: refreshToken,
	}

	respondWithJSON(w, 200, retrievedUserClean)
}

func (cfg *apiConfig) refreshHandler(w http.ResponseWriter, r *http.Request) {
	refreshToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, 401, "Unauthorized")
		return
	}

	refreshTokenDB, err := cfg.dbQueries.GetRefreshToken(r.Context(), refreshToken)
	if err != nil {
		respondWithError(w, 401, "Unauthorized")
		return
	}
	if refreshTokenDB.RevokedAt.Valid {
		respondWithError(w, 401, "Unauthorized")
		return
	}

	userID, err := cfg.dbQueries.GetUserIDFromRefreshToken(r.Context(), refreshToken)
	if err != nil {
		respondWithError(w, 401, "Unauthorized")
		return
	}

	accessToken, err := auth.MakeJWT(userID, cfg.secret)
	if err != nil {
		respondWithError(w, 401, "Unauthorized")
		return
	}

	type respStruct struct {
		Token string `json:"token"`
	}
	resp := respStruct{
		Token: accessToken,
	}

	respondWithJSON(w, 200, resp)
}

func (cfg *apiConfig) revokeHandler(w http.ResponseWriter, r *http.Request) {
	refreshToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, 401, "Unauthorized")
		return
	}

	_, err = cfg.dbQueries.RevokeRefreshToken(r.Context(), refreshToken)
	if err != nil {
		respondWithError(w, 401, "Unauthorized")
		return
	}

	respondWithJSON(w, 204, "")
}

func (cfg *apiConfig) createChirpHandler(w http.ResponseWriter, r *http.Request) {
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, 401, "Unauthorized")
		return
	}

	tokenUserID, err := auth.ValidateJWT(token, cfg.secret)
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

	mux.Handle("POST /api/users", http.HandlerFunc(apiCfg.createUserHandler))
	mux.Handle("POST /api/login", http.HandlerFunc(apiCfg.userLoginHandler))
	mux.Handle("POST /api/chirps", http.HandlerFunc(apiCfg.createChirpHandler))
	mux.Handle("PUT /api/users", http.HandlerFunc(apiCfg.updateUserHandler))

	mux.Handle("POST /api/refresh", http.HandlerFunc(apiCfg.refreshHandler))
	mux.Handle("POST /api/revoke", http.HandlerFunc(apiCfg.revokeHandler))

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
