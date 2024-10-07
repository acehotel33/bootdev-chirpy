package auth

import (
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestHashPassword(t *testing.T) {
	password := "mySecurePassword"
	hash, err := HashPassword(password)
	if err != nil {
		t.Errorf("Error hashing password: %v", err)
	}

	// Ensure the hash is not equal to the original password
	if hash == password {
		t.Errorf("Hashed password should not equal the original password")
	}

	// Ensure the hash is of non-zero length
	if len(hash) == 0 {
		t.Errorf("Hashed password should not be empty")
	}

	// Hash the same password again to ensure bcrypt produces different hashes
	secondHash, err := HashPassword(password)
	if err != nil {
		t.Errorf("Expected no error when hashing second time, got %v", err)
	}

	// Hashes should be different because bcrypt adds salt
	if hash == secondHash {
		t.Error("Expected different hashes for the same password due to salting, got the same")
	}
}

func TestCheckPasswordHash(t *testing.T) {
	password := "supersecret"

	// Generate a hashed password
	hashedPassword, err := HashPassword(password)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	// Test that the correct password returns no error
	err = CheckPasswordHash(password, hashedPassword)
	if err != nil {
		t.Errorf("Expected no error for correct password, got %v", err)
	}

	// Test that an incorrect password returns an error
	wrongPassword := "wrongpassword"
	err = CheckPasswordHash(wrongPassword, hashedPassword)
	if err == nil {
		t.Error("Expected error for incorrect password, got none")
	}
}

func TestMakeValidateJWT(t *testing.T) {
	userID, err := uuid.NewRandom()
	if err != nil {
		t.Fatalf("Failed to create random UUID: %v", err)
	}

	expiry := time.Hour

	tokenString, err := MakeJWT(userID, "bootdev", expiry)
	if err != nil {
		t.Errorf("Expected no error for MakeJWT: %v", err)
	}
	uID, err := ValidateJWT(tokenString, "bootdev")
	if err != nil {
		t.Errorf("Expected no error for ValidateJWT: %v", err)
	}
	if userID != uID {
		t.Errorf("Expected userID to match: %v", err)
	}
}

func TestGetBearerToken(t *testing.T) {
	tests := []struct {
		name       string
		headers    http.Header
		expected   string
		shouldFail bool
	}{
		{
			name: "Valid Bearer token",
			headers: http.Header{
				"Authorization": {"Bearer validtoken123"},
			},
			expected:   "validtoken123",
			shouldFail: false,
		},
		{
			name:       "Missing Authorization header",
			headers:    http.Header{},
			expected:   "",
			shouldFail: true,
		},
		{
			name: "Invalid Bearer format",
			headers: http.Header{
				"Authorization": {"InvalidBearer"},
			},
			expected:   "",
			shouldFail: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			token, err := GetBearerToken(test.headers)
			if (err != nil) != test.shouldFail {
				t.Errorf("expected failure: %v, got error: %v", test.shouldFail, err)
			}
			if token != test.expected {
				t.Errorf("expected token %v, got %v", test.expected, token)
			}
		})
	}
}
