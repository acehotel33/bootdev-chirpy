package auth

import (
	"testing"
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
