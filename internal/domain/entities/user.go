package entities

import (
	"errors"

	"golang.org/x/crypto/bcrypt"
)

// User is the base entity for the user in app
type User struct {
	ID           string
	Email        string
	PasswordHash []byte
}

func NewUser(email, password string) (User, error) {
	if email == "" || password == "" {
		return User{}, emptyFields
	}
	if len(password) < 8 {
		return User{}, insecurePassword
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	return User{
		Email:        email,
		PasswordHash: passwordHash,
	}, err
}

var (
	insecurePassword = errors.New("insecure password")
	emptyFields      = errors.New("empty fields")
)
