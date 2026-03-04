package utils

const (
	UserIDKey    = "user_id"
	SessionIDKey = "session_id"
)

type ErrorResponse struct {
	Error string `json:"error"`
}
