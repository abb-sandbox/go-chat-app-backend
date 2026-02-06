package config

import (
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	// gin framework (debug or release)
	GIN_MODE string

	// For Zap logger (true or false) bool
	DEV     bool
	LOG_LVL string

	// Postgres DB
	PG_URL string

	// Redis memory storage
	REDIS_URL string

	// JWTService for stateful JWT Auth Service
	JWT_SECRET string
	JWT_SHORT  time.Duration // Access token expiry (e.g., 15m)
	JWT_LONG   time.Duration // Refresh token/Session expiry (e.g., 24h)

	// MinIO blob storage
	MINIO_ROOT_USER     string
	MINIO_ROOT_PASSWORD string
	MINIO_ENDPOINT      string
	MINIO_USE_SSL       bool

	// UserAuthService
	ACT_EXP time.Duration // How much time keep activation link active
}

func GetConfig() Config {
	if value := os.Getenv("CLOUD"); value == "false" {
		_ = godotenv.Load()
	}
	return Config{
		// --- Application/Framework Settings ---
		GIN_MODE: GetStringEnv("GIN_MODE", "debug"),

		// --- Logger Settings ---
		DEV:     GetBoolEnv("DEV", true),
		LOG_LVL: GetStringEnv("LOG_LVL", "info"),

		// --- Postgres DB ---
		PG_URL: GetStringEnv("PG_URL", ""),

		// --- Redis memory storage ---
		REDIS_URL: GetStringEnv("REDIS_URL", ""),

		// --- JWT Service ---
		JWT_SECRET: GetStringEnv("JWT_SECRET", "super-strong-default-secret-CHANGE-ME!"),
		JWT_SHORT:  getEnvAsDuration("JWT_SHORT", 15*time.Minute),
		JWT_LONG:   getEnvAsDuration("JWT_LONG", 30*24*time.Hour),

		// --- MinIO blob storage ---
		MINIO_ROOT_USER:     GetStringEnv("MINIO_ROOT_USER", "minioadmin"),
		MINIO_ROOT_PASSWORD: GetStringEnv("MINIO_ROOT_PASSWORD", "minioadminpassword"),
		MINIO_ENDPOINT:      GetStringEnv("MINIO_ENDPOINT", "localhost:9000"),
		MINIO_USE_SSL:       GetBoolEnv("MINIO_USE_SSL", false),

		// For AuthHandler
		ACT_EXP: getEnvAsDuration("ACT_EXP", time.Minute*5),
	}
}

// --- Helper Functions ---

// GetStringEnv gets environment variable 'key' or returns 'defaultValue'.
// Note: This is now the primary String getter, using os.Getenv(key) directly.
func GetStringEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

// GetBoolEnv gets environment variable 'key' as a boolean.
func GetBoolEnv(key string, defaultValue bool) bool {
	value := os.Getenv(key)
	switch value {
	case "true", "1", "t":
		return true
	case "false", "0", "f":
		return false
	}
	return defaultValue
}

// Helper function to get an environment variable as a time.Duration.
func getEnvAsDuration(key string, defaultValue time.Duration) time.Duration {
	// Note: This helper uses os.LookupEnv internally, as it's cleaner for type conversion helpers
	if valueStr, exists := os.LookupEnv(key); exists {
		if value, err := time.ParseDuration(valueStr); err == nil {
			return value
		}
	}
	return defaultValue
}

// Helper function to get an environment variable as an integer.
// (Retained for completeness, though not currently used by the Config struct)
func getEnvAsInt(key string, defaultValue int) int {
	if valueStr, exists := os.LookupEnv(key); exists {
		if value, err := strconv.Atoi(valueStr); err == nil {
			return value
		}
	}
	return defaultValue
}
