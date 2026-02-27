package utils

import "github.com/gin-gonic/gin"

// --- Gin Helpers (Idiomatic Naming) ---

// GetFromContextAsString retrieves the item as string from the Gin context.
func GetFromContextAsString(c *gin.Context, key string) (string, bool) {
	v, ok := c.Get(key)
	if !ok {
		return "", false
	}
	id, ok := v.(string)
	return id, ok
}
