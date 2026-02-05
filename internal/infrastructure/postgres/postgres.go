package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/AzimBB/go-chat-app-backend/internal/config"
	"github.com/jackc/pgx/v5/pgxpool"
)

// NewPool constructs a pgxpool.Pool to be used by repositories.
func NewPool(cfg config.Config) (*pgxpool.Pool, error) {
	if cfg.PG_URL == "" {
		return nil, fmt.Errorf("no postgres dsn provided")
	}
	pool, err := pgxpool.New(context.Background(), cfg.PG_URL)
	if err != nil {
		return nil, err
	}
	// Set sensible defaults; these can be replaced by config in future
	pool.Config().MaxConns = 10
	pool.Config().MinConns = 1
	pool.Config().MaxConnLifetime = time.Hour
	return pool, nil
}
