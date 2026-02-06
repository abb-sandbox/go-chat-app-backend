package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/AzimBB/go-chat-app-backend/internal/config"
	"github.com/jackc/pgx/v5/pgxpool"
)

func NewPool(cfg config.Config) (*pgxpool.Pool, error) {
	if cfg.PG_URL == "" {
		return nil, fmt.Errorf("no postgres dsn provided")
	}

	// 1. Parse the config string into a Config struct
	poolConfig, err := pgxpool.ParseConfig(cfg.PG_URL)
	if err != nil {
		return nil, fmt.Errorf("unable to parse DATABASE_URL: %w", err)
	}

	// 2. Set sensible defaults
	poolConfig.MaxConns = 10
	poolConfig.MinConns = 2
	poolConfig.MaxConnLifetime = time.Hour

	// 3. Create the pool
	pool, err := pgxpool.NewWithConfig(context.Background(), poolConfig)
	if err != nil {
		return nil, err
	}

	// 4. ACTIVE PING WITH RETRY (The missing piece)
	maxRetries := 5
	for i := 0; i < maxRetries; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err = pool.Ping(ctx)
		cancel()

		if err == nil {
			return pool, nil // Success!
		}

		time.Sleep(2 * time.Second)
	}

	return nil, fmt.Errorf("postgres unreachable after %d attempts: %w", maxRetries, err)
}
