package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/AzimBB/go-chat-app-backend/internal/config"
	"github.com/AzimBB/go-chat-app-backend/internal/domain/adapters"
	"github.com/AzimBB/go-chat-app-backend/internal/domain/entities"
	redislib "github.com/redis/go-redis/v9"
)

// Package-level, reusable errors
var (
	ErrCacheMiss        = errors.New("cache miss")
	ErrSessionExpired   = errors.New("session already expired")
	ErrInvalidRedisDB   = errors.New("invalid redis db index")
	defaultDialTimeout  = 5 * time.Second
	defaultReadTimeout  = 3 * time.Second
	defaultWriteTimeout = 3 * time.Second
)

type RedisCache struct {
	client *redislib.Client
}

// NewRedisClient creates and validates a Redis client with exponential backoff retries.
func NewRedisClient(cfg config.Config) (*redislib.Client, error) {
	if cfg.REDIS_URL == "" {
		return nil, errors.New("redis address is empty")
	}

	opt, err := redislib.ParseURL(cfg.REDIS_URL)
	if err != nil {
		return nil, err
	}

	client := redislib.NewClient(opt)

	// --- Retry Logic Start ---
	maxRetries := 5
	initialDelay := 1 * time.Second

	var lastErr error
	for i := 0; i < maxRetries; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)

		lastErr = client.Ping(ctx).Err()
		cancel() // Cancel context immediately after Ping

		if lastErr == nil {
			return client, nil
		}

		// Exponential backoff: 1s, 2s, 4s, 8s...
		wait := initialDelay * time.Duration(1<<i)

		time.Sleep(wait)
	}
	// --- Retry Logic End ---

	_ = client.Close()
	return nil, fmt.Errorf("could not connect to Redis after %d attempts: %w", maxRetries, lastErr)
}

func NewCache(client *redislib.Client) adapters.Cache {
	return &RedisCache{client: client}
}

// SaveUserInCache stores a user with a TTL.
func (r *RedisCache) SaveUserInCache(ctx context.Context, key string, user entities.User, duration time.Duration) error {
	if key == "" {
		return errors.New("empty cache key")
	}
	if duration <= 0 {
		return errors.New("invalid ttl")
	}

	b, err := json.Marshal(user)
	if err != nil {
		return fmt.Errorf("marshal user: %w", err)
	}

	return r.client.Set(ctx, key, b, duration).Err()
}

// GetUserFromCache returns ErrCacheMiss if the key does not exist.
func (r *RedisCache) GetUserFromCache(ctx context.Context, key string) (entities.User, error) {
	if key == "" {
		return entities.User{}, errors.New("empty cache key")
	}

	v, err := r.client.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redislib.Nil) {
			return entities.User{}, ErrCacheMiss
		}
		return entities.User{}, err
	}

	var user entities.User
	if err := json.Unmarshal([]byte(v), &user); err != nil {
		return entities.User{}, fmt.Errorf("unmarshal user: %w", err)
	}

	return user, nil
}

func (r *RedisCache) RemoveFromCacheByKey(ctx context.Context, key string) error {
	if key == "" {
		return errors.New("empty cache key")
	}
	return r.client.Del(ctx, key).Err()
}

// SaveSession stores a session until its expiration time.
func (r *RedisCache) SaveSession(ctx context.Context, session entities.Session) error {
	if session.ID == "" {
		return errors.New("empty session id")
	}

	ttl := time.Until(session.ExpiresAt)
	if ttl <= 0 {
		return ErrSessionExpired
	}

	b, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("marshal session: %w", err)
	}

	return r.client.Set(ctx, session.ID, b, ttl).Err()
}

// GetSessionByID returns ErrCacheMiss if the session does not exist.
func (r *RedisCache) GetSessionByID(ctx context.Context, id string) (entities.Session, error) {
	if id == "" {
		return entities.Session{}, errors.New("empty session id")
	}

	v, err := r.client.Get(ctx, id).Result()
	if err != nil {
		if errors.Is(err, redislib.Nil) {
			return entities.Session{}, ErrCacheMiss
		}
		return entities.Session{}, err
	}

	var session entities.Session
	if err := json.Unmarshal([]byte(v), &session); err != nil {
		return entities.Session{}, fmt.Errorf("unmarshal session: %w", err)
	}

	return session, nil
}

func (r *RedisCache) RemoveSessionByID(ctx context.Context, id string) error {
	if id == "" {
		return errors.New("empty session id")
	}
	return r.client.Del(ctx, id).Err()
}
