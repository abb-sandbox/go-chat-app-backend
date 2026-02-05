package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/AzimBB/go-chat-app-backend/internal/config"
	"github.com/AzimBB/go-chat-app-backend/internal/domain/adapters"
	"github.com/AzimBB/go-chat-app-backend/internal/domain/entity"
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

// NewRedisClient creates and validates a Redis client with sane defaults.
func NewRedisClient(cfg config.Config) (*redislib.Client, error) {
	if cfg.REDIS_URL == "" {
		return nil, errors.New("redis address is empty")
	}

	opt, err := redislib.ParseURL(cfg.REDIS_URL)
	if err != nil {
		return nil, err
	}

	client := redislib.NewClient(opt)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, err
	}

	return client, nil
}

func NewCache(client *redislib.Client) adapters.Cache {
	return &RedisCache{client: client}
}

// SaveUserInCache stores a user with a TTL.
func (r *RedisCache) SaveUserInCache(ctx context.Context, key string, user entity.User, duration time.Duration) error {
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
func (r *RedisCache) GetUserFromCache(ctx context.Context, key string) (entity.User, error) {
	if key == "" {
		return entity.User{}, errors.New("empty cache key")
	}

	v, err := r.client.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redislib.Nil) {
			return entity.User{}, ErrCacheMiss
		}
		return entity.User{}, err
	}

	var user entity.User
	if err := json.Unmarshal([]byte(v), &user); err != nil {
		return entity.User{}, fmt.Errorf("unmarshal user: %w", err)
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
func (r *RedisCache) SaveSession(ctx context.Context, session entity.Session) error {
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
func (r *RedisCache) GetSessionByID(ctx context.Context, id string) (entity.Session, error) {
	if id == "" {
		return entity.Session{}, errors.New("empty session id")
	}

	v, err := r.client.Get(ctx, id).Result()
	if err != nil {
		if errors.Is(err, redislib.Nil) {
			return entity.Session{}, ErrCacheMiss
		}
		return entity.Session{}, err
	}

	var session entity.Session
	if err := json.Unmarshal([]byte(v), &session); err != nil {
		return entity.Session{}, fmt.Errorf("unmarshal session: %w", err)
	}

	return session, nil
}

func (r *RedisCache) RemoveSessionByID(ctx context.Context, id string) error {
	if id == "" {
		return errors.New("empty session id")
	}
	return r.client.Del(ctx, id).Err()
}
