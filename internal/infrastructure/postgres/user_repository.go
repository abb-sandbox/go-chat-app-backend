package postgres

import (
	"context"
	stdsql "database/sql"
	"errors"
	"time"

	"github.com/AzimBB/go-chat-app-backend/internal/domain/entities"
	app_errors "github.com/AzimBB/go-chat-app-backend/internal/domain/errors"
	sq "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

type PostgresUserRepository struct {
	pool *pgxpool.Pool
}

func NewUserRepository(pool *pgxpool.Pool) *PostgresUserRepository {
	return &PostgresUserRepository{pool: pool}
}

func (p *PostgresUserRepository) CheckEmailExistence(ctx context.Context, email string) error {
	sb := sq.StatementBuilder.PlaceholderFormat(sq.Dollar)

	q, args, err := sb.
		Select("id").
		From("users").
		Where(sq.Eq{"email": email}).
		Limit(1).
		ToSql()
	if err != nil {
		return err
	}

	var id string // ✅ UUID as string
	err = p.pool.QueryRow(ctx, q, args...).Scan(&id)

	if err == nil {
		return app_errors.EmailAlreadyExists
	}
	if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, stdsql.ErrNoRows) {
		return nil
	}
	return err
}

func (p *PostgresUserRepository) Create(ctx context.Context, user *entities.User) error {
	sb := sq.StatementBuilder.PlaceholderFormat(sq.Dollar)

	query, args, err := sb.
		Insert("users").
		Columns(
			"email",
			"password_hash",
			"created_at",
		).
		Values(
			user.Email,
			user.PasswordHash,
			time.Now(),
		).
		Suffix("RETURNING id").
		ToSql()

	if err != nil {
		return err
	}

	var id string
	if err := p.pool.QueryRow(ctx, query, args...).Scan(&id); err != nil {
		return err
	}

	user.ID = id // ✅ CRITICAL FIX
	return nil
}

func (p *PostgresUserRepository) CheckPassword(ctx context.Context, email, password string) error {
	sb := sq.StatementBuilder.PlaceholderFormat(sq.Dollar)

	q, args, err := sb.
		Select("password_hash").
		From("users").
		Where(sq.Eq{"email": email}).
		ToSql()

	if err != nil {
		return err
	}

	var passwordHash []byte
	err = p.pool.QueryRow(ctx, q, args...).Scan(&passwordHash)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, stdsql.ErrNoRows) {
			return app_errors.InvalidCredentials
		}
		return err
	}

	if bcrypt.CompareHashAndPassword(passwordHash, []byte(password)) != nil {
		return app_errors.InvalidCredentials
	}

	return nil
}

func (p *PostgresUserRepository) GetUserIDByEmail(
	ctx context.Context,
	email string,
) (string, error) {

	sb := sq.StatementBuilder.PlaceholderFormat(sq.Dollar)

	q, args, err := sb.
		Select("id").
		From("users").
		Where(sq.Eq{"email": email}).
		ToSql()

	if err != nil {
		return "", err
	}

	var id string

	err = p.pool.QueryRow(ctx, q, args...).Scan(&id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, stdsql.ErrNoRows) {
			return "", errors.New("no rows")
		}
		return "", err
	}

	return id, nil
}
