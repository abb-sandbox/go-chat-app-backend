package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/AzimBB/go-chat-app-backend/internal/config"
	infrajwt "github.com/AzimBB/go-chat-app-backend/internal/infrastructure/jwt"
	"github.com/AzimBB/go-chat-app-backend/internal/infrastructure/logger"
	inframailing "github.com/AzimBB/go-chat-app-backend/internal/infrastructure/mailing"
	"github.com/AzimBB/go-chat-app-backend/internal/infrastructure/postgres"
	infrapostgres "github.com/AzimBB/go-chat-app-backend/internal/infrastructure/postgres"
	infraredis "github.com/AzimBB/go-chat-app-backend/internal/infrastructure/redis"
	handlers "github.com/AzimBB/go-chat-app-backend/internal/interfaces/http/handlers/auth"
	"github.com/AzimBB/go-chat-app-backend/internal/interfaces/http/middleware"
	usecases "github.com/AzimBB/go-chat-app-backend/internal/usecases/user_auth_service"
	"github.com/gin-gonic/gin"
)

// @title						Go Chat App API
// @version					1.0
// @description				Backend API for Flutter Chat App.
// @securityDefinitions.apikey	CookieAuth
// @in							cookie
// @name						access_token
func main() {
	cfg := config.GetConfig()
	var lg usecases.Logger = logger.NewZapLogger(cfg.LOG_LVL, cfg.DEV)
	lg.Info("Postgres dsn", cfg.PG_URL)

	// Initialize DB
	pool, err := postgres.NewPool(cfg)
	if err != nil {
		lg.Error(err, "failed to connect to postgres")
		return
	}
	defer pool.Close()

	// Initialize Redis
	rClient, err := infraredis.NewRedisClient(cfg)
	if err != nil {
		lg.Error(err, "failed to connect to redis")
		return
	}
	defer rClient.Close()

	// Initialize infra services and application
	userRepo := infrapostgres.NewUserRepository(pool)
	cache := infraredis.NewCache(rClient)
	mailer := inframailing.NewNoopMailer()

	jwtSvc := infrajwt.New(cfg)

	authService := &usecases.UserAuthServiceImpl{
		UserRepository:       userRepo,
		JWTService:           jwtSvc,
		Cache:                cache,
		MailingService:       mailer,
		ActivationTimeExpiry: cfg.ACT_EXP,
		Logger:               lg,
	}

	r := gin.Default()
	// Health check for local dev and readiness
	r.GET("/health", handlers.Health)

	r.GET("/", handlers.Health)
	api_v1 := r.Group("/api/v1")
	api_v1.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok", "time": time.Now().Format(time.RFC3339)})
	})
	// Register auth routes
	h := handlers.NewAuthHandler(authService, lg, cfg)
	h.RegisterRoutes(api_v1, middleware.AuthMiddleware(jwtSvc, cache, lg))

	// Run server with graceful shutdown
	port := os.Getenv("PORT")
	if port == "" {
		port = "8000" // Default for local
	}
	srv := &http.Server{Addr: "0.0.0.0:" + port, Handler: r}
	go func() {
		if err := srv.ListenAndServe(); err != nil {
			lg.Error(err, "http server stopped")
		}
	}()
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	<-quit
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		lg.Error(err, "server forced to shutdown")
	}
	lg.Info("server exiting")
}
