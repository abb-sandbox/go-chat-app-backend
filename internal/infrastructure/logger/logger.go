package logger

import (
	"errors"
	"log"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// ZapLogger implements the ports.Logger interface using Uber's Zap.
type ZapLogger struct {
	log *zap.Logger
}

// NewZapLogger creates a new configured ZapLogger instance.
func NewZapLogger(level string, isDevelopment bool) *ZapLogger {
	var config zap.Config
	if isDevelopment {
		config = zap.NewDevelopmentConfig()
	} else {
		config = zap.NewProductionConfig()
	}

	// Set the log level
	var lvl zapcore.Level
	if err := lvl.UnmarshalText([]byte(level)); err == nil {
		config.Level = zap.NewAtomicLevelAt(lvl)
	} else {
		config.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	}

	// Configure stdout for output (JSON for production, Console for development)
	config.OutputPaths = []string{"stdout"}
	config.ErrorOutputPaths = []string{"stderr"}

	logger, err := config.Build()
	if err != nil {
		// Fallback to a simple logger if configuration fails
		log.Fatal("Failed to initialize Zap logger: ", err)
	}

	return &ZapLogger{log: logger}
}

// --- Implementations of ports.Logger methods ---

func (z *ZapLogger) Debug(msg string, fields ...interface{}) {
	z.log.Debug(msg, convertToZapFields(fields...)...)
}

func (z *ZapLogger) Info(msg string, fields ...interface{}) {
	z.log.Info(msg, convertToZapFields(fields...)...)
}

func (z *ZapLogger) Warn(msg string, fields ...interface{}) {
	z.log.Warn(msg, convertToZapFields(fields...)...)
}

func (z *ZapLogger) Error(err error, msg string, fields ...interface{}) {
	// Start with the standard fields
	zapFields := convertToZapFields(fields...)

	// Add the error object itself
	if err != nil && !errors.Is(err, errors.New("")) { // Ensure error is not nil or empty
		zapFields = append(zapFields, zap.Error(err))
	}

	z.log.Error(msg, zapFields...)
}

func (z *ZapLogger) With(fields ...interface{}) *ZapLogger {
	newLogger := z.log.With(convertToZapFields(fields...)...)
	return &ZapLogger{log: newLogger}
}

// Sync flushes any buffered log entries (useful before application exit).
func (z *ZapLogger) Sync() {
	// This is optional and often called via defer in main.go
	z.log.Sync()
}
