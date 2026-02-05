package adapters

type Logger interface {
	Debug(msg string, fields ...interface{})
	Info(msg string, fields ...interface{})
	Warn(msg string, fields ...interface{})

	Error(err error, msg string, fields ...interface{})

	// With is used to create a new logger instance with pre-defined fields (e.g., for request tracing).
	With(fields ...interface{}) Logger
}
