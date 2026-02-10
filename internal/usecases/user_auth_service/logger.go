package usecases

type Logger interface {
	Debug(msg string, fields ...interface{})
	Info(msg string, fields ...interface{})
	Warn(msg string, fields ...interface{})

	Error(err error, msg string, fields ...interface{})
}
