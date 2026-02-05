package logger

import "go.uber.org/zap"

func convertToZapFields(fields ...interface{}) []zap.Field {
	if len(fields)%2 != 0 {
		// If there's an odd number, we log an error, but try to proceed.
		zap.L().Error("Logger field conversion error: fields must be key-value pairs",
			zap.Any("fields_provided", fields))
		return nil
	}

	zapFields := make([]zap.Field, 0, len(fields)/2)
	for i := 0; i < len(fields); i += 2 {
		key, ok := fields[i].(string)
		if !ok {
			// Handle non-string keys gracefully
			zap.L().Error("Logger field conversion error: key is not a string",
				zap.Any("key_value", fields[i]))
			continue
		}
		zapFields = append(zapFields, zap.Any(key, fields[i+1]))
	}
	return zapFields
}
