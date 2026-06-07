package logging

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// New builds a JSON logger with Themis standard fields.
func New(component string) (*zap.Logger, error) {
	cfg := zap.NewProductionConfig()
	return newLogger(cfg, component)
}

var buildZapLogger = func(cfg zap.Config) (*zap.Logger, error) {
	return cfg.Build()
}

func newLogger(cfg zap.Config, component string) (*zap.Logger, error) {
	cfg.Encoding = "json"
	cfg.EncoderConfig.TimeKey = "timestamp"
	cfg.EncoderConfig.LevelKey = "level"
	cfg.EncoderConfig.MessageKey = "message"
	cfg.EncoderConfig.EncodeLevel = zapcore.LowercaseLevelEncoder
	cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

	logger, err := buildZapLogger(cfg)
	if err != nil {
		return nil, err
	}

	return logger.With(zap.String("component", component)), nil
}

// WithRequest adds request-scoped fields to a logger.
func WithRequest(logger *zap.Logger, requestID, productID, projectID string) *zap.Logger {
	fields := []zap.Field{zap.String("request_id", requestID)}
	if productID != "" {
		fields = append(fields, zap.String("product_id", productID))
	}
	if projectID != "" {
		fields = append(fields, zap.String("project_id", projectID))
	}
	return logger.With(fields...)
}
