// Package logging adapts the configured zap logger to the domain.Logger port so
// every layer logs through one backend, format, and THEMIS_LOG_LEVEL (CR-7).
package logging

import (
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/themis-project/themis/internal/domain"
)

// ZapLogger implements domain.Logger over a *zap.Logger.
type ZapLogger struct {
	z *zap.Logger
}

var _ domain.Logger = (*ZapLogger)(nil)

// New builds a JSON zap logger at the requested level (debug|info|warn|error)
// tagged with the component field, adapted to domain.Logger.
func New(component, level string) (*ZapLogger, error) {
	cfg := zap.NewProductionConfig()
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		cfg.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	case "warn":
		cfg.Level = zap.NewAtomicLevelAt(zap.WarnLevel)
	case "error":
		cfg.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)
	default:
		cfg.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	}
	cfg.Encoding = "json"
	cfg.EncoderConfig.TimeKey = "timestamp"
	cfg.EncoderConfig.LevelKey = "level"
	cfg.EncoderConfig.MessageKey = "message"
	cfg.EncoderConfig.EncodeLevel = zapcore.LowercaseLevelEncoder
	cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

	z, err := cfg.Build()
	if err != nil {
		return nil, err
	}
	return &ZapLogger{z: z.With(zap.String("component", component))}, nil
}

// NewFromZap adapts an existing *zap.Logger to the domain.Logger port.
func NewFromZap(z *zap.Logger) *ZapLogger { return &ZapLogger{z: z} }

// Zap returns the underlying zap logger for callers that still take *zap.Logger.
func (l *ZapLogger) Zap() *zap.Logger { return l.z }

// Debug logs at debug level.
func (l *ZapLogger) Debug(msg string, fields ...domain.Field) { l.z.Debug(msg, zapFields(fields)...) }

// Info logs at info level.
func (l *ZapLogger) Info(msg string, fields ...domain.Field) { l.z.Info(msg, zapFields(fields)...) }

// Warn logs at warn level.
func (l *ZapLogger) Warn(msg string, fields ...domain.Field) { l.z.Warn(msg, zapFields(fields)...) }

// Error logs at error level.
func (l *ZapLogger) Error(msg string, fields ...domain.Field) { l.z.Error(msg, zapFields(fields)...) }

// With returns a child logger with the given fields bound.
func (l *ZapLogger) With(fields ...domain.Field) domain.Logger {
	return &ZapLogger{z: l.z.With(zapFields(fields)...)}
}

func zapFields(fields []domain.Field) []zap.Field {
	out := make([]zap.Field, 0, len(fields))
	for _, f := range fields {
		out = append(out, zap.Any(f.Key, f.Value))
	}
	return out
}
