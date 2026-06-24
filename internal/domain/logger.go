package domain

// CR-7 — one logging port.
//
// Before this change the configured zap logger reached almost nothing: schedulers
// swallowed errors, feed clients logged through slog.Default() (a second,
// unconfigured system that ignored THEMIS_LOG_LEVEL), and use cases were silent.
// Logger is the single port every layer logs through; infrastructure implements
// it over zap so one backend, format, and level govern all output. Keeping the
// port in domain lets use cases and adapters log without importing zap/slog,
// preserving the clean-architecture import rule.

// Field is a structured key/value pair attached to a log line.
type Field struct {
	Key   string
	Value any
}

// LogString builds a string log field.
func LogString(key, value string) Field { return Field{Key: key, Value: value} }

// LogInt builds an integer log field.
func LogInt(key string, value int) Field { return Field{Key: key, Value: value} }

// LogAny builds a log field for an arbitrary value.
func LogAny(key string, value any) Field { return Field{Key: key, Value: value} }

// LogErr builds an "error" field, tolerating a nil error.
func LogErr(err error) Field {
	if err == nil {
		return Field{Key: "error", Value: ""}
	}
	return Field{Key: "error", Value: err.Error()}
}

// Logger is the domain logging port. Implemented in infrastructure over zap.
type Logger interface {
	Debug(msg string, fields ...Field)
	Info(msg string, fields ...Field)
	Warn(msg string, fields ...Field)
	Error(msg string, fields ...Field)
	With(fields ...Field) Logger
}

// NopLogger discards every log line. It is the safe default wherever a logger is
// not injected, replacing the scattered slog.Default() fallbacks.
type NopLogger struct{}

// Debug discards the log line.
func (NopLogger) Debug(string, ...Field) {}

// Info discards the log line.
func (NopLogger) Info(string, ...Field) {}

// Warn discards the log line.
func (NopLogger) Warn(string, ...Field) {}

// Error discards the log line.
func (NopLogger) Error(string, ...Field) {}

// With returns the same no-op logger.
func (n NopLogger) With(...Field) Logger { return n }

// LoggerOrNop returns log when non-nil, otherwise a NopLogger.
func LoggerOrNop(log Logger) Logger {
	if log == nil {
		return NopLogger{}
	}
	return log
}
