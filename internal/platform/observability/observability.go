// Package observability is the one shared observability bootstrap every deployable node
// uses (CONVENTIONS.md R1 · BCK-0051): a structured logger that emits to BOTH the console
// (zap, human-readable or JSON) AND OpenTelemetry (an OTLP log exporter), from a single log
// call. The minimum severity and the OTel exporter are config-driven (R2): console is always
// on; OTel log export is enabled only when an OTLP endpoint is configured. Logs carry a
// service name and are meant to be correlated by stable business identifiers (never infra
// ids). The pure domain/app rings never log — only adapters and the composition root do, so
// this package sits at the platform layer, outside any bounded context.
package observability

import (
	"context"
	"os"
	"strings"
	"time"

	"go.opentelemetry.io/contrib/bridges/otelzap"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	otellogglobal "go.opentelemetry.io/otel/log/global"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// ConfigFromEnv reads the standard, node-shared observability options from the environment
// (R2 — one config-loading convention for every node). The variable names and defaults are:
//
//	THEMIS_LOG_LEVEL          debug | info | warn | error   (default info)
//	THEMIS_LOG_FORMAT         console | json                (default json)
//	THEMIS_OTLP_LOGS_ENDPOINT host:port of an OTLP/HTTP logs collector; empty = console-only
//	THEMIS_OTLP_INSECURE      "1" to use http instead of https to the collector (local dev)
//
// service is the node's service.name (e.g. "evidence").
func ConfigFromEnv(service string) Config {
	return Config{
		Service:      service,
		Level:        os.Getenv("THEMIS_LOG_LEVEL"),
		Format:       os.Getenv("THEMIS_LOG_FORMAT"),
		OTLPEndpoint: os.Getenv("THEMIS_OTLP_LOGS_ENDPOINT"),
		OTLPInsecure: os.Getenv("THEMIS_OTLP_INSECURE") == "1",
	}
}

// Config controls the shared observability bootstrap (R1/R2).
type Config struct {
	// Service is the service.name for telemetry (e.g. "evidence"); tagged on every record.
	Service string
	// Level is the minimum severity: debug | info | warn | error (default info).
	Level string
	// Format is the console encoding: console | json (default json).
	Format string
	// OTLPEndpoint is the OTLP/HTTP logs endpoint (host:port). Empty disables OTel log export
	// (console-only) — so nothing external is required to run locally.
	OTLPEndpoint string
	// OTLPInsecure sends over http instead of https to the OTLP endpoint (local collectors).
	OTLPInsecure bool
}

// Field is a structured log field. The constructors below re-export zap's so callers never
// import zap directly.
type Field = zap.Field

// Field constructors (a curated subset of zap's).
func String(key, val string) Field                 { return zap.String(key, val) }
func Int(key string, val int) Field                { return zap.Int(key, val) }
func Int64(key string, val int64) Field            { return zap.Int64(key, val) }
func Bool(key string, val bool) Field              { return zap.Bool(key, val) }
func Duration(key string, val time.Duration) Field { return zap.Duration(key, val) }
func Err(err error) Field                          { return zap.Error(err) }
func Any(key string, val any) Field                { return zap.Any(key, val) }

// Logger is the structured, dual-channel logger every node uses (R1).
type Logger struct {
	z *zap.Logger
}

// Setup builds the dual-channel logger + (when configured) an OTel LoggerProvider from cfg,
// returning the logger and a shutdown func to flush + close on exit. Console is always on;
// OTel log export is enabled only when cfg.OTLPEndpoint is set (config-driven — R2).
func Setup(ctx context.Context, cfg Config) (*Logger, func(context.Context) error, error) {
	level := ParseLevel(cfg.Level)

	encCfg := zap.NewProductionEncoderConfig()
	encCfg.TimeKey = "timestamp"
	encCfg.LevelKey = "level"
	encCfg.MessageKey = "message"
	encCfg.EncodeTime = zapcore.ISO8601TimeEncoder
	encCfg.EncodeLevel = zapcore.LowercaseLevelEncoder

	var consoleEnc zapcore.Encoder
	if strings.EqualFold(strings.TrimSpace(cfg.Format), "console") {
		consoleEnc = zapcore.NewConsoleEncoder(encCfg)
	} else {
		consoleEnc = zapcore.NewJSONEncoder(encCfg)
	}
	cores := []zapcore.Core{zapcore.NewCore(consoleEnc, zapcore.Lock(zapcore.AddSync(os.Stdout)), level)}

	shutdown := func(context.Context) error { return nil }

	if strings.TrimSpace(cfg.OTLPEndpoint) != "" {
		provider, err := newOTelLogs(ctx, cfg)
		if err != nil {
			return nil, nil, err
		}
		otellogglobal.SetLoggerProvider(provider)
		otelCore := otelzap.NewCore(cfg.Service, otelzap.WithLoggerProvider(provider))
		cores = append(cores, leveledCore{Core: otelCore, level: level})
		shutdown = provider.Shutdown
	}

	z := zap.New(zapcore.NewTee(cores...))
	if cfg.Service != "" {
		z = z.With(zap.String("service", cfg.Service))
	}
	return &Logger{z: z}, shutdown, nil
}

// newOTelLogs builds an OTel LoggerProvider exporting via OTLP/HTTP.
func newOTelLogs(ctx context.Context, cfg Config) (*sdklog.LoggerProvider, error) {
	opts := []otlploghttp.Option{otlploghttp.WithEndpoint(cfg.OTLPEndpoint)}
	if cfg.OTLPInsecure {
		opts = append(opts, otlploghttp.WithInsecure())
	}
	exp, err := otlploghttp.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	res := resource.NewWithAttributes(semconv.SchemaURL, semconv.ServiceNameKey.String(cfg.Service))
	return sdklog.NewLoggerProvider(
		sdklog.WithResource(res),
		sdklog.WithProcessor(sdklog.NewBatchProcessor(exp)),
	), nil
}

// leveledCore applies the configured minimum level to a wrapped core (the otelzap core does
// not filter by level itself), so console and OTel honor the same severity threshold.
type leveledCore struct {
	zapcore.Core
	level zapcore.LevelEnabler
}

func (c leveledCore) Enabled(l zapcore.Level) bool { return c.level.Enabled(l) && c.Core.Enabled(l) }

func (c leveledCore) Check(e zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if c.Enabled(e.Level) {
		return ce.AddCore(e, c)
	}
	return ce
}

// ParseLevel maps a config string to a zap level (default info for unknown/empty).
func ParseLevel(level string) zapcore.Level {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		return zapcore.DebugLevel
	case "warn", "warning":
		return zapcore.WarnLevel
	case "error":
		return zapcore.ErrorLevel
	default:
		return zapcore.InfoLevel
	}
}

// Nop returns a logger that discards everything — for tests and components without wiring.
func Nop() *Logger { return &Logger{z: zap.NewNop()} }

// New adapts an existing zap logger (used by tests to capture output).
func New(z *zap.Logger) *Logger { return &Logger{z: z} }

// Debug logs at debug severity.
func (l *Logger) Debug(msg string, fields ...Field) { l.z.Debug(msg, fields...) }

// Info logs at info severity.
func (l *Logger) Info(msg string, fields ...Field) { l.z.Info(msg, fields...) }

// Warn logs at warn severity.
func (l *Logger) Warn(msg string, fields ...Field) { l.z.Warn(msg, fields...) }

// Error logs at error severity.
func (l *Logger) Error(msg string, fields ...Field) { l.z.Error(msg, fields...) }

// With returns a child logger with the given fields attached to every record — e.g. a
// correlation id or component name (R1: correlated by business identifiers).
func (l *Logger) With(fields ...Field) *Logger { return &Logger{z: l.z.With(fields...)} }

// Component returns a child logger tagged with a component name.
func (l *Logger) Component(name string) *Logger { return l.With(String("component", name)) }

// Sync flushes any buffered console entries (call before exit).
func (l *Logger) Sync() error { return l.z.Sync() }

// Redact masks a sensitive value so it never appears in the clear in either channel (R1 /
// INT-0064/0069). Callers pass secrets through it before logging.
func Redact(value string) string {
	if value == "" {
		return ""
	}
	return "[redacted]"
}
