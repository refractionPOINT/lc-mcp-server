package auth

import (
	"log/slog"

	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
)

// LCLoggerSlog adapts an slog.Logger to the LCLogger interface
// This allows us to see SDK internal logs for debugging
type LCLoggerSlog struct {
	logger *slog.Logger
}

// NewLCLoggerSlog creates a new slog-based LCLogger adapter
func NewLCLoggerSlog(logger *slog.Logger) lc.LCLogger {
	if logger == nil {
		logger = slog.Default()
	}
	return &LCLoggerSlog{logger: logger}
}

// Fatal logs at error level (slog doesn't have fatal)
// Prefixed with [SDK] to distinguish SDK logs from server logs
func (l *LCLoggerSlog) Fatal(msg string) {
	l.logger.Error("[SDK-FATAL] " + msg)
}

// Error logs at error level
func (l *LCLoggerSlog) Error(msg string) {
	l.logger.Error("[SDK] " + msg)
}

// Warn logs at warn level
func (l *LCLoggerSlog) Warn(msg string) {
	l.logger.Warn("[SDK] " + msg)
}

// Info logs at info level
func (l *LCLoggerSlog) Info(msg string) {
	l.logger.Info("[SDK] " + msg)
}

// Debug logs at debug level
func (l *LCLoggerSlog) Debug(msg string) {
	l.logger.Debug("[SDK] " + msg)
}

// Trace logs at debug level (slog doesn't have trace)
func (l *LCLoggerSlog) Trace(msg string) {
	l.logger.Debug("[SDK-TRACE] " + msg)
}
