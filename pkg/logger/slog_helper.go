package logger

import (
	"log/slog"
	"runtime"
)

var ShowDebugLogs = false

func SlogError(val error) slog.Attr {
	stack := make([]byte, 4096)
	n := runtime.Stack(stack, false)

	if ShowDebugLogs {
		return slog.Group("error",
			slog.String("exception.message", val.Error()),
			slog.String("exception.stacktrace", string(stack[:n])),
		)
	} else {
		return slog.Group("error",
			slog.String("exception.message", val.Error()),
		)
	}
}
