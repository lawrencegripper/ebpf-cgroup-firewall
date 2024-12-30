package logger

import (
	"fmt"
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
			slog.String("exception.stacktrace", fmt.Sprintf("%s", stack[:n])),
		)
	} else {
		return slog.Group("error",
			slog.String("exception.message", val.Error()),
		)
	}
}