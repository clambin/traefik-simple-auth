package testutils

import (
	"io"
	"log/slog"
)

var DiscardLogger = slog.New(slog.NewTextHandler(io.Discard, nil))
