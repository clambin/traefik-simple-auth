package server

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRequest_LogValue(t *testing.T) {
	r, _ := http.NewRequest(http.MethodGet, "https://example.com/", nil)
	r.Header.Add("X-Forwarded-For", "127.0.0.1:0")

	assert.Equal(t, "[url=https://example.com/ X-Forwarded-For=127.0.0.1:0]", (*request)(r).LogValue().String())
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////

func TestRejectedRequest_LogValue(t *testing.T) {
	r, _ := http.NewRequest(http.MethodGet, "https://example.com/", nil)
	r.Header.Add("User-Agent", "foo")

	assert.Equal(t, "[method=GET url=https://example.com/ user_agent=foo]", (*rejectedRequest)(r).LogValue().String())
}
