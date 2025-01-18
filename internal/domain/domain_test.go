package domain

import (
	"github.com/stretchr/testify/assert"
	"net/url"
	"testing"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr assert.ErrorAssertionFunc
		want    Domain
	}{
		{
			name:    "no dot",
			input:   "example.com",
			wantErr: assert.NoError,
			want:    ".example.com",
		},
		{
			name:    "dot",
			input:   ".example.com",
			wantErr: assert.NoError,
			want:    ".example.com",
		},
		{
			name:    "whitespace is ignored",
			input:   " .example.com ",
			wantErr: assert.NoError,
			want:    ".example.com",
		},
		{
			name:    "port is not allowed",
			input:   ".example.com:443",
			wantErr: assert.Error,
		},
		{
			name:    "invalid entry",
			input:   ". example.com",
			wantErr: assert.Error,
		},
		{
			name:    "empty entry",
			input:   "",
			wantErr: assert.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := New(tt.input)
			tt.wantErr(t, err)
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestDomain_Match(t *testing.T) {
	tests := []struct {
		name    string
		domains Domain
		target  string
		wantOK  assert.BoolAssertionFunc
		want    Domain
	}{
		{
			name:    "match",
			domains: ".example.com",
			target:  "https://example.com/foo",
			wantOK:  assert.True,
			want:    ".example.com",
		},
		{
			name:    "match should be case-insensitive",
			domains: ".example.com",
			target:  "https://Example.Com/foo",
			wantOK:  assert.True,
			want:    ".example.com",
		},
		{
			name:    "ignore ports",
			domains: ".example.com",
			target:  "https://example.com:443/foo",
			wantOK:  assert.True,
			want:    ".example.com",
		},
		{
			name:    "no match",
			domains: ".example.com",
			target:  "https://www.example.net",
			wantOK:  assert.False,
		},
		{
			name:    "overlap",
			domains: ".example.com",
			target:  "https://www.badexample.com/foo",
			wantOK:  assert.False,
		},
		{
			name:    "empty",
			domains: ".example.com",
			target:  "",
			wantOK:  assert.False,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, _ := url.Parse(tt.target)
			tt.wantOK(t, tt.domains.Matches(u))
		})
	}
}

// Current:
// BenchmarkDomains_Domain-16    	46558543	        26.06 ns/op	       0 B/op	       0 allocs/op
func BenchmarkDomains_Domain(b *testing.B) {
	domain, _ := New(".example.com")
	b.ReportAllocs()
	for range b.N {
		if ok := domain.Matches(&url.URL{Host: "www.example.com"}); !ok {
			b.Fatal("should match")
		}
	}
}
