package domain

import (
	"github.com/stretchr/testify/assert"
	"net/url"
	"testing"
)

func Test_isSubdomain(t *testing.T) {
	tests := []struct {
		name   string
		domain string
		input  string
		want   assert.BoolAssertionFunc
	}{
		{
			name:   "equal",
			domain: ".example.com",
			input:  "example.com",
			want:   assert.True,
		},
		{
			name:   "valid subdomain",
			domain: ".example.com",
			input:  "www.example.com",
			want:   assert.True,
		},
		{
			name:   "don't match on overlap",
			domain: ".example.com",
			input:  "bad-example.com",
			want:   assert.False,
		},
		{
			name:   "mismatch",
			domain: ".example.com",
			input:  "www.example2.com",
			want:   assert.False,
		},
		{
			name:  "empty subdomain",
			input: "example.com",
			want:  assert.False,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.want(t, isValidSubdomain(tt.domain, tt.input))
		})
	}
}

func TestDomains(t *testing.T) {
	tests := []struct {
		name    string
		domains Domains
		target  string
		wantOK  assert.BoolAssertionFunc
		want    string
	}{
		{
			name:    "match single domain",
			domains: Domains{"example.com"},
			target:  "https://www.example.com/foo",
			wantOK:  assert.True,
			want:    "example.com",
		},
		{
			name:    "match multiple domains",
			domains: Domains{"example.com", "example.org"},
			target:  "https://www.example.org/foo",
			wantOK:  assert.True,
			want:    "example.org",
		},
		{
			name:    "no match",
			domains: Domains{"example.com", "example.org"},
			target:  "https://www.example.net",
			wantOK:  assert.False,
		},
		{
			name:    "empty",
			domains: Domains{},
			target:  "https://www.example.com",
			wantOK:  assert.False,
		},
		{
			name:    "error",
			domains: Domains{},
			target:  "",
			wantOK:  assert.False,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			u, _ := url.Parse(tt.target)
			domain, ok := tt.domains.GetDomain(u)
			tt.wantOK(t, ok)
			assert.Equal(t, tt.want, domain)
		})
	}
}
