package domains

import (
	"github.com/stretchr/testify/assert"
	"net/url"
	"slices"
	"strings"
	"testing"
)

func TestGetDomains(t *testing.T) {
	tests := []struct {
		name    string
		input   []string
		wantErr assert.ErrorAssertionFunc
		want    Domains
	}{
		{
			name:    "single domain, no dot",
			input:   []string{"example.com"},
			wantErr: assert.NoError,
			want:    Domains{".example.com"},
		},
		{
			name:    "single domain, dot",
			input:   []string{".example.com"},
			wantErr: assert.NoError,
			want:    Domains{".example.com"},
		},
		{
			name:    "multiple domains",
			input:   []string{".example.com", "example.org"},
			wantErr: assert.NoError,
			want:    Domains{".example.com", ".example.org"},
		},
		{
			name:    "invalid entry",
			input:   []string{". example.com"},
			wantErr: assert.Error,
		},
		{
			name:    "empty entry",
			input:   []string{""},
			wantErr: assert.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result, err := New(tt.input)
			tt.wantErr(t, err)
			if err != nil {
				return
			}

			slices.Sort(result)
			assert.Equal(t, tt.want, result)
		})
	}
}

func FuzzGetDomains(f *testing.F) {
	testcases := []string{"example.com", ".example.com", "example.com,example.org", ".example.com,.example.org"}
	for _, tc := range testcases {
		f.Add(tc)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if domains, err := New(strings.Split(s, ",")); err == nil {
			for _, domain := range domains {
				if _, err = url.Parse("https://www" + string(domain)); err != nil {
					t.Errorf("invalid URL: %v", err)
				}
				if domain[0] != '.' {
					t.Errorf("domain does not start with '.', got %q", domain)
				}
			}
		}
	})
}

func TestDomains_Domain(t *testing.T) {
	tests := []struct {
		name    string
		domains []string
		target  string
		wantOK  assert.BoolAssertionFunc
		want    Domain
	}{
		{
			name:    "match single domain",
			domains: []string{"example.com"},
			target:  "https://example.com/foo",
			wantOK:  assert.True,
			want:    ".example.com",
		},
		{
			name:    "match should be case-insensitive",
			domains: []string{"Example.com"},
			target:  "https://example.Com/foo",
			wantOK:  assert.True,
			want:    ".example.com",
		},
		{
			name:    "ignore ports",
			domains: []string{"example.com"},
			target:  "https://example.com:443/foo",
			wantOK:  assert.True,
			want:    ".example.com",
		},
		{
			name:    "match multiple domains",
			domains: []string{"example.com", "example.org"},
			target:  "https://www.example.org/foo",
			wantOK:  assert.True,
			want:    ".example.org",
		},
		{
			name:    "no match",
			domains: []string{"example.com", "example.org"},
			target:  "https://www.example.net",
			wantOK:  assert.False,
		},
		{
			name:    "overlap",
			domains: []string{"example.com"},
			target:  "https://www.badexample.com/foo",
			wantOK:  assert.False,
		},
		{
			name:    "empty",
			domains: []string{},
			target:  "https://www.example.com",
			wantOK:  assert.False,
		},
		{
			name:    "error",
			domains: []string{},
			target:  "",
			wantOK:  assert.False,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			u, _ := url.Parse(tt.target)
			domains, _ := New(tt.domains)
			domain, ok := domains.Domain(u)
			tt.wantOK(t, ok)
			assert.Equal(t, tt.want, domain)
		})
	}
}

// before:
// BenchmarkDomains_Domain-16      217555663                5.487 ns/op           0 B/op          0 allocs/op
// after (case-insensitive):
// BenchmarkDomains_Domain-16      65392693                18.35 ns/op            0 B/op          0 allocs/op
func BenchmarkDomains_Domain(b *testing.B) {
	domains, _ := New([]string{"example.com"})
	for range b.N {
		_, _ = domains.Domain(&url.URL{Host: "www.example.com"})
	}
}
