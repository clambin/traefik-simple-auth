package domains

import (
	"github.com/stretchr/testify/assert"
	"net/url"
	"slices"
	"strings"
	"testing"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr assert.ErrorAssertionFunc
		want    Domains
	}{
		{
			name:    "single domain, no dot",
			input:   "example.com",
			wantErr: assert.NoError,
			want:    Domains{".example.com"},
		},
		{
			name:    "single domain, dot",
			input:   ".example.com",
			wantErr: assert.NoError,
			want:    Domains{".example.com"},
		},
		{
			name:    "multiple domains",
			input:   ".example.com,example.org",
			wantErr: assert.NoError,
			want:    Domains{".example.com", ".example.org"},
		},
		{
			name:    "whitespace is ignored",
			input:   ".example.com , example.org",
			wantErr: assert.NoError,
			want:    Domains{".example.com", ".example.org"},
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
			t.Parallel()

			result, err := New(strings.Split(tt.input, ","))
			tt.wantErr(t, err)
			if err != nil {
				return
			}

			slices.Sort(result)
			assert.Equal(t, tt.want, result)
		})
	}
}

func FuzzNew(f *testing.F) {
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
		domains Domains
		target  string
		wantOK  assert.BoolAssertionFunc
		want    Domain
	}{
		{
			name:    "match single domain",
			domains: Domains{".example.com"},
			target:  "https://example.com/foo",
			wantOK:  assert.True,
			want:    ".example.com",
		},
		{
			name:    "match should be case-insensitive",
			domains: Domains{".example.com"},
			target:  "https://Example.Com/foo",
			wantOK:  assert.True,
			want:    ".example.com",
		},
		{
			name:    "match multiple domains",
			domains: Domains{".example.com", ".example.org"},
			target:  "https://www.example.org/foo",
			wantOK:  assert.True,
			want:    ".example.org",
		},
		{
			name:    "ignore ports",
			domains: Domains{".example.com"},
			target:  "https://example.com:443/foo",
			wantOK:  assert.True,
			want:    ".example.com",
		},
		{
			name:    "no match",
			domains: Domains{".example.com", ".example.org"},
			target:  "https://www.example.net",
			wantOK:  assert.False,
		},
		{
			name:    "overlap",
			domains: Domains{".example.com"},
			target:  "https://www.badexample.com/foo",
			wantOK:  assert.False,
		},
		{
			name:    "empty",
			domains: Domains{".example.com"},
			target:  "",
			wantOK:  assert.False,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			u, _ := url.Parse(tt.target)
			domain, ok := tt.domains.Domain(u)
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
