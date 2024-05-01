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

			result, err := GetDomains(tt.input)
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
		if domains, err := GetDomains(strings.Split(s, ",")); err == nil {
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
			target:  "https://www.example.com/foo",
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
			domains, _ := GetDomains(tt.domains)
			domain, ok := domains.Domain(u)
			tt.wantOK(t, ok)
			assert.Equal(t, tt.want, domain)
		})
	}
}

func Test_isSubdomain(t *testing.T) {
	tests := []struct {
		name   string
		domain Domain
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.want(t, isValidSubdomain(tt.domain, tt.input))
		})
	}
}

// before:
// BenchmarkDomains_Domain-16      38363563                31.01 ns/op            0 B/op          0 allocs/op
// after:
// BenchmarkDomains_Domain-16      217555663                5.487 ns/op           0 B/op          0 allocs/op
func BenchmarkDomains_Domain(b *testing.B) {
	domains, _ := GetDomains([]string{"example.com"})
	for range b.N {
		_, _ = domains.Domain(&url.URL{Host: "www.example.com"})
	}
}
