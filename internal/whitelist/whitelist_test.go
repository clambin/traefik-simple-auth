package whitelist

import (
	"github.com/stretchr/testify/assert"
	"net/mail"
	"strings"
	"testing"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		emails  string
		email   string
		wantErr assert.ErrorAssertionFunc
		want    assert.BoolAssertionFunc
	}{
		{
			name:    "match",
			emails:  "foo@example.com,bar@example.com",
			email:   "foo@example.com",
			wantErr: assert.NoError,
			want:    assert.True,
		},
		{
			name:    "leading whitespace is ignored",
			emails:  "foo@example.com, bar@example.com",
			email:   "bar@example.com",
			wantErr: assert.NoError,
			want:    assert.True,
		},
		{
			name:    "trailing whitespace is ignored",
			emails:  "foo@example.com ,bar@example.com",
			email:   "foo@example.com",
			wantErr: assert.NoError,
			want:    assert.True,
		},
		{
			name:    "email list is case-insensitive",
			emails:  "Foo@example.com",
			email:   "foo@example.com",
			wantErr: assert.NoError,
			want:    assert.True,
		},
		{
			name:    "email is case-insensitive",
			emails:  "foo@example.com",
			email:   "Foo@example.com",
			wantErr: assert.NoError,
			want:    assert.True,
		},
		{
			name:    "no match",
			emails:  "foo@example.com",
			email:   "bar@example.com",
			wantErr: assert.NoError,
			want:    assert.False,
		},
		{
			name:    "empty",
			emails:  "",
			email:   "foo@example.com",
			wantErr: assert.NoError,
			want:    assert.True,
		},
		{
			name:    "invalid email address",
			emails:  "0",
			wantErr: assert.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			list, err := New(strings.Split(tt.emails, ","))
			tt.wantErr(t, err)
			if err != nil {
				return
			}

			tt.want(t, list.Match(tt.email))
		})
	}
}

func FuzzNew(f *testing.F) {
	testcases := []string{"foo@example.com", "foo@example.com,foo@example.org"}
	for _, tc := range testcases {
		f.Add(tc)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if list, err := New(strings.Split(s, ",")); err == nil {
			for _, address := range list.list() {
				if _, err = mail.ParseAddress(address); err != nil {
					t.Errorf("invalid email address: %v", err)
				}
			}
		}
	})
}
