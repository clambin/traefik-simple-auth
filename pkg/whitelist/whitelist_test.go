package whitelist

import (
	"github.com/stretchr/testify/assert"
	"net/mail"
	"slices"
	"strings"
	"testing"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		emails  []string
		email   string
		wantErr assert.ErrorAssertionFunc
		want    assert.BoolAssertionFunc
	}{
		{
			name:    "match",
			emails:  []string{"foo@example.com", "bar@example.com"},
			email:   "foo@example.com",
			wantErr: assert.NoError,
			want:    assert.True,
		},
		{
			name:    "no match",
			emails:  []string{"foo@example.com"},
			email:   "bar@example.com",
			wantErr: assert.NoError,
			want:    assert.False,
		},
		{
			name:    "empty",
			emails:  []string{},
			email:   "foo@example.com",
			wantErr: assert.NoError,
			want:    assert.True,
		},
		{
			name:    "case-insensitive",
			emails:  []string{"foo@example.com", "bar@example.com"},
			email:   "Foo@example.com",
			wantErr: assert.NoError,
			want:    assert.True,
		},
		{
			name:    "invalid email address",
			emails:  []string{"foo@example.com", "0"},
			wantErr: assert.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			list, err := New(tt.emails)
			tt.wantErr(t, err)
			if err != nil {
				return
			}

			tt.want(t, list.Match(tt.email))

			sortedList := list.list()
			slices.Sort(sortedList)
			slices.Sort(tt.emails)
			assert.Equal(t, tt.emails, sortedList)
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
