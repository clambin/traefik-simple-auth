package server

import (
	"github.com/stretchr/testify/assert"
	"slices"
	"testing"
)

func Test_whitelist(t *testing.T) {
	tests := []struct {
		name   string
		emails []string
		email  string
		want   assert.BoolAssertionFunc
	}{
		{
			name:   "match",
			emails: []string{"foo@example.com", "bar@example.com"},
			email:  "foo@example.com",
			want:   assert.True,
		},
		{
			name:   "no match",
			emails: []string{"foo@example.com"},
			email:  "bar@example.com",
			want:   assert.False,
		},
		{
			name:   "empty",
			emails: []string{},
			want:   assert.False,
		},
		{
			name:   "case-insensitive",
			emails: []string{"foo@example.com", "bar@example.com"},
			email:  "Foo@example.com",
			want:   assert.True,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			list := newWhitelist(tt.emails)
			tt.want(t, list.contains(tt.email))

			sortedList := list.list()
			slices.Sort(sortedList)
			slices.Sort(tt.emails)
			assert.Equal(t, tt.emails, sortedList)
		})
	}
}
