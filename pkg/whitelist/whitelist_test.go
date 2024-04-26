package whitelist

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
			email:  "foo@example.com",
			want:   assert.True,
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

			list := New(tt.emails)
			tt.want(t, list.Match(tt.email))

			sortedList := list.list()
			slices.Sort(sortedList)
			slices.Sort(tt.emails)
			assert.Equal(t, tt.emails, sortedList)
		})
	}
}
