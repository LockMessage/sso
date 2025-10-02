package validation

import (
	"errors"
	"testing"

	"github.com/LockMessage/sso/internal/domain"
)

func TestValidEmails(t *testing.T) {
	validEmails := []struct {
		name string
		want error
	}{
		{name: "test@io.com", want: nil},
		{name: "test.io@epam.com", want: nil},
		{name: "test.io.example+today@epam.com", want: nil},
		{name: "test-io@epam.com", want: nil},
		{name: "test@io-epam.com", want: nil},
		{name: "test-io@epam-usa.com", want: nil},
		{name: "123456789testio@epam2.com", want: nil},
	}
	for _, tt := range validEmails {
		t.Run(tt.name, func(t *testing.T) {
			if got := ValidateEmail(tt.name); got != tt.want {
				t.Errorf("ValidateEmail() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestInvalidEmail(t *testing.T) {
	t.Parallel()
	invalidEmails := []struct {
		name string
		want error
	}{
		{name: "@.com", want: domain.ErrWrongEmailFormat},
		{name: "", want: domain.ErrWrongEmailFormat},
		{name: " ", want: domain.ErrWrongEmailFormat},
		{name: "\"test.io.com", want: domain.ErrWrongEmailFormat},
		{name: "test(io\"epam)example]com", want: domain.ErrWrongEmailFormat},
		{name: "test\\\"io\\\"epam.com\"", want: domain.ErrWrongEmailFormat},
		{name: ".test... io\\today@epam.com", want: domain.ErrWrongEmailFormat},
	}
	for _, tt := range invalidEmails {
		t.Run(tt.name, func(t *testing.T) {
			if got := ValidateEmail(tt.name); errors.Is(got, tt.want) {
				t.Errorf("ValidateEmail() = %v, want %v", got, tt.want)
			}
		})
	}
}
