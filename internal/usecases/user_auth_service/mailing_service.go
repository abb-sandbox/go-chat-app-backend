package usecases

import "context"

type MailingService interface {
	SendActivationCode(ctx context.Context, email, activationCode string) error
}
