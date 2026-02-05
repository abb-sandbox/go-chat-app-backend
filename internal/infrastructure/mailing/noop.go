package mailing

import (
	"context"
	"fmt"

	"github.com/AzimBB/go-chat-app-backend/internal/domain/adapters"
)

// NoopMailer implements MailingService with no-op behavior
type NoopMailer struct{}

func NewNoopMailer() adapters.MailingService { return &NoopMailer{} }

func (n *NoopMailer) SendActivationCode(ctx context.Context, email, code string) error {
	// For now just pretend and return nil
	fmt.Println("activation code:", code)
	return nil
}
