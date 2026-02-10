package mailing

import (
	"context"
	"fmt"
)

// NoopMailer implements MailingService with no-op behavior
type NoopMailer struct{}

func NewNoopMailer() *NoopMailer { return &NoopMailer{} }

func (n *NoopMailer) SendActivationCode(ctx context.Context, email, code string) error {
	// For now just pretend and return nil
	fmt.Println("activation code:", code)
	return nil
}
