package mailing

import (
	"context"

	"github.com/resend/resend-go/v2"
)

// NoopMailer implements MailingService with no-op behavior
type NoopMailer struct {
	apiKey      string
	serverName  string
	actEndpoint string
}

func NewNoopMailer(apiKey string, serverName string, actEndpointTail string) *NoopMailer {
	return &NoopMailer{apiKey: apiKey, serverName: serverName, actEndpoint: "https://" + serverName + "/" + actEndpointTail + "/"}
}

func (n *NoopMailer) SendActivationLink(ctx context.Context, email, code string) error {

	client := resend.NewClient(n.apiKey)

	params := &resend.SendEmailRequest{
		From:    "noreply@" + n.serverName,
		To:      []string{email},
		Subject: n.GetTemplate(code),
		Html:    "<p>Congrats on sending your <strong>first email</strong>!</p>",
	}

	_, err := client.Emails.Send(params)
	if err != nil {
		return err
	}
	return nil
}

func (n *NoopMailer) GetTemplate(link string) string {
	return `<div class="container"><h2>Account Activation</h2><p>Activate your account by clicking the link below.</p>	<a href="` + n.actEndpoint + link + `" class="activate-btn" id="linkBtn">Activate Account</a></div>`
}
