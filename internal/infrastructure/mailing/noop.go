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
	return `
		<!DOCTYPE html>
		<html lang="en">
		<head>
			<meta charset="UTF-8">
			<meta name="viewport" content="width=device-width, initial-scale=1.0">
			<title>Activate Account</title>
			<style>
				/* CSS Reset & Centering */
				body, html {
					height: 100%;
					margin: 0;
					display: flex;
					align-items: center;
					justify-content: center;
					background-color: #f4f7f9;
					font-family: 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
				}

				/* Container */
				.container {
					background-color: #ffffff;
					padding: 40px;
					border-radius: 12px;
					box-shadow: 0 10px 25px rgba(0,0,0,0.05);
					text-align: center;
					max-width: 400px;
					width: 90%;
				}

				h2 {
					color: #1a1a1a;
					margin-bottom: 10px;
				}

				p {
					color: #666;
					font-size: 16px;
					margin-bottom: 30px;
					line-height: 1.5;
				}

				/* The Activation Button */
				.activate-btn {
					display: inline-block;
					background-color: #4f46e5; /* Modern Indigo */
					color: #ffffff;
					padding: 14px 32px;
					font-size: 16px;
					font-weight: 600;
					text-decoration: none;
					border-radius: 8px;
					transition: transform 0.2s, background-color 0.2s;
					border: none;
					cursor: pointer;
				}

				.activate-btn:hover {
					background-color: #4338ca;
					transform: translateY(-2px);
				}

				.activate-btn:active {
					transform: translateY(0);
				}
			</style>
		</head>
		<body>

			<div class="container">
				<h2>Account Activation</h2>
				<p>Activate your account by clicking the link below.</p>
				
				<a href="` + n.actEndpoint + link + `" class="activate-btn" id="linkBtn">
					Activate Account
				</a>
			</div>

			<script>
				// Simple JS to log the click (optional)
				document.getElementById('linkBtn').addEventListener('click', function() {
					console.log("Redirecting to activation URL...");
				});
			</script>

		</body>
		</html>
	`
}
