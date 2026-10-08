package service

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/smtp"
)

// Mailer delivers an email. LogMailer is the dev default (EMAIL_DRIVER=log).
type Mailer interface {
	Send(ctx context.Context, to, subject, body string) error
}

// LogMailer prints the email to the server log — dev default, no SMTP needed.
type LogMailer struct{}

func (LogMailer) Send(_ context.Context, to, subject, body string) error {
	log.Printf("[EMAIL] to=%s subject=%q\n%s", to, subject, body)
	return nil
}

// SMTPMailer sends via SMTP with STARTTLS when the server advertises it
// (net/smtp behaviour). PlainAuth refuses unencrypted non-local connections.
type SMTPMailer struct {
	Host     string
	Port     string // default 587
	User     string
	Password string
	From     string
}

func (m SMTPMailer) Send(_ context.Context, to, subject, body string) error {
	port := m.Port
	if port == "" {
		port = "587"
	}
	addr := net.JoinHostPort(m.Host, port)

	var auth smtp.Auth
	if m.User != "" {
		auth = smtp.PlainAuth("", m.User, m.Password, m.Host)
	}

	msg := fmt.Sprintf(
		"From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s",
		m.From, to, subject, body,
	)
	return smtp.SendMail(addr, auth, m.From, []string{to}, []byte(msg))
}
