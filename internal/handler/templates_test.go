package handler

import (
	"bytes"
	"html/template"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func getTestTemplate(t *testing.T) *template.Template {
	t.Helper()
	pattern := filepath.Join(templatesDir(), "*.html")
	tmpl, err := template.ParseGlob(pattern)
	if err != nil {
		t.Fatalf("parse templates: %v", err)
	}
	return tmpl
}

func TestRenderTemplate_Signup(t *testing.T) {
	tmpl := getTestTemplate(t)
	w := httptest.NewRecorder()
	if err := tmpl.ExecuteTemplate(w, "signup.html", map[string]string{}); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(w.Body.String(), "Create your account") {
		t.Error("signup template missing title")
	}
	if !strings.Contains(w.Body.String(), `action="/signup-form"`) {
		t.Error("signup form should POST to /signup-form")
	}
}

func TestRenderTemplate_Login(t *testing.T) {
	tmpl := getTestTemplate(t)
	w := httptest.NewRecorder()
	if err := tmpl.ExecuteTemplate(w, "login.html", map[string]string{}); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(w.Body.String(), "Log in to your account") {
		t.Error("login template missing title")
	}
	if !strings.Contains(w.Body.String(), `action="/login-form"`) {
		t.Error("login form should POST to /login-form")
	}
}

func TestRenderTemplate_CheckEmail(t *testing.T) {
	tmpl := getTestTemplate(t)
	w := httptest.NewRecorder()
	if err := tmpl.ExecuteTemplate(w, "check-email.html", map[string]string{"Email": "test@example.com"}); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(w.Body.String(), "test@example.com") {
		t.Error("check-email template should show email")
	}
}

func TestRenderTemplate_VerifySuccess(t *testing.T) {
	tmpl := getTestTemplate(t)
	w := httptest.NewRecorder()
	if err := tmpl.ExecuteTemplate(w, "verify-success.html", map[string]string{}); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(w.Body.String(), "Email verified") {
		t.Error("verify-success template missing title")
	}
}

func TestRenderTemplate_VerifyExpired(t *testing.T) {
	tmpl := getTestTemplate(t)
	w := httptest.NewRecorder()
	if err := tmpl.ExecuteTemplate(w, "verify-expired.html", map[string]string{}); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(w.Body.String(), "link expired") {
		t.Error("verify-expired template missing title")
	}
}

func TestRenderTemplate_ForgotPassword(t *testing.T) {
	tmpl := getTestTemplate(t)
	w := httptest.NewRecorder()
	if err := tmpl.ExecuteTemplate(w, "forgot-password.html", map[string]bool{"Success": false}); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(w.Body.String(), "Reset your password") {
		t.Error("forgot-password template missing title")
	}
	if !strings.Contains(w.Body.String(), `action="/forgot-password-form"`) {
		t.Error("forgot-password form should POST to /forgot-password-form")
	}
}

func TestRenderTemplate_ResetPassword(t *testing.T) {
	tmpl := getTestTemplate(t)
	w := httptest.NewRecorder()
	if err := tmpl.ExecuteTemplate(w, "reset-password.html", map[string]string{"Token": "abc123"}); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(w.Body.String(), "Set new password") {
		t.Error("reset-password template missing title")
	}
	if !strings.Contains(w.Body.String(), "abc123") {
		t.Error("reset-password template missing token")
	}
}

func TestRenderTemplate_Authorize(t *testing.T) {
	tmpl := getTestTemplate(t)
	w := httptest.NewRecorder()
	if err := tmpl.ExecuteTemplate(w, "authorize.html", map[string]string{
		"ClientName": "My App",
	}); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(w.Body.String(), "My App") {
		t.Error("authorize template should show client name")
	}
}

func TestRenderTemplate_LinkAccount(t *testing.T) {
	tmpl := getTestTemplate(t)
	w := httptest.NewRecorder()
	if err := tmpl.ExecuteTemplate(w, "link-account.html", map[string]string{
		"Provider": "google",
		"Email":    "user@example.com",
	}); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(w.Body.String(), "google") {
		t.Error("link-account template should show provider")
	}
	if !strings.Contains(w.Body.String(), "user@example.com") {
		t.Error("link-account template should show email")
	}
}

func TestRenderTemplate_WithError(t *testing.T) {
	tmpl := getTestTemplate(t)
	w := httptest.NewRecorder()
	if err := tmpl.ExecuteTemplate(w, "signup.html", map[string]string{
		"Error": "Something went wrong",
	}); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(w.Body.String(), "Something went wrong") {
		t.Error("template should display error message")
	}
}

func TestRenderTemplate_WithClientName(t *testing.T) {
	tmpl := getTestTemplate(t)
	w := httptest.NewRecorder()
	if err := tmpl.ExecuteTemplate(w, "authorize.html", map[string]string{
		"ClientName": "Acme Corp",
	}); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(w.Body.String(), "Acme Corp") {
		t.Error("template should show 'Continue to Acme Corp'")
	}
}

func TestTemplate_DarkThemeColors(t *testing.T) {
	tmpl := getTestTemplate(t)
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "signup.html", map[string]string{}); err != nil {
		t.Fatalf("execute: %v", err)
	}
	html := buf.String()
	if !strings.Contains(html, "#0F1319") {
		t.Error("template should use dark background #0F1319")
	}
	if !strings.Contains(html, "#171D26") {
		t.Error("template should use card background #171D26")
	}
	if !strings.Contains(html, "#5FD9C0") {
		t.Error("template should use primary color #5FD9C0")
	}
}
