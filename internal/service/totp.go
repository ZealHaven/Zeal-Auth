package service

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// Minimal TOTP (RFC 6238, SHA1, 6 digits, 30s step) — stdlib only.
// ponytail: swap for github.com/pquerna/otp if QR rendering/APP args needed.

const (
	totpStep   = 30
	totpDigits = 6
	// totpWindow accepts codes one step before/after to tolerate clock skew.
	totpWindow = 1
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateTOTPSecret returns a new base32 TOTP secret (160 bits).
func GenerateTOTPSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return b32.EncodeToString(b), nil
}

// ValidateTOTP reports whether code is valid for secret at time now.
func ValidateTOTP(secret, code string, now time.Time) bool {
	secret = strings.ToUpper(strings.TrimSpace(secret))
	code = strings.TrimSpace(code)
	if len(code) != totpDigits {
		return false
	}
	key, err := b32.DecodeString(secret)
	if err != nil {
		return false
	}
	counter := uint64(now.Unix() / totpStep)
	for w := -totpWindow; w <= totpWindow; w++ {
		if hotp(key, counter+uint64(w)) == code {
			return true
		}
	}
	return false
}

// ComputeTOTP returns the current valid code for secret (tests + enrollment UX).
func ComputeTOTP(secret string, now time.Time) string {
	key, err := b32.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return ""
	}
	return hotp(key, uint64(now.Unix()/totpStep))
}

func hotp(key []byte, counter uint64) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	bin := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%0*d", totpDigits, bin%pow10(totpDigits))
}

func pow10(n int) uint32 {
	p := uint32(1)
	for i := 0; i < n; i++ {
		p *= 10
	}
	return p
}

// TOTPProvisioningURI builds the otpauth:// URI apps scan (label = email).
func TOTPProvisioningURI(issuer, email, secret string) string {
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&digits=%d&period=%d",
		issuer, email, secret, issuer, totpDigits, totpStep)
}

// GenerateRecoveryCodes returns n single-use plain codes; caller stores hashes.
func GenerateRecoveryCodes(n int) ([]string, error) {
	out := make([]string, n)
	for i := range out {
		b := make([]byte, 5) // 10 hex chars
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		out[i] = fmt.Sprintf("%x", b)
	}
	return out, nil
}
