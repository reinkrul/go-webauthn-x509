package users

import (
	"crypto/x509"
	"github.com/duo-labs/webauthn/webauthn"
)

type user struct {
	id           UserID
	fullName     string
	credentials  []webauthn.Credential
	certificates []*x509.Certificate
}

func (u *user) GetCertificate() *x509.Certificate {
	if len(u.certificates) == 0 {
		return nil
	}
	return u.certificates[len(u.certificates) - 1]
}

func (u *user) AddCertificate(certificate *x509.Certificate) {
	u.certificates = append(u.certificates, certificate)
}

func (u user) WebAuthnID() []byte {
	return u.id.Bytes()
}

func (u user) WebAuthnName() string {
	return u.fullName
}

func (u user) WebAuthnDisplayName() string {
	return u.fullName
}

func (u user) WebAuthnIcon() string {
	return ""
}

func (u user) WebAuthnCredentials() []webauthn.Credential {
	return append(u.credentials) // clones slice
}

func (u user) GetCredentials() []webauthn.Credential {
	return append(u.credentials) // clones slice
}

func (u *user) AddCredential(credential webauthn.Credential) {
	u.credentials = append(u.credentials, credential)
}
