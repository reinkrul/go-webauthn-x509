package main

import (
	"github.com/reinkrul/go-webauthn-certificate/ca"
	"github.com/reinkrul/go-webauthn-certificate/http"
	"github.com/reinkrul/go-webauthn-certificate/users"
	"github.com/sirupsen/logrus"
)

func main() {
	var certificateAuthority ca.CertificateAuthority
	var server http.HTTPServer
	var users = users.NewUserDatabase()
	var err error
	caName := "Acme Corp."
	if certificateAuthority, err = ca.NewCertificateAuthority(caName); err != nil {
		logrus.Fatalf("Unable to create certificate authority: %v", err)
	}
	if server, err = http.NewHTTPServer(caName, users, certificateAuthority); err != nil {
		logrus.Fatalf("Unable to start HTTP server: %v", err)
	}
	server.Start()
}