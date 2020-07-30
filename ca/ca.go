package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"github.com/sirupsen/logrus"
	"math/big"
	"time"
)

type CertificateAuthority interface {
	IssueCertificate(subject pkix.Name, key crypto.PublicKey) (*x509.Certificate, error)
}

func NewCertificateAuthority(name string) (CertificateAuthority, error) {
	certAuth := &certificateAuthority{}
	if err := certAuth.initialize(name); err != nil {
		return nil, err
	}
	return certAuth, nil
}

type certificateAuthority struct {
	name        string
	privateKey  crypto.PrivateKey
	certificate *x509.Certificate
}

func (ca *certificateAuthority) IssueCertificate(subject pkix.Name, key crypto.PublicKey) (*x509.Certificate, error) {
	logrus.Infof("Issuing certificate to %s", subject)
	template := &x509.Certificate{
		PublicKey:    key,
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(0, 0, 7),
		KeyUsage:     x509.KeyUsageContentCommitment | x509.KeyUsageDigitalSignature,
	}
	certificateAsASN1, err := x509.CreateCertificate(rand.Reader, template, ca.certificate, key, ca.privateKey)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(certificateAsASN1)
}

func (ca *certificateAuthority) initialize(name string) error {
	ca.name = name
	var err error
	if ca.certificate, ca.privateKey, err = loadCertificateAndKey(); err != nil {
		return err
	} else if ca.certificate == nil || ca.privateKey == nil {
		logrus.Info("Generating new CA certificate and key")
		if ca.privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
			return err
		}
		subject := pkix.Name{
			Country:      []string{"NL"},
			Organization: []string{ca.name},
			CommonName:   ca.name + " Root CA",
		}
		certificate := &x509.Certificate{
			PublicKey:             (ca.privateKey.(crypto.Signer)).Public(),
			SerialNumber:          big.NewInt(time.Now().UnixNano()),
			Issuer:                subject,
			Subject:               subject,
			NotBefore:             time.Now(),
			NotAfter:              time.Now().AddDate(0, 0, 365),
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
			BasicConstraintsValid: true,
			IsCA:                  true,
		}
		certificateAsASN1, err := x509.CreateCertificate(rand.Reader, certificate, certificate, certificate.PublicKey, ca.privateKey)
		if err != nil {
			return err
		}
		if ca.certificate, err = x509.ParseCertificate(certificateAsASN1); err != nil {
			return err
		}
		return saveCertificateAndKey(ca.certificate, ca.privateKey)
	}
	logrus.Info("CA certificate and key loaded")
	return nil
}
