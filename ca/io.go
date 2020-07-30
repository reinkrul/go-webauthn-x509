package ca

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"os"
)

const caCertFile = "ca-certificate.pem"
const caKeyFile = "ca-privatekey.pem"

func saveCertificateAndKey(certificate *x509.Certificate, privateKey crypto.PrivateKey) error {
	if err := ioutil.WriteFile(caCertFile, pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certificate.Raw,
	}), os.ModePerm); err != nil {
		return err
	}
	if pkcs8PrivateKey, err := x509.MarshalPKCS8PrivateKey(privateKey); err != nil {
		return err
	} else {
		if err := ioutil.WriteFile(caKeyFile, pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: pkcs8PrivateKey,
		}), os.ModePerm); err != nil {
			return err
		}
	}
	return nil
}

func loadCertificateAndKey() (*x509.Certificate, crypto.PrivateKey, error) {
	if !fileExists(caCertFile) || !fileExists(caKeyFile) {
		return nil, nil, nil
	}
	var certificate *x509.Certificate
	if certificateBytes, err := ioutil.ReadFile(caCertFile); err != nil {
		return nil, nil, err
	} else {
		block, _ := pem.Decode(certificateBytes)
		if certificate, err = x509.ParseCertificate(block.Bytes); err != nil {
			return nil, nil, err
		}
	}
	var privateKey interface{}
	if privateKeyBytes, err := ioutil.ReadFile(caKeyFile); err != nil {
		return nil, nil, err
	} else {
		block, _ := pem.Decode(privateKeyBytes)
		if privateKey, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
			return nil, nil, err
		}
	}
	return certificate, privateKey.(crypto.PrivateKey), nil
}

func fileExists(fileName string) bool {
	info, err := os.Stat(fileName)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}