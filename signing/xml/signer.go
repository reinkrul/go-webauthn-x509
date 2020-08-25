package xml

import (
	"bytes"
	"crypto/tls"
	"encoding/xml"
	"errors"
	"github.com/amdonov/xmlsig"
	"github.com/reinkrul/go-webauthn-certificate/signing"
	"github.com/reinkrul/go-webauthn-certificate/signing/types"
)

var Processor types.DocumentProcessor = signXML

type SignatureContainer interface {
	SetSignature(signature *xmlsig.Signature)
}

func signXML(document interface{}, privateKey signing.RemotePrivateKey) ([]byte, error) {
	if _, ok := document.(SignatureContainer); !ok {
		return nil, errors.New("document should implement SignatureContainer")
	}

	signer, err := xmlsig.NewSigner(tls.Certificate{
		Certificate: [][]byte{privateKey.Certificate.Raw},
		PrivateKey:  privateKey,
	})
	if err != nil {
		return nil, err
	}
	if sig, err := signer.CreateSignature(document); err != nil {
		return nil, err
	} else {
		(document.(SignatureContainer)).SetSignature(sig)
	}
	buf := new(bytes.Buffer)
	if err := xml.NewEncoder(buf).Encode(document); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
