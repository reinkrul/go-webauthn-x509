package signing

import (
	"crypto"
	"crypto/x509"
	"errors"
	"github.com/reinkrul/go-webauthn-certificate/signing/pdf"
	"github.com/reinkrul/go-webauthn-certificate/signing/types"
	"github.com/reinkrul/go-webauthn-certificate/signing/xml"
	"github.com/sirupsen/logrus"
	"io"
	"sync"
)

type OutOfBandDocumentSigner struct {
	dataToBeSigned chan []byte
	signature      chan []byte
	signedDocument chan []byte
	err            chan error
	completed      bool
	mux            *sync.Mutex

	certificate      *x509.Certificate
	unsignedDocument interface{}
	reason           string
}

func NewOutOfBandDocumentSigner(certificate *x509.Certificate, unsignedDocument interface{}) *OutOfBandDocumentSigner {
	return &OutOfBandDocumentSigner{
		dataToBeSigned:   make(chan []byte, 1),
		signature:        make(chan []byte, 1),
		signedDocument:   make(chan []byte, 1),
		err:              make(chan error, 1),
		mux:              new(sync.Mutex),
		certificate:      certificate,
		unsignedDocument: unsignedDocument,
	}
}

// Start starts the out of band signing process. If successful it returns the data to be signed.
func (o *OutOfBandDocumentSigner) Start(processor types.DocumentProcessor) ([]byte, error) {
	go func() {
		if signedDocument, err := processor(o.unsignedDocument, RemotePrivateKey{
			Certificate: o.certificate,
			session:     o,
		}); err != nil {
			o.err <- err
		} else {
			o.signedDocument <- signedDocument
		}
	}()
	select {
	case dataToBeSigned := <-o.dataToBeSigned:
		return dataToBeSigned, nil
	case err := <-o.err:
		return nil, err
	}
}

func (o *OutOfBandDocumentSigner) Complete(signature []byte) ([]byte, error) {
	// Make sure only the first call to Complete() is accepted in a non-blocking manner
	o.mux.Lock()
	if o.completed {
		o.mux.Unlock()
		return nil, errors.New("signing transaction already completed")
	}
	o.completed = true
	o.mux.Unlock()
	o.signature <- signature
	select {
	case signedDocument := <-o.signedDocument:
		return signedDocument, nil
	case err := <-o.err:
		return nil, err
	}
}

type RemotePrivateKey struct {
	Certificate *x509.Certificate
	session     *OutOfBandDocumentSigner
}

func (o RemotePrivateKey) Public() crypto.PublicKey {
	return o.session.certificate.PublicKey
}

func (o RemotePrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	// TODO: Time-out (avoid leaking goroutines which are never signed)
	// TODO: check hash func with yubikey
	logrus.Info("Returning DataToBeSigned")
	o.session.dataToBeSigned <- digest
	logrus.Info("Waiting for Signature")
	return <-o.session.signature, nil
}

func DocumentTypes() map[string]types.DocumentType {
	types := []types.DocumentType{
		{Processor: xml.Processor, MimeType: "text/xml", FileExtension: "xml"},
		{Processor: pdf.Processor, MimeType: "application/pdf", FileExtension: "pdf"},
	}
	result := make(map[string]types.DocumentType, 0)
	for _, documentType := range types {
		result[documentType.MimeType] = documentType
	}
	return result
}
