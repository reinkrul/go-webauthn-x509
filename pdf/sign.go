package pdf

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/sirupsen/logrus"
	"github.com/unidoc/unipdf/v3/annotator"
	"github.com/unidoc/unipdf/v3/core"
	"github.com/unidoc/unipdf/v3/model"
	"io"
	"sync"
	"time"
)

type OutOfBandPDFSigner struct {
	dataToBeSigned chan []byte
	signature      chan []byte
	signedPDF      chan []byte
	err            chan error
	completed      bool
	mux            *sync.Mutex

	certificate *x509.Certificate
	name        string
	pdfBytes    []byte
	reason      string
}

func NewOutOfBandPDFSigner(pdfBytes []byte, name string, reason string, certificate *x509.Certificate) *OutOfBandPDFSigner {
	return &OutOfBandPDFSigner{
		dataToBeSigned: make(chan []byte, 1),
		signature:      make(chan []byte, 1),
		signedPDF:      make(chan []byte, 1),
		err:            make(chan error, 1),
		mux:            new(sync.Mutex),
		certificate:    certificate,
		name:           name,
		reason:         reason,
		pdfBytes:       pdfBytes,
	}
}

// Start starts the out of band signing process. If successful it returns the data to be signed.
func (o *OutOfBandPDFSigner) Start() ([]byte, error) {
	go func() {
		if signedPDF, err := o.sign(o.name, o.reason, o.pdfBytes, o.certificate); err != nil {
			o.err <- err
		} else {
			o.signedPDF <- signedPDF
		}
	}()
	select {
	case dataToBeSigned := <-o.dataToBeSigned:
		return dataToBeSigned, nil
	case err := <-o.err:
		return nil, err
	}
}

func (o *OutOfBandPDFSigner) Complete(signature []byte) ([]byte, error) {
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
	case signedPDF := <-o.signedPDF:
		return signedPDF, nil
	case err := <-o.err:
		return nil, err
	}
}

// sign signs the specified input PDF file using an adobeX509ECDSA signature handler
// and saves the result at the destination specified by the outputPath parameter.
//func sign(priv *crypto11.PKCS11PrivateKeyRSA, certificate *x509.Certificate, inputPath, outputPath string) error {
func (o *OutOfBandPDFSigner) sign(name string, reason string, pdfBytes []byte, certificate *x509.Certificate) ([]byte, error) {
	// Create reader.
	reader, err := model.NewPdfReader(bytes.NewReader(pdfBytes))
	if err != nil {
		return nil, err
	}
	appender, err := model.NewPdfAppender(reader)
	if err != nil {
		return nil, err
	}

	// Create custom signature handler.
	signer := webAuthnSigner{session: o}
	handler, err := NewAdobePKCS7Detached(signer, certificate)
	if err != nil {
		return nil, fmt.Errorf("unable to create PKCS7 detached signature: %w", err)
	}

	// Create signature.
	signature := model.NewPdfSignature(handler)
	signature.SetName(name)
	signature.SetReason(reason)
	signature.SetDate(time.Now(), "")

	if err := signature.Initialize(); err != nil {
		return nil, err
	}

	// Create signature field and appearance.
	opts := annotator.NewSignatureFieldOpts()
	opts.FontSize = 10
	opts.Rect = []float64{10, 25, 75, 60}

	sigField, err := annotator.NewSignatureField(
		signature,
		[]*annotator.SignatureLine{
			annotator.NewSignatureLine("Name", o.name),
			annotator.NewSignatureLine("Date", time.Now().String()),
			annotator.NewSignatureLine("Reason", reason),
		},
		opts,
	)
	if err != nil {
		return nil, err
	}
	sigField.T = core.MakeString("External signature")

	// Sign PDF.
	if err = appender.Sign(1, sigField); err != nil {
		return nil, err
	}

	buf := new(bytes.Buffer)
	if err := appender.Write(buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

type webAuthnSigner struct {
	session *OutOfBandPDFSigner
}

func (o webAuthnSigner) Public() crypto.PublicKey {
	return o.session.certificate.PublicKey
}

func (o webAuthnSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	// TODO: Time-out (avoid leaking goroutines which are never signed)
	// TODO: check hash func with yubikey
	logrus.Info("Returning DataToBeSigned")
	o.session.dataToBeSigned <- digest
	logrus.Info("Waiting for Signature")
	return <-o.session.signature, nil
}
