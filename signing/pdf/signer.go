package pdf

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/reinkrul/go-webauthn-certificate/signing"
	"github.com/reinkrul/go-webauthn-certificate/signing/types"
	"github.com/unidoc/unipdf/v3/annotator"
	"github.com/unidoc/unipdf/v3/core"
	"github.com/unidoc/unipdf/v3/model"
	"time"
)


var Processor types.DocumentProcessor = signPDF

// sign signs the specified input PDF file using an adobeX509ECDSA signature handler
// and saves the result at the destination specified by the outputPath parameter.
//func sign(priv *crypto11.PKCS11PrivateKeyRSA, certificate *x509.Certificate, inputPath, outputPath string) error {
func signPDF(document interface{}, privateKey signing.RemotePrivateKey) ([]byte, error) {
	// Create reader.
	documentAsBytes, ok := document.([]byte)
	if !ok {
		return nil, errors.New("document should be []byte")
	}
	reader, err := model.NewPdfReader(bytes.NewReader(documentAsBytes))
	if err != nil {
		return nil, err
	}
	appender, err := model.NewPdfAppender(reader)
	if err != nil {
		return nil, err
	}

	// Create custom signature handler.
	handler, err := NewAdobePKCS7Detached(privateKey, privateKey.Certificate)
	if err != nil {
		return nil, fmt.Errorf("unable to create PKCS7 detached signature: %w", err)
	}

	// Create signature.
	name := privateKey.Certificate.Subject.CommonName
	reason := "Signed using WebAuthn token"
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
			annotator.NewSignatureLine("Name", name),
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
