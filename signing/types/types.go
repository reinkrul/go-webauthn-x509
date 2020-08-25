package types

import "github.com/reinkrul/go-webauthn-certificate/signing"

type DocumentProcessor func(document interface{}, privateKey signing.RemotePrivateKey) ([]byte, error)

type DocumentType struct {
	Processor     DocumentProcessor
	FileExtension string
	MimeType      string
}

