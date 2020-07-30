package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	cose "github.com/duo-labs/webauthn/protocol/webauthncose"
	"math/big"
)

// ConvertWebAuthnPublicKey converts a WebAuthn PublicKey to a Go crypto RSA or EC public key.
func ConvertWebAuthnPublicKey(publicKey interface{}) (interface{}, error) {
	if pk, ok := publicKey.(cose.EC2PublicKeyData); ok {
		if curve, err := getCurveForCOSEAlgo(cose.COSEAlgorithmIdentifier(pk.Algorithm)); err != nil {
			return nil, err
		} else {
			return &ecdsa.PublicKey{
				Curve: curve,
				X:     big.NewInt(0).SetBytes(pk.XCoord),
				Y:     big.NewInt(0).SetBytes(pk.YCoord),
			}, nil
		}
	} else if pk, ok := publicKey.(cose.RSAPublicKeyData); ok {
		// Taken from protocol/webauthncose/webauthncose.go
		return &rsa.PublicKey{
			N: big.NewInt(0).SetBytes(pk.Modulus),
			E: int(uint(pk.Exponent[2]) | uint(pk.Exponent[1])<<8 | uint(pk.Exponent[0])<<16),
		}, nil
	} else {
		return nil, fmt.Errorf("unsupported COSE key type: %T", publicKey)
	}
}

func getCurveForCOSEAlgo(algo cose.COSEAlgorithmIdentifier) (elliptic.Curve, error) {
	// See https://www.iana.org/assignments/cose/cose.xhtml
	switch algo {
	case cose.AlgES256:
		return elliptic.P256(), nil
	case cose.AlgES384:
		return elliptic.P384(), nil
	case cose.AlgES512:
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("unsupported EC algorithm: %s", algo)
	}
}
