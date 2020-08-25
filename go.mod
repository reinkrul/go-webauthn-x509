module github.com/reinkrul/go-webauthn-certificate

go 1.14

require (
	github.com/amdonov/xmlsig v0.1.0
	github.com/duo-labs/webauthn v0.0.0-20190926021235-9562c88a0899
	github.com/duo-labs/webauthn.io v0.0.0-20190926134215-35f44a73518f
	github.com/google/go-tpm v0.1.0 // indirect
	github.com/gorilla/mux v1.7.1
	github.com/gorilla/sessions v1.2.0
	github.com/jinzhu/gorm v1.9.11 // indirect
	github.com/satori/go.uuid v1.2.0
	github.com/sirupsen/logrus v1.6.0
	github.com/unidoc/pkcs7 v0.0.0-20200411230602-d883fd70d1df
	github.com/unidoc/unipdf/v3 v3.9.0
)

replace github.com/unidoc/pkcs7 => ../pkcs7
