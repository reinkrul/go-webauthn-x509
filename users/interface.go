package users

import (
	"crypto/x509"
	"encoding/binary"
	"github.com/duo-labs/webauthn/webauthn"
	"math/rand"
	"strconv"
)

func NewUserDatabase() Repository {
	return &repository{users: make(map[UserID]*user, 0)}
}

type UserID uint64

func NewUserID() UserID {
	buf := make([]byte, 8)
	rand.Read(buf)
	return UserID(binary.BigEndian.Uint64(buf))
}

func UserIDFromString(input string) (UserID, error) {
	if i, err := strconv.ParseInt(input, 10, 64); err != nil {
		return 0, err
	} else {
		return UserID(i), nil
	}
}

func (u UserID) Bytes() []byte {
	buf := make([]byte, binary.MaxVarintLen64)
	binary.BigEndian.PutUint64(buf, uint64(u))
	return buf
}

type User interface {
	webauthn.User
	AddCredential(credential webauthn.Credential)
	AddCertificate(certificate *x509.Certificate)
	GetCertificate() *x509.Certificate
}

type Repository interface {
	Add(name string) User
	Get(id UserID) User
}