package users

import "github.com/duo-labs/webauthn/webauthn"

// TODO: mutexing

type repository struct {
	users map[UserID]*user
}

func (db *repository) Get(id UserID) User {
	user := db.users[id]
	return user
}

func (db *repository) Add(fullName string) User {
	newUser := user{
		id:          NewUserID(),
		fullName:    fullName,
		credentials: []webauthn.Credential{},
	}
	db.users[newUser.id] = &newUser
	return &newUser
}
