package http

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/gob"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/duo-labs/webauthn/protocol/webauthncose"
	"github.com/duo-labs/webauthn/webauthn"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/reinkrul/go-webauthn-certificate/ca"
	"github.com/reinkrul/go-webauthn-certificate/users"
	"github.com/sirupsen/logrus"
	"log"
	"net"
	"net/http"
)

const sessionKey = "registration"

type RegistrationRequest struct {
	FullName string
}

func NewHTTPServer(name string, users users.Repository, ca ca.CertificateAuthority) (HTTPServer, error) {
	server := httpServer{
		address: "localhost:8080",
		users:   users,
		ca:      ca,
	}
	if host, _, err := net.SplitHostPort(server.address); err != nil {
		return nil, err
	} else {
		if server.webAuthn, err = webauthn.New(&webauthn.Config{
			RPDisplayName: name,
			RPID:          host,
			RPOrigin:      "http://" + host,
		}); err != nil {
			return nil, err
		}
	}
	server.sessions = sessions.NewCookieStore([]byte("unsafe for production"))
	return &server, nil
}

type HTTPServer interface {
	Start()
}

type httpServer struct {
	address  string
	users    users.Repository
	ca       ca.CertificateAuthority
	webAuthn *webauthn.WebAuthn
	sessions sessions.Store
}

func (h *httpServer) Start() {
	logrus.Infof("Starting HTTP server on: %s", h.address)

	gob.Register(webauthn.SessionData{})
	r := mux.NewRouter()
	r.HandleFunc("/registration", h.beginRegistration).Methods("POST")
	r.HandleFunc("/registration/{id}", h.finishRegistration).Methods("POST")
	//r.HandleFunc("/login/start/{username}", BeginLogin).Methods("POST")
	//r.HandleFunc("/login/finish/{username}", FinishLogin).Methods("POST")
	r.HandleFunc("/user/{id}/certificate", h.getCertificate).Methods("GET")
	r.PathPrefix("/").Handler(http.FileServer(http.Dir("./web")))

	log.Fatal(http.ListenAndServe(h.address, r))
}

func (h *httpServer) beginRegistration(response http.ResponseWriter, request *http.Request) {
	registrationRequest := RegistrationRequest{}
	if err := unmarshalJsonRequest(request, &registrationRequest); err != nil {
		handleError(response, err)
		return
	}
	logrus.Infof("Begin registration for user: %s", registrationRequest.FullName)
	// TODO: Validate request?
	newUser := h.users.Add(registrationRequest.FullName)
	if options, sessionData, err := h.webAuthn.BeginRegistration(newUser); err != nil {
		handleError(response, err)
		return
	} else {
		if session, err := h.sessions.Get(request, sessionKey); err != nil {
			handleError(response, err)
			return
		} else {
			session.Values[sessionKey] = *sessionData
			if err = session.Save(request, response); err != nil {
				handleError(response, err)
				return
			}
		}
		if err := marshalResponse(response, options); err != nil {
			handleError(response, err)
			return
		}
	}
}

func (h *httpServer) finishRegistration(response http.ResponseWriter, request *http.Request) {
	vars := mux.Vars(request)
	var user users.User
	if id, err := users.UserIDFromString(vars["id"]); err != nil {
		handleError(response, fmt.Errorf("missing/invalid id: %w", err))
		return
	} else {
		user = h.users.Get(id)
	}

	var sessionData webauthn.SessionData
	if session, err := h.sessions.Get(request, sessionKey); err != nil {
		handleError(response, err)
		return
	} else {
		var ok bool
		if sessionData, ok = session.Values[sessionKey].(webauthn.SessionData); !ok {
			handleError(response, errors.New("unable to unmarshal registration session data"))
			return
		}
	}
	if credential, err := h.webAuthn.FinishRegistration(user, sessionData, request); err != nil {
		handleError(response, err)
		return
	} else {
		logrus.Info("Registration successful")
		user.AddCredential(*credential)
		if err = h.issueCertificate(user, credential); err != nil {
			handleError(response, fmt.Errorf("unable to issue certificate: %w", err))
		}
	}
}

func (h *httpServer) issueCertificate(user users.User, credential *webauthn.Credential) error {
	var publicKey interface{}
	if pk, err := webauthncose.ParsePublicKey(credential.PublicKey); err != nil {
		return fmt.Errorf("unable to parse public key: %w", err)
	} else if publicKey, err = ca.ConvertWebAuthnPublicKey(pk); err != nil {
		return fmt.Errorf("unable to convert public key: %w", err)
	}
	if certificate, err := h.ca.IssueCertificate(pkix.Name{CommonName: user.WebAuthnDisplayName()}, publicKey); err != nil {
		return err
	} else {
		user.AddCertificate(certificate)
	}
	return nil
}

func (h *httpServer) getCertificate(response http.ResponseWriter, request *http.Request) {
	vars := mux.Vars(request)
	var user users.User
	if id, err := users.UserIDFromString(vars["id"]); err != nil {
		handleError(response, fmt.Errorf("missing/invalid id: %w", err))
		return
	} else {
		user = h.users.Get(id)
	}
	pemAsBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: user.GetCertificate().Raw,
	})
	response.Header().Add("Content-Type", "application/x-pem-file")
	response.Header().Add("Content-Disposition", `attachment;filename="` + user.WebAuthnDisplayName() + `.pem"`)
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(pemAsBytes)
}

func handleError(response http.ResponseWriter, err error) {
	logrus.Errorf("An error occurred: %v", err)
	response.Header().Add("Content-Type", "text/plain")
	http.Error(response, err.Error(), http.StatusInternalServerError)
}

func unmarshalJsonRequest(request *http.Request, body interface{}) error {
	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(request.Body); err != nil {
		return err
	}
	return json.Unmarshal(buf.Bytes(), body)
}

//
//func BeginLogin(w http.ResponseWriter, r *http.Request) {
//
//	// get username
//	vars := mux.Vars(r)
//	username := vars["username"]
//
//	// get user
//	user, err := userDB.GetUser(username)
//
//	// user doesn't exist
//	if err != nil {
//		log.Println(err)
//		marshalResponse(w, err.Error(), http.StatusBadRequest)
//		return
//	}
//
//	// generate PublicKeyCredentialRequestOptions, session data
//	options, sessionData, err := webAuthn.BeginLogin(user)
//	if err != nil {
//		log.Println(err)
//		marshalResponse(w, err.Error(), http.StatusInternalServerError)
//		return
//	}
//
//	// store session data as marshaled JSON
//	err = sessionStore.SaveWebauthnSession("authentication", sessionData, r, w)
//	if err != nil {
//		log.Println(err)
//		marshalResponse(w, err.Error(), http.StatusInternalServerError)
//		return
//	}
//
//	marshalResponse(w, options, http.StatusOK)
//}
//
//func FinishLogin(w http.ResponseWriter, r *http.Request) {
//
//	// get username
//	vars := mux.Vars(r)
//	username := vars["username"]
//
//	// get user
//	user, err := userDB.GetUser(username)
//
//	// user doesn't exist
//	if err != nil {
//		log.Println(err)
//		marshalResponse(w, err.Error(), http.StatusBadRequest)
//		return
//	}
//
//	// load the session data
//	sessionData, err := sessionStore.GetWebauthnSession("authentication", r)
//	if err != nil {
//		log.Println(err)
//		marshalResponse(w, err.Error(), http.StatusBadRequest)
//		return
//	}
//
//	// in an actual implementation, we should perform additional checks on
//	// the returned 'credential', i.e. check 'credential.Authenticator.CloneWarning'
//	// and then increment the credentials counter
//	_, err = webAuthn.FinishLogin(user, sessionData, r)
//	if err != nil {
//		log.Println(err)
//		marshalResponse(w, err.Error(), http.StatusBadRequest)
//		return
//	}
//
//	// handle successful login
//	marshalResponse(w, "Login Success", http.StatusOK)
//}

func marshalResponse(response http.ResponseWriter, body interface{}) error {
	if data, err := json.Marshal(body); err != nil {
		return err
	} else {
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(http.StatusOK)
		_, _ = response.Write(data)
		return nil
	}
}
