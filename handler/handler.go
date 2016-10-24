package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/nirasan/gae-jwt/bindata"
	"strings"
	"github.com/pkg/errors"
)

func NewHandler() http.Handler {
	r := mux.NewRouter()
	r.HandleFunc("/registration", RegistrationHandler)
	r.HandleFunc("/authentication", AuthenticationHandler)
	r.HandleFunc("/authorized_hello", AuthorizedHelloWorldHandler)
	r.HandleFunc("/hello", HelloWorldHandler)
	return r
}

type RegistrationHandlerRequest struct {
	Username string
	Password string
}

type RegistrationHandlerResponse struct {
	Success bool
}

var userTable = make(map[string]string)

func RegistrationHandler(w http.ResponseWriter, r *http.Request) {
	var req RegistrationHandlerRequest
	DecodeJson(r, &req)
	userTable[req.Username] = req.Password
	EncodeJson(w, RegistrationHandlerResponse{Success: true})
}

type AuthenticationHandlerRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type AuthenticationHandlerResponse struct {
	Success bool
	Token   string
}

func AuthenticationHandler(w http.ResponseWriter, r *http.Request) {
	var req AuthenticationHandlerRequest
	DecodeJson(r, &req)
	if password, ok := userTable[req.Username]; !ok || password != req.Password {
		EncodeJson(w, AuthenticationHandlerResponse{Success: false})
		return
	}
	method := jwt.GetSigningMethod("ES256")
	token := jwt.NewWithClaims(method, jwt.MapClaims{
		"sub": req.Username,
		"exp": time.Now().Add(time.Hour * 1).Unix(),
	})
	pem, e := bindata.Asset("assets/ec256-key-pri.pem")
	if e != nil {
		panic(e.Error())
	}
	key, e := jwt.ParseECPrivateKeyFromPEM(pem)
	if e != nil {
		panic(e.Error())
	}
	signedToken, e := token.SignedString(key)
	if e != nil {
		panic(e.Error())
	}
	EncodeJson(w, AuthenticationHandlerResponse{Success: true, Token: signedToken})
}

type HelloWorldHandlerResponse struct {
	Success bool
	Message string
}

func HelloWorldHandler(w http.ResponseWriter, r *http.Request) {
	EncodeJson(w, HelloWorldHandlerResponse{Success: true, Message: "Hello World"})
}

func AuthorizedHelloWorldHandler(w http.ResponseWriter, r *http.Request) {
	token, e := Authorization(r)

	if e != nil {
		EncodeJson(w, HelloWorldHandlerResponse{Success: false})
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		EncodeJson(w, HelloWorldHandlerResponse{Success: true, Message: "Hello " + claims["sub"].(string)})
	}
}

func Authorization(r *http.Request) (*jwt.Token, error) {

	header := r.Header.Get("Authorization")
	if header == "" {
		return nil, errors.New("Invalid authorization hader")
	}

	parts := strings.SplitN(header, " ", 2)
	if !(len(parts) == 2 && parts[0] == "Bearer") {
		return nil, errors.New("Invalid authorization hader")
	}

	token, e := jwt.Parse(parts[1], func(t *jwt.Token) (interface{}, error){
		method := jwt.GetSigningMethod("ES256")
		if method != t.Method {
			return nil, errors.New("Invalid signing method")
		}
		pem, e := bindata.Asset("assets/ec256-key-pub.pem")
		if e != nil {
			return nil, e
		}
		key, e := jwt.ParseECPublicKeyFromPEM(pem)
		if e != nil {
			return nil, e
		}
		return key, nil
	})
	if e != nil {
		return nil, errors.New(e.Error())
	}

	if _, ok := token.Claims.(jwt.MapClaims); !ok || !token.Valid {
		return nil, errors.New("Invalid token")
	}

	return token, nil
}

func DecodeJson(r *http.Request, data interface{}) {
	decoder := json.NewDecoder(r.Body)
	defer r.Body.Close()
	if e := decoder.Decode(data); e != nil {
		panic(e.Error())
	}
}

func EncodeJson(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}
