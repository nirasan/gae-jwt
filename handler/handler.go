package handler

import (
	"encoding/json"
	"fmt"
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
	r.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "hello world")
	})
	r.HandleFunc("/registration", RegistrationHandler)
	r.HandleFunc("/authentication", AuthenticationHandler)
	r.HandleFunc("/authorization", AuthorizationHandler)
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

type AuthorizationHandlerResponse struct {
	Success bool
}

func AuthorizationHandler(w http.ResponseWriter, r *http.Request) {

	header := r.Header.Get("Authorization")
	if header == "" {
		panic("Invalid authorization hader")
	}

	parts := strings.SplitN(header, " ", 2)
	if !(len(parts) == 2 && parts[0] == "Bearer") {
		panic("Invalid authorization hader")
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
		panic(e.Error())
	}

	if _, ok := token.Claims.(jwt.MapClaims); !ok || !token.Valid {
		panic("Invalid token")
		return
	}

	EncodeJson(w, AuthorizationHandlerResponse{Success: true})
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
