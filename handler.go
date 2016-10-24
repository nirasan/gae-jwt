package gae_jwt

import (
	"net/http"
	"github.com/gorilla/mux"
	"fmt"
)

func NewHandler() http.Handler {
	r := mux.NewRouter()
	r.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "hello world")
	})
	return r
}
