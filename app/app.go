package app

import (
	"net/http"
	"github.com/nirasan/gae-jwt"
)

func init() {
	http.Handle("/", gae_jwt.NewHandler())
}
