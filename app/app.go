package app

import (
	"github.com/nirasan/gae-jwt/handler"
	"net/http"
)

func init() {
	http.Handle("/", handler.NewHandler())
}
